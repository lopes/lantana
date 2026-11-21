"""IOC extraction helpers for the enrichment and transform pipelines.

Supports:
- Inbound source IPs (`extract_ips`)
- Malware SHA-256 hashes from bronze (`extract_hashes_from_bronze`) and date-scoped
  sensor disk scans (`extract_hashes_from_disk`, `extract_dionaea_binary_events`)
- Post-auth outbound stager URLs (`extract_outbound_urls`), stager domains
  (`extract_stager_domains`), outbound C2 IPs (`extract_outbound_c2_ips`), and
  persistent OpenSSH public-key fingerprints (`extract_ssh_public_keys`)
- OPSEC & non-routable IP filtering (`filter_internal_ips`)
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import ipaddress
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import polars as pl
import structlog

from lantana.common.redact import derive_ip_variants

if TYPE_CHECKING:
    from datetime import date
    from pathlib import Path

    from lantana.common.redact import RedactionConfig

logger = structlog.get_logger()

_FILE_EVENT_IDS: frozenset[str] = frozenset(
    {"cowrie.session.file_download", "cowrie.session.file_upload"}
)

_BINARY_MAX_BYTES: int = 100 * 1024 * 1024  # 100 MiB cap shared with disk-scan

# Non-routable IPv4/IPv6 ranges that should never be sent to a threat-intel
# provider or exported as outbound C2 indicators. Deliberately does NOT include
# RFC 5737 TEST-NET (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or
# RFC 3849 (2001:db8::/32) so synthetic test fixtures remain routable in tests.
_NON_ROUTABLE_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT (RFC6598)
    ipaddress.ip_network("169.254.0.0/16"),  # link-local IPv4
    ipaddress.ip_network("127.0.0.0/8"),  # loopback IPv4
    ipaddress.ip_network("0.0.0.0/8"),  # current network / unspecified
    ipaddress.ip_network("224.0.0.0/4"),  # multicast IPv4
    ipaddress.ip_network("240.0.0.0/4"),  # reserved IPv4
    ipaddress.ip_network("fc00::/7"),  # ULA IPv6
    ipaddress.ip_network("fe80::/10"),  # link-local IPv6
    ipaddress.ip_network("::1/128"),  # loopback IPv6
    ipaddress.ip_network("::/128"),  # unspecified IPv6
    ipaddress.ip_network("ff00::/8"),  # multicast IPv6
]

_URL_RE = re.compile(r"""(?i)\b(?:https?|ftp|tftp)://[^\s'"`<>|;)}\]]+""")
_DEV_TCP_UDP_RE = re.compile(r"/dev/(?:tcp|udp)/([0-9A-Fa-f:.]+)/\d+")
_OUTBOUND_TOOL_IP_RE = re.compile(
    r"""(?i)\b(?:tftp|nc|ncat|netcat|scp|rsync|curl|wget|busybox\s+wget|busybox\s+tftp)\b[^\n;|&]*?\b(\d{1,3}(?:\.\d{1,3}){3})\b"""
)
_SSH_PUBKEY_RE = re.compile(
    r"\b(ssh-(?:rsa|ed25519|ecdsa-sha2-nistp(?:256|384|521)))\s+([A-Za-z0-9+/=]{20,})"
)
_NON_GLOBAL_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".arpa",
)


def extract_ips(df: pl.DataFrame) -> set[str]:
    """Return unique non-null src_ip values from a bronze DataFrame."""
    if "src_ip" not in df.columns:
        return set()
    values = df.get_column("src_ip").drop_nulls().unique().cast(pl.Utf8).to_list()
    return {ip for ip in values if ip}


def extract_hashes_from_bronze(df: pl.DataFrame) -> set[str]:
    """Return unique non-null shasum values from file_download/file_upload events only.

    Filters to cowrie.session.file_download and cowrie.session.file_upload
    specifically. cowrie.log.closed events also carry a shasum (SHA256 of the
    TTY recording file) which is not a malware artifact.
    """
    if "shasum" not in df.columns or "eventid" not in df.columns:
        return set()
    filtered = df.filter(pl.col("eventid").is_in(list(_FILE_EVENT_IDS)))
    values = filtered.get_column("shasum").drop_nulls().unique().cast(pl.Utf8).to_list()
    return {h for h in values if h}


def extract_dionaea_binary_events(
    sensor_dir: Path,
    target_date: date,
    default_server: str = "unknown",
    default_operation: str = "unknown",
) -> list[dict[str, Any]]:
    """Build synthetic OCSF-bound events for dionaea-captured binaries.

    Each regular file under ``<sensor_dir>/dionaea/binaries`` whose UTC mtime
    matches ``target_date`` yields one ``dionaea.binary.captured`` event with
    naive UTC ``timestamp``, ``shasum``, ``binary_file_name``, ``dataset``,
    ``server``, and ``operation``. Symlinks are skipped defensively.
    """
    binaries_dir = sensor_dir / "dionaea" / "binaries"
    if not binaries_dir.exists():
        return []

    events: list[dict[str, Any]] = []
    for file_path in binaries_dir.iterdir():
        try:
            if file_path.is_symlink():
                continue
            stat = file_path.stat()
            if not file_path.is_file() or stat.st_size > _BINARY_MAX_BYTES:
                continue
            mtime_dt = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
            if mtime_dt.date() != target_date:
                continue
            sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
        except (PermissionError, FileNotFoundError, OSError) as exc:
            logger.warning(
                "dionaea_binary_skipped",
                path=str(file_path),
                reason=type(exc).__name__,
            )
            continue
        events.append(
            {
                "eventid": "dionaea.binary.captured",
                "timestamp": mtime_dt.replace(tzinfo=None),
                "shasum": sha,
                "binary_file_name": file_path.name,
                "dataset": "dionaea",
                "server": default_server,
                "operation": default_operation,
            }
        )
    return events


def extract_hashes_from_disk(
    sensor_dir: Path,
    target_date: date | None = None,
) -> set[str]:
    """Compute SHA256 for artifacts under <sensor>/<honeypot>/{downloads,binaries}.

    When ``target_date`` is provided, scopes hashing strictly to files whose
    UTC mtime falls on ``target_date`` so nightly runs do not re-hash weeks of
    historical files. Symlinks and files > 100 MiB are skipped.
    """
    download_dirs = list(sensor_dir.glob("*/downloads")) + list(sensor_dir.glob("*/binaries"))
    hashes: set[str] = set()
    for download_dir in download_dirs:
        if not download_dir.exists():
            continue
        for file_path in download_dir.iterdir():
            try:
                if file_path.is_symlink():
                    continue
                stat = file_path.stat()
                if not file_path.is_file() or stat.st_size > _BINARY_MAX_BYTES:
                    continue
                if target_date is not None:
                    mtime_date = datetime.fromtimestamp(stat.st_mtime, tz=UTC).date()
                    if mtime_date != target_date:
                        continue
                hashes.add(hashlib.sha256(file_path.read_bytes()).hexdigest())
            except (PermissionError, FileNotFoundError, OSError) as exc:
                logger.warning(
                    "disk_hash_skipped",
                    path=str(file_path),
                    reason=type(exc).__name__,
                )
    return hashes


def _parse_infra_sets(
    config: RedactionConfig,
) -> tuple[
    set[str],
    set[ipaddress.IPv4Address | ipaddress.IPv6Address],
    list[ipaddress.IPv4Network | ipaddress.IPv6Network],
]:
    infra_set = {ip.strip() for ip in config.infrastructure_ips if ip and ip.strip()}
    parsed_infra: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for ip_str in infra_set:
        try:
            parsed_infra.add(ipaddress.ip_address(ip_str))
        except ValueError:
            continue
    cidr_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in config.infrastructure_cidrs:
        try:
            cidr_nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            continue
    return infra_set, parsed_infra, cidr_nets


def _is_blocked_ip(
    ip_str: str,
    infra_set: set[str],
    parsed_infra: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
    cidr_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Return True if ``ip_str`` is infra-owned or non-routable."""
    if ip_str in infra_set:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if addr in parsed_infra:
        return True
    if any(addr in net for net in _NON_ROUTABLE_NETS):
        return True
    return any(addr in net for net in cidr_nets)


def filter_internal_ips(ips: set[str], config: RedactionConfig) -> set[str]:
    """Drop operation-owned and non-routable addresses before external enrichment."""
    infra_set, parsed_infra, cidr_nets = _parse_infra_sets(config)
    kept: set[str] = set()
    for ip in ips:
        if _is_blocked_ip(ip, infra_set, parsed_infra, cidr_nets):
            continue
        kept.add(ip)
    return kept


def _is_infra_host(host: str, config: RedactionConfig) -> bool:
    """Return True if a URL hostname matches any infra IP, variant, or configured hostname."""
    lowered = host.lower().strip().rstrip(".")
    if not lowered or lowered == "localhost":
        return True
    if any(lowered.endswith(suffix) for suffix in _NON_GLOBAL_DOMAIN_SUFFIXES):
        return True

    infra_hostnames = {
        h.lower().strip().rstrip(".") for h in config.infrastructure_hostnames if h and h.strip()
    }
    if lowered in infra_hostnames:
        return True

    infra_set, parsed_infra, cidr_nets = _parse_infra_sets(config)
    try:
        ipaddress.ip_address(lowered)
        return _is_blocked_ip(lowered, infra_set, parsed_infra, cidr_nets)
    except ValueError:
        pass

    # Guard against ISP PTR hostnames encoding the WAN IP (e.g. 97.ip-203-0-113.example.org)
    for ip_str in config.infrastructure_ips:
        for variant in derive_ip_variants(ip_str):
            if variant.lower() in lowered:
                return True
    return False


def _clean_url_token(raw: str) -> str:
    """Trim trailing shell/sentence punctuation from an extracted URL."""
    cleaned = raw.strip().rstrip(".,;:'\"`)>]}")
    return cleaned


def _iter_text_column(df: pl.DataFrame, candidates: tuple[str, ...]) -> list[str]:
    """Collect non-null, non-empty string values across candidate columns."""
    out: list[str] = []
    for col in candidates:
        if col in df.columns and df.schema[col] == pl.Utf8:
            out.extend(
                str(v)
                for v in df.get_column(col).drop_nulls().unique().to_list()
                if isinstance(v, str) and v.strip()
            )
    return out


def extract_outbound_urls(df: pl.DataFrame, config: RedactionConfig) -> set[str]:
    """Extract external post-auth stager URLs from file URLs and shell command lines.

    Works on both bronze (``url``, ``input``) and silver (``file_url``,
    ``actor_process_cmd_line``) DataFrames. Filters out any URL pointing at
    infrastructure IPs/hostnames or non-routable addresses.
    """
    if df.is_empty():
        return set()

    raw_candidates: set[str] = set()
    # Direct URL columns
    url_df = df
    if "file_intent" in df.columns:
        url_df = df.filter(pl.col("file_intent").fill_null("malware") != "probe")
    for direct_url in _iter_text_column(url_df, ("file_url", "url")):
        cleaned = _clean_url_token(direct_url)
        if cleaned:
            raw_candidates.add(cleaned)

    # URLs embedded in post-auth shell commands
    for cmd in _iter_text_column(df, ("actor_process_cmd_line", "input")):
        for match in _URL_RE.findall(cmd):
            cleaned = _clean_url_token(match)
            if cleaned:
                raw_candidates.add(cleaned)

    valid_urls: set[str] = set()
    for url in raw_candidates:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https", "ftp", "tftp"}:
            continue
        host = parsed.hostname
        if not host or _is_infra_host(host, config):
            continue
        valid_urls.add(url)
    return valid_urls


def extract_stager_domains(urls: set[str], config: RedactionConfig) -> set[str]:
    """Extract unique external domain names (non-IP hosts) from stager URLs."""
    domains: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip().rstrip(".")
        if not host or "." not in host:
            continue
        try:
            ipaddress.ip_address(host)
            continue  # IP-hosted URL -> handled by outbound C2 IP extractor
        except ValueError:
            pass
        if _is_infra_host(host, config):
            continue
        domains.add(host)
    return domains


def extract_outbound_c2_ips(df: pl.DataFrame, config: RedactionConfig) -> set[str]:
    """Extract external outbound C2 / payload-staging IP literals from post-auth activity.

    Sources:
    - IP hosts of extracted stager URLs
    - ``/dev/tcp/<ip>/<port>`` and ``/dev/udp/<ip>/<port>`` reverse shells
    - ``tftp`` / ``nc`` / ``ncat`` / ``netcat`` / ``scp`` / ``wget`` / ``curl`` IP arguments

    Every candidate is validated as a real IP literal and filtered against
    operation infrastructure and non-routable ranges.
    """
    if df.is_empty():
        return set()

    candidates: set[str] = set()

    for url in extract_outbound_urls(df, config):
        host = urlparse(url).hostname
        if host:
            with contextlib.suppress(ValueError):
                candidates.add(str(ipaddress.ip_address(host)))

    for cmd in _iter_text_column(df, ("actor_process_cmd_line", "input")):
        for raw_ip in _DEV_TCP_UDP_RE.findall(cmd):
            try:
                candidates.add(str(ipaddress.ip_address(raw_ip)))
            except ValueError:
                continue
        for raw_ip in _OUTBOUND_TOOL_IP_RE.findall(cmd):
            try:
                candidates.add(str(ipaddress.ip_address(raw_ip)))
            except ValueError:
                continue

    return filter_internal_ips(candidates, config)


def _format_ssh_pubkey_fingerprint(key_type: str, key_blob: str) -> str | None:
    """Compute canonical ``<key_type> SHA256:<b64>`` fingerprint for an OpenSSH key."""
    try:
        raw_bytes = base64.b64decode(key_blob.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw_bytes) < 16:
        return None
    digest_b64 = base64.b64encode(hashlib.sha256(raw_bytes).digest()).decode("ascii").rstrip("=")
    return f"{key_type} SHA256:{digest_b64}"


def extract_ssh_public_keys(
    df: pl.DataFrame,
    sensor_dir: Path | None = None,
) -> set[str]:
    """Extract canonical OpenSSH public-key fingerprints from commands and persistence files.

    Matches ``ssh-rsa``, ``ssh-ed25519``, and ``ssh-ecdsa-sha2-nistp*`` blobs
    written via shell commands (e.g. ``echo "ssh-ed25519 AAAA..." >> ~/.ssh/authorized_keys``)
    and optionally from Cowrie persistence downloads when ``sensor_dir`` is given.
    """
    if df.is_empty():
        return set()

    fingerprints: set[str] = set()
    for cmd in _iter_text_column(df, ("actor_process_cmd_line", "input")):
        for key_type, key_blob in _SSH_PUBKEY_RE.findall(cmd):
            fp = _format_ssh_pubkey_fingerprint(key_type, key_blob)
            if fp is not None:
                fingerprints.add(fp)

    if sensor_dir is not None and "file_hash_sha256" in df.columns:
        persistence_df = df
        if "file_intent" in df.columns:
            persistence_df = df.filter(pl.col("file_intent") == "persistence")
        elif "destfile" in df.columns:
            persistence_df = df.filter(
                pl.col("destfile").fill_null("").str.contains("authorized_keys")
            )
        else:
            persistence_df = df.clear()

        downloads_dir = sensor_dir / "cowrie" / "downloads"
        if not persistence_df.is_empty() and downloads_dir.exists():
            shas = (
                persistence_df.get_column("file_hash_sha256")
                .drop_nulls()
                .unique()
                .cast(pl.Utf8)
                .to_list()
            )
            for sha in shas:
                candidate = downloads_dir / str(sha)
                try:
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                    if candidate.stat().st_size > 1024 * 1024:
                        continue
                    text = candidate.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for key_type, key_blob in _SSH_PUBKEY_RE.findall(text):
                    fp = _format_ssh_pubkey_fingerprint(key_type, key_blob)
                    if fp is not None:
                        fingerprints.add(fp)

    return fingerprints

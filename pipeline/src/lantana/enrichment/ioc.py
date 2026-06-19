"""IOC extraction helpers for the enrichment pipeline.

Phase 3 of the IOC-first refactor lifts these out of runner.py so the
runner can extract IOCs globally (across all datasets) once per run
instead of duplicating work per dataset.

Supported IOC types right now: IP addresses and SHA256 file hashes.
URL/domain extraction is intentionally out of scope until Suricata
HTTP fields surface in bronze.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import polars as pl
import structlog

if TYPE_CHECKING:
    from datetime import date
    from pathlib import Path

    from lantana.common.redact import RedactionConfig

logger = structlog.get_logger()


def extract_ips(df: pl.DataFrame) -> set[str]:
    """Return unique non-null src_ip values from a bronze DataFrame."""
    if "src_ip" not in df.columns:
        return set()
    values = df.get_column("src_ip").drop_nulls().unique().cast(pl.Utf8).to_list()
    return {ip for ip in values if ip}


_FILE_EVENT_IDS: frozenset[str] = frozenset(
    {"cowrie.session.file_download", "cowrie.session.file_upload"}
)


def extract_hashes_from_bronze(df: pl.DataFrame) -> set[str]:
    """Return unique non-null shasum values from file_download/file_upload events only.

    Filters to cowrie.session.file_download and cowrie.session.file_upload
    specifically. cowrie.log.closed events also carry a shasum (SHA256 of the
    TTY recording file) which is not a malware artifact — including those would
    send ~200 junk hashes/day to VirusTotal, exhausting the free-tier rate limit
    before any real malware hash is reached.
    """
    if "shasum" not in df.columns or "eventid" not in df.columns:
        return set()
    filtered = df.filter(pl.col("eventid").is_in(list(_FILE_EVENT_IDS)))
    values = filtered.get_column("shasum").drop_nulls().unique().cast(pl.Utf8).to_list()
    return {h for h in values if h}


_BINARY_MAX_BYTES: int = 100 * 1024 * 1024  # 100 MiB cap shared with disk-scan


def extract_dionaea_binary_events(
    sensor_dir: Path,
    target_date: date,
) -> list[dict[str, Any]]:
    """Build synthetic OCSF-bound events for dionaea-captured binaries.

    Dionaea's ``store`` ihandler writes every accepted SMB/FTP/HTTP
    upload to ``var/lib/dionaea/binaries/`` as an MD5-named file, but
    never emits a hash event into the ``log_json`` stream. Without a
    scanner the entire dionaea catalog of captures (op_alpha had 192
    samples by 2026-06-19) is invisible to silver → gold → brief — the
    pipeline ingested dionaea connection events but never learned
    which files those connections actually delivered.

    Each binary whose mtime falls inside ``target_date`` (UTC day)
    produces one synthetic event with:
        eventid           = ``dionaea.binary.captured``
        timestamp         = mtime as ISO8601 ``…Z``
        shasum            = SHA-256 of the file contents
        binary_file_name  = on-disk filename (typically MD5)
        dataset           = ``dionaea``

    The runner concats these onto dionaea bronze; normalize_dionaea
    then dispatches them to ``class_uid=CLASS_FILE_ACTIVITY`` with the
    shasum mapped to ``file_hash_sha256`` and ``file_intent='malware'``.
    src_ip / dst_ip are left null (dionaea doesn't write per-binary
    attribution to disk); they fall through normalize as typed-null
    columns and the malware top-N in gold still gets the hash.

    File-size cap and unreadable-file handling mirror
    ``extract_hashes_from_disk`` so the two scanners can't disagree
    on which binaries are worth processing.
    """
    binaries_dir = sensor_dir / "dionaea" / "binaries"
    if not binaries_dir.exists():
        return []

    events: list[dict[str, Any]] = []
    for file_path in binaries_dir.iterdir():
        try:
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
                "timestamp": mtime_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "shasum": sha,
                "binary_file_name": file_path.name,
                "dataset": "dionaea",
            }
        )
    return events


def extract_hashes_from_disk(sensor_dir: Path) -> set[str]:
    """Compute SHA256 for every artifact under <sensor>/<honeypot>/{downloads,binaries}.

    Used as a defensive sweep for any file the bronze event pipeline
    may have missed. Files larger than 100 MiB are skipped to keep the
    daily run bounded.

    Skips unreadable files: cowrie writes downloaded payloads under the
    stigma user and the pipeline runs as nectar, so individual files
    may not be readable across the zone boundary. The bronze
    ``file_download`` event path remains the primary source for hashes;
    this disk scan is a best-effort backstop.
    """
    download_dirs = list(sensor_dir.glob("*/downloads")) + list(sensor_dir.glob("*/binaries"))
    hashes: set[str] = set()
    for download_dir in download_dirs:
        if not download_dir.exists():
            continue
        for file_path in download_dir.iterdir():
            try:
                if not file_path.is_file() or file_path.stat().st_size > 100 * 1024 * 1024:
                    continue
                hashes.add(hashlib.sha256(file_path.read_bytes()).hexdigest())
            except (PermissionError, FileNotFoundError) as exc:
                logger.warning(
                    "disk_hash_skipped",
                    path=str(file_path),
                    reason=type(exc).__name__,
                )
    return hashes


# Non-routable IPv4/IPv6 ranges that should never be sent to a threat-intel
# provider. Threat-intel providers have no useful data on these by construction.
# Deliberately does NOT include RFC 5737 TEST-NET (203.0.113.0/24 etc.) — those
# are reserved-but-not-private, valid stand-ins for attacker addresses in tests
# and docs.
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


def filter_internal_ips(ips: set[str], config: RedactionConfig) -> set[str]:
    """Drop addresses that should never reach an external enrichment provider.

    Two categories:
    1. **Operation-owned** — exact matches in `config.infrastructure_ips`
       or CIDR membership in `config.infrastructure_cidrs`. OPSEC defense
       in depth behind Vector's Layer-1 source filter.
    2. **Non-routable** — RFC1918, CGNAT, link-local (`fe80::/10`,
       `169.254.0.0/16`), loopback, multicast, unspecified, IPv6 ULA.
       Providers have no threat intel on these by construction; sending
       them burns rate-limit budget and, for some providers, triggers
       KeyError paths on sparse 200 responses (observed in op_alpha's
       first run, where `10.69.215.134` blew up VirusTotal parsing).
    """
    infra_set = set(config.infrastructure_ips)
    cidr_nets = [ipaddress.ip_network(cidr) for cidr in config.infrastructure_cidrs]
    kept: set[str] = set()
    for ip in ips:
        if ip in infra_set:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Not an IP literal — keep it (likely a hostname or junk; the
            # provider call itself will fail it cheaply if it isn't valid).
            kept.add(ip)
            continue
        if any(addr in net for net in _NON_ROUTABLE_NETS):
            continue
        if any(addr in net for net in cidr_nets):
            continue
        kept.add(ip)
    return kept

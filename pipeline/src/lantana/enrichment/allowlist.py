"""Benign/shared-infrastructure allowlist and outbound IOC verification policy.

Pure stdlib single source of truth shared across:
- ``enrichment/runner.py``: avoids burning scarce free-tier API quota on static
  benign/shared infrastructure (public DNS resolvers, utility hosts, shared-host
  apex domains) while still enriching path-specific URLs on shared hosts.
- ``transform/metrics.py``: tags every row in Gold ``extracted_iocs`` with
  ``verification_status`` (``verified`` | ``unverified`` | ``suppressed``) and
  ``verification_reason`` without silently dropping raw visibility.
- ``intel/stix.py`` & ``dashboard/queries.py``: enforces defense-in-depth gating
  at STIX 2.1 bundle generation and Vigil preview time (including safe fallback
  for legacy Gold partitions written before verification columns existed).
"""

from __future__ import annotations

import ipaddress
import unicodedata
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from lantana.common.config import StixExportConfig

VERIFICATION_STATUS_VERIFIED: str = "verified"
VERIFICATION_STATUS_UNVERIFIED: str = "unverified"
VERIFICATION_STATUS_SUPPRESSED: str = "suppressed"

# Multi-day rollup precedence: safety (suppressed) > corroboration (verified) > unverified.
VERIFICATION_STATUS_PRECEDENCE: dict[str, int] = {
    VERIFICATION_STATUS_SUPPRESSED: 3,
    VERIFICATION_STATUS_VERIFIED: 2,
    VERIFICATION_STATUS_UNVERIFIED: 1,
}

# Corroboration thresholds aligned with docs/risk-scoring.md & virustotal.py:
# - VT URL/file FP rates are low -> >= 1 engine crosses score 50.0.
# - VT IP/domain single-engine hits are noisy -> >= 3 engines crosses score 50.0.
# - AbuseIPDB >= 50 aligns with RISK_SCORE_MALICIOUS_THRESHOLD.
VT_URL_MIN_MALICIOUS: int = 1
VT_DOMAIN_MIN_MALICIOUS: int = 3
VT_IP_MIN_MALICIOUS: int = 3
ABUSEIPDB_C2_MIN_CONFIDENCE: int = 50
GTI_CORROBORATING_VERDICTS: frozenset[str] = frozenset({"VERDICT_MALICIOUS", "VERDICT_SUSPICIOUS"})

# Public DNS resolvers and well-known connectivity-check endpoints that attackers
# routinely reference in recon/checks or to poison blocklists.
# Deliberately excludes RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
# and RFC 3849 (2001:db8::/32) so synthetic test fixtures remain actionable.
BENIGN_RESOLVER_IPS: frozenset[str] = frozenset(
    {
        # Cloudflare DNS
        "1.1.1.1",
        "1.0.0.1",
        "1.1.1.2",
        "1.0.0.2",
        "1.1.1.3",
        "1.0.0.3",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2606:4700:4700::1112",
        "2606:4700:4700::1002",
        "2606:4700:4700::1113",
        "2606:4700:4700::1003",
        # Google Public DNS
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        # Quad9
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "2620:fe::9",
        # OpenDNS / Cisco Umbrella
        "208.67.222.222",
        "208.67.220.220",
        "208.67.222.123",
        "208.67.220.123",
        "2620:119:35::35",
        "2620:119:53::53",
        # AdGuard / ControlD / Level3 / DNS.SB / Alibaba / DNSPod / 114DNS
        "94.140.14.14",
        "94.140.15.15",
        "76.76.2.0",
        "76.76.10.0",
        "4.2.2.1",
        "4.2.2.2",
        "4.2.2.3",
        "4.2.2.4",
        "4.2.2.5",
        "4.2.2.6",
        "185.222.222.222",
        "45.11.45.11",
        "223.5.5.5",
        "223.6.6.6",
        "119.29.29.29",
        "114.114.114.114",
    }
)

_PARSED_BENIGN_RESOLVER_IPS: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset(
    ipaddress.ip_address(ip) for ip in BENIGN_RESOLVER_IPS
)

# Multi-tenant code hosting, paste sites, chat/file-share platforms, cloud object
# storage, serverless PaaS, container registries, and CDNs.
# Policy: NEVER export as `stager_domain` (sinkholing breaks legitimate users);
# allow path-specific `stager_url` ONLY when corroborated (VT/GTI/captured hash).
SHARED_HOSTING_DOMAINS: frozenset[str] = frozenset(
    {
        # Code / Git / artifact hosting
        "github.com",
        "githubusercontent.com",
        "github.io",
        "gitlab.com",
        "gitlab.io",
        "bitbucket.org",
        "codeberg.org",
        "sourceforge.net",
        "sr.ht",
        # Paste & ephemeral file-sharing services
        "pastebin.com",
        "pastee.dev",
        "paste.ee",
        "hastebin.com",
        "dpaste.org",
        "ix.io",
        "sprunge.us",
        "termbin.com",
        "transfer.sh",
        "file.io",
        "0x0.st",
        "tmpfiles.org",
        "catbox.moe",
        "gofile.io",
        "anonfiles.com",
        "mega.nz",
        "mediafire.com",
        "wetransfer.com",
        # Chat / collaboration CDNs
        "discord.com",
        "discordapp.com",
        "discordapp.net",
        "telegram.org",
        "t.me",
        "slack.com",
        "slack-edge.com",
        "notion.so",
        # Cloud storage, serverless, tunnels & PaaS
        "amazonaws.com",
        "cloudfront.net",
        "storage.googleapis.com",
        "googleapis.com",
        "firebasestorage.googleapis.com",
        "drive.google.com",
        "docs.google.com",
        "blob.core.windows.net",
        "azureedge.net",
        "azurewebsites.net",
        "digitaloceanspaces.com",
        "backblazeb2.com",
        "r2.dev",
        "workers.dev",
        "pages.dev",
        "netlify.app",
        "vercel.app",
        "herokuapp.com",
        "fly.dev",
        "onrender.com",
        "ngrok.io",
        "ngrok-free.app",
        "trycloudflare.com",
        "dropbox.com",
        "dropboxusercontent.com",
        "onedrive.live.com",
        "1drv.ms",
        "box.com",
        # Container registries & public asset CDNs
        "docker.io",
        "docker.com",
        "ghcr.io",
        "gcr.io",
        "quay.io",
        "cloudflare.com",
        "cloudflare-dns.com",
        "fastly.net",
        "akamai.net",
        "akamaiedge.net",
        "akamaized.net",
        "jsdelivr.net",
        "unpkg.com",
        "bootstrapcdn.com",
        "archive.org",
    }
)

# Recon / IP-echo services, OS package mirrors, language package indexes, search
# engines, and major vendor portals.
# Policy: suppress BOTH `stager_domain` AND `stager_url`.
# Deliberately excludes RFC 2606 (`example.com`, `example.org`, `example.net`) so
# OPSEC-compliant synthetic test fixtures remain usable in unit tests.
BENIGN_UTILITY_DOMAINS: frozenset[str] = frozenset(
    {
        # IP echo & connectivity checks
        "ifconfig.me",
        "ifconfig.co",
        "ifconfig.io",
        "ipinfo.io",
        "icanhazip.com",
        "ipify.org",
        "ident.me",
        "ipecho.net",
        "myip.com",
        "whatismyipaddress.com",
        "checkip.amazonaws.com",
        "checkip.dyndns.org",
        "wtfismyip.com",
        "ip-api.com",
        "ipapi.co",
        "curlmyip.net",
        "seeip.org",
        "eth0.me",
        "tnx.nl",
        "httpbin.org",
        "speedtest.net",
        # OS package repos & language registries
        "debian.org",
        "ubuntu.com",
        "canonical.com",
        "centos.org",
        "redhat.com",
        "fedoraproject.org",
        "alpinelinux.org",
        "archlinux.org",
        "kali.org",
        "gentoo.org",
        "opensuse.org",
        "freebsd.org",
        "gnu.org",
        "kernel.org",
        "pypi.org",
        "pythonhosted.org",
        "npmjs.org",
        "npmjs.com",
        "yarnpkg.com",
        "rubygems.org",
        "crates.io",
        "pkg.go.dev",
        "golang.org",
        "maven.org",
        "brew.sh",
        "snapcraft.io",
        "flathub.org",
        "cpan.org",
        "packagist.org",
        "nuget.org",
        # Search engines, portals, NTP, PKI & major tech vendors
        "google.com",
        "gstatic.com",
        "bing.com",
        "duckduckgo.com",
        "yahoo.com",
        "baidu.com",
        "yandex.ru",
        "wikipedia.org",
        "wikimedia.org",
        "microsoft.com",
        "windowsupdate.com",
        "apple.com",
        "icloud.com",
        "mozilla.org",
        "mozilla.com",
        "letsencrypt.org",
        "digicert.com",
        "verisign.com",
        "iana.org",
        "ietf.org",
        "w3.org",
        "ntp.org",
        "cloudflare-ech.com",
    }
)


_IDEOGRAPHIC_DOTS: tuple[str, ...] = ("\u3002", "\uff0e", "\uff61")
_IPV6_MAPPED_V4_NET: ipaddress.IPv6Network = ipaddress.IPv6Network("::ffff:0:0/96")


def _normalize_host(host: str) -> str:
    """Normalize a hostname with NFKC, UTS-46 dot folding, IDNA/punycode, and stripping."""
    folded = host
    for dot in _IDEOGRAPHIC_DOTS:
        if dot in folded:
            folded = folded.replace(dot, ".")
    cleaned = unicodedata.normalize("NFKC", folded).strip().lower()
    while cleaned.startswith("*."):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip(".").rstrip(".")
    if not cleaned:
        return ""
    try:
        return cleaned.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return cleaned


def _unwrap_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _parse_inet_aton_ipv4(raw: str) -> ipaddress.IPv4Address | None:
    """Parse POSIX ``inet_aton`` non-canonical IPv4 literals (octal, hex, decimal, shorthand)."""
    if not raw or ":" in raw:
        return None
    parts = raw.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    nums: list[int] = []
    for part in parts:
        if not part:
            return None
        low = part.lower()
        try:
            if low.startswith("0x"):
                if len(low) <= 2:
                    return None
                val = int(low, 16)
            elif low.startswith("0") and len(low) > 1:
                val = int(low, 8)
            else:
                if not low.isdigit():
                    return None
                val = int(low, 10)
        except ValueError:
            return None
        if val < 0:
            return None
        nums.append(val)

    if len(nums) == 1:
        if nums[0] > 0xFFFFFFFF:
            return None
        return ipaddress.IPv4Address(nums[0])
    if len(nums) == 2:
        if nums[0] > 0xFF or nums[1] > 0xFFFFFF:
            return None
        return ipaddress.IPv4Address((nums[0] << 24) | nums[1])
    if len(nums) == 3:
        if nums[0] > 0xFF or nums[1] > 0xFF or nums[2] > 0xFFFF:
            return None
        return ipaddress.IPv4Address((nums[0] << 24) | (nums[1] << 16) | nums[2])
    if any(n > 0xFF for n in nums):
        return None
    return ipaddress.IPv4Address((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3])


def parse_normalized_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP literal tolerating brackets, trailing dots, zone IDs, and non-canonical IPv4."""
    cleaned = raw.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()
    cleaned = cleaned.rstrip(".")
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    if not cleaned:
        return None
    try:
        return _unwrap_ip(ipaddress.ip_address(cleaned))
    except ValueError:
        return _parse_inet_aton_ipv4(cleaned)


def _parse_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    return parse_normalized_ip(raw)


def _matches_domain_suffix(host: str, suffix: str) -> bool:
    """Return True if ``host`` equals ``suffix`` or is a label-bounded subdomain."""
    clean_suffix = _normalize_host(suffix)
    if not clean_suffix:
        return False
    return host == clean_suffix or host.endswith("." + clean_suffix)


def _longest_suffix_match(host: str, domains: frozenset[str]) -> int:
    """Return length of the longest label-bounded suffix match, or 0 if none."""
    best = 0
    for candidate in domains:
        if _matches_domain_suffix(host, candidate) and len(candidate) > best:
            best = len(candidate)
    return best


def _classify_domain_tier(host: str) -> str | None:
    """Return ``'utility'``, ``'shared'``, or ``None`` using longest-suffix precedence.

    Longest-suffix disambiguates nested namespaces cleanly:
    - ``checkip.amazonaws.com`` (len 21, utility) beats ``amazonaws.com`` (len 13, shared)
    - ``drive.google.com`` (len 16, shared) beats ``google.com`` (len 10, utility)
    """
    normalized = _normalize_host(host)
    if not normalized:
        return None
    util_len = _longest_suffix_match(normalized, BENIGN_UTILITY_DOMAINS)
    shared_len = _longest_suffix_match(normalized, SHARED_HOSTING_DOMAINS)
    if util_len == 0 and shared_len == 0:
        return None
    if util_len >= shared_len:
        return "utility"
    return "shared"


def _matches_operator_domains(host: str, allowlist_domains: Sequence[str]) -> bool:
    normalized = _normalize_host(host)
    if not normalized:
        return False
    return any(_matches_domain_suffix(normalized, d) for d in allowlist_domains if d and d.strip())


def _normalize_network(
    raw: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse an IPv4/IPv6 CIDR, unwrapping ``::ffff:0:0/96`` mapped ranges to IPv4Network."""
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        return None
    if (
        isinstance(net, ipaddress.IPv6Network)
        and net.prefixlen >= 96
        and net.subnet_of(_IPV6_MAPPED_V4_NET)
        and net.network_address.ipv4_mapped is not None
    ):
        return ipaddress.IPv4Network(
            (net.network_address.ipv4_mapped, net.prefixlen - 96), strict=False
        )
    return net


def _matches_operator_ips(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allowlist_ips: Sequence[str],
) -> bool:
    for raw in allowlist_ips:
        cleaned = raw.strip()
        if not cleaned:
            continue
        if "/" in cleaned:
            net = _normalize_network(cleaned)
            if net is not None and addr.version == net.version and addr in net:
                return True
        else:
            parsed = parse_normalized_ip(cleaned)
            if parsed is not None and addr == parsed:
                return True
    return False


def is_shared_hosting_url(url: str) -> bool:
    """Return True if ``url`` points at a multi-tenant shared-hosting domain."""
    cleaned = url.strip()
    if not cleaned:
        return False
    try:
        parsed = urlparse(cleaned)
        host = parsed.hostname
    except ValueError:
        return False
    if not host or "\\" in parsed.netloc or parse_normalized_ip(host) is not None:
        return False
    return _classify_domain_tier(host) == "shared"


def classify_static_suppression(
    ioc_type: str,
    ioc_value: str,
    *,
    allowlist_domains: Sequence[str] = (),
    allowlist_ips: Sequence[str] = (),
) -> str | None:
    """Return a suppression reason if ``(ioc_type, ioc_value)`` is statically suppressed.

    Returns ``None`` when the IOC is NOT statically suppressed (eligible for
    enrichment and corroboration checks). Malformed URLs fail closed as
    ``"malformed_url"``.
    """
    cleaned = ioc_value.strip()
    if not cleaned:
        return None

    if ioc_type in ("c2_ip", "ip"):
        addr = parse_normalized_ip(cleaned)
        if addr is None:
            return None
        if _matches_operator_ips(addr, allowlist_ips):
            return "operator_allowlist"
        if addr in _PARSED_BENIGN_RESOLVER_IPS:
            return "benign_resolver_ip"
        return None

    if ioc_type in ("stager_domain", "domain"):
        addr = parse_normalized_ip(cleaned)
        if addr is not None:
            if _matches_operator_ips(addr, allowlist_ips):
                return "operator_allowlist"
            if addr in _PARSED_BENIGN_RESOLVER_IPS:
                return "benign_resolver_ip"
            return None
        host = _normalize_host(cleaned)
        if _matches_operator_domains(host, allowlist_domains):
            return "operator_allowlist"
        tier = _classify_domain_tier(host)
        if tier == "utility":
            return "benign_utility_domain"
        if tier == "shared":
            return "shared_hosting_domain"
        return None

    if ioc_type in ("stager_url", "url"):
        try:
            parsed = urlparse(cleaned)
            raw_host = parsed.hostname
        except ValueError:
            return "malformed_url"
        if not raw_host or "\\" in parsed.netloc:
            return "malformed_url"

        addr = parse_normalized_ip(raw_host)
        if addr is not None:
            if _matches_operator_ips(addr, allowlist_ips):
                return "operator_allowlist"
            if addr in _PARSED_BENIGN_RESOLVER_IPS:
                return "benign_resolver_ip"
            return None

        host = _normalize_host(raw_host)
        if not host:
            return "malformed_url"
        if _matches_operator_domains(host, allowlist_domains):
            return "operator_allowlist"
        tier = _classify_domain_tier(host)
        if tier == "utility":
            return "benign_utility_domain"
        if tier == "shared":
            # Root/empty URLs on shared platforms (e.g. https://github.com/) are
            # never specific payload stagers — suppress statically.
            if not parsed.path.strip("/") and not parsed.query:
                return "shared_hosting_root_url"
            return None
        return None

    return None


def _opt_int(val: object) -> int | None:
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val)
    return None


def _opt_str(val: object) -> str | None:
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def evaluate_ioc_verification(
    ioc_type: str,
    ioc_value: str,
    *,
    vt_malicious: int | None = None,
    gti_verdict: str | None = None,
    captured_artifact: bool = False,
    greynoise_riot: bool = False,
    greynoise_class: str | None = None,
    abuseipdb_confidence: int | None = None,
    allowlist_domains: Sequence[str] = (),
    allowlist_ips: Sequence[str] = (),
) -> tuple[str, str]:
    """Classify an extracted IOC into ``(verification_status, verification_reason)``.

    Precedence:
    1. First-party observed artifacts (``malware_hash``, ``ssh_key``) -> ``verified``
    2. Static benign/shared/operator suppression -> ``suppressed``
    3. Dynamic GreyNoise RIOT / ``benign`` override -> ``suppressed``
    4. Type-specific corroboration (VT/GTI/GreyNoise/AbuseIPDB/captured hash) -> ``verified``
    5. Uncorroborated shared-hosting URL -> ``suppressed`` (never leaks via unverified opt-in)
    6. Everything else -> ``unverified`` (``uncorroborated``)
    """
    if ioc_type in ("malware_hash", "ssh_key"):
        return (VERIFICATION_STATUS_VERIFIED, "captured_artifact")

    static_reason = classify_static_suppression(
        ioc_type,
        ioc_value,
        allowlist_domains=allowlist_domains,
        allowlist_ips=allowlist_ips,
    )
    if static_reason is not None:
        return (VERIFICATION_STATUS_SUPPRESSED, static_reason)

    gn_cls = (greynoise_class or "").strip().lower()
    if ioc_type in ("c2_ip", "stager_url"):
        if greynoise_riot:
            return (VERIFICATION_STATUS_SUPPRESSED, "greynoise_riot")
        if gn_cls == "benign":
            return (VERIFICATION_STATUS_SUPPRESSED, "greynoise_benign")

    gti_upper = (gti_verdict or "").strip().upper()
    has_gti = gti_upper in GTI_CORROBORATING_VERDICTS

    if ioc_type == "stager_url":
        if captured_artifact:
            return (VERIFICATION_STATUS_VERIFIED, "captured_artifact")
        if vt_malicious is not None and vt_malicious >= VT_URL_MIN_MALICIOUS:
            return (VERIFICATION_STATUS_VERIFIED, "vt_malicious")
        if has_gti:
            return (VERIFICATION_STATUS_VERIFIED, "gti_verdict")
        if is_shared_hosting_url(ioc_value):
            return (VERIFICATION_STATUS_SUPPRESSED, "shared_hosting_unverified_url")
        return (VERIFICATION_STATUS_UNVERIFIED, "uncorroborated")

    if ioc_type == "stager_domain":
        if vt_malicious is not None and vt_malicious >= VT_DOMAIN_MIN_MALICIOUS:
            return (VERIFICATION_STATUS_VERIFIED, "vt_malicious")
        if has_gti:
            return (VERIFICATION_STATUS_VERIFIED, "gti_verdict")
        return (VERIFICATION_STATUS_UNVERIFIED, "uncorroborated")

    if ioc_type == "c2_ip":
        if captured_artifact:
            return (VERIFICATION_STATUS_VERIFIED, "captured_artifact")
        if vt_malicious is not None and vt_malicious >= VT_IP_MIN_MALICIOUS:
            return (VERIFICATION_STATUS_VERIFIED, "vt_malicious")
        if has_gti:
            return (VERIFICATION_STATUS_VERIFIED, "gti_verdict")
        if gn_cls == "malicious":
            return (VERIFICATION_STATUS_VERIFIED, "greynoise_malicious")
        if abuseipdb_confidence is not None and abuseipdb_confidence >= ABUSEIPDB_C2_MIN_CONFIDENCE:
            return (VERIFICATION_STATUS_VERIFIED, "abuseipdb_malicious")
        return (VERIFICATION_STATUS_UNVERIFIED, "uncorroborated")

    return (VERIFICATION_STATUS_UNVERIFIED, "uncorroborated")


def should_export_ioc_to_stix(
    row: Mapping[str, object],
    stix_config: StixExportConfig | None = None,
) -> tuple[bool, str, str]:
    """Determine whether an ``extracted_iocs`` row may be emitted as a STIX 2.1 Indicator.

    Returns ``(eligible, effective_status, effective_reason)``.

    Enforces defense-in-depth at STIX generation time:
    - Always re-checks static benign/shared-infra & operator allowlists even on
      pre-verified or legacy Gold Parquet rows.
    - Recomputes verification from enrichment fields when reading legacy Gold
      partitions that predate ``verification_status`` / ``verification_reason``.
    - Promotes ``unverified`` non-shared outbound IOCs only when
      ``stix_config.include_unverified_outbound`` is explicitly ``True``.
    """
    ioc_type = _opt_str(row.get("ioc_type")) or ""
    ioc_value = _opt_str(row.get("ioc_value")) or ""
    if not ioc_type or not ioc_value:
        return (False, VERIFICATION_STATUS_SUPPRESSED, "empty_ioc")

    allow_domains = stix_config.allowlist_domains if stix_config is not None else ()
    allow_ips = stix_config.allowlist_ips if stix_config is not None else ()
    include_unverified = (
        bool(stix_config.include_unverified_outbound) if stix_config is not None else False
    )

    if ioc_type in ("malware_hash", "ssh_key"):
        reason = _opt_str(row.get("verification_reason")) or "captured_artifact"
        return (True, VERIFICATION_STATUS_VERIFIED, reason)

    static_reason = classify_static_suppression(
        ioc_type,
        ioc_value,
        allowlist_domains=allow_domains,
        allowlist_ips=allow_ips,
    )
    if static_reason is not None:
        return (False, VERIFICATION_STATUS_SUPPRESSED, static_reason)

    stored_status = _opt_str(row.get("verification_status"))
    stored_reason = _opt_str(row.get("verification_reason"))

    if stored_status in (
        VERIFICATION_STATUS_VERIFIED,
        VERIFICATION_STATUS_UNVERIFIED,
        VERIFICATION_STATUS_SUPPRESSED,
    ):
        status = stored_status
        reason = stored_reason or (
            "uncorroborated" if status == VERIFICATION_STATUS_UNVERIFIED else status
        )
    else:
        status, reason = evaluate_ioc_verification(
            ioc_type,
            ioc_value,
            vt_malicious=_opt_int(row.get("vt_malicious")),
            gti_verdict=_opt_str(row.get("gti_verdict")),
            allowlist_domains=allow_domains,
            allowlist_ips=allow_ips,
        )

    if status == VERIFICATION_STATUS_SUPPRESSED:
        return (False, status, reason)
    if status == VERIFICATION_STATUS_VERIFIED:
        return (True, status, reason)

    # Unverified outbound IOC: never promote shared-host URLs even when opt-in is enabled.
    if ioc_type == "stager_url" and is_shared_hosting_url(ioc_value):
        return (False, VERIFICATION_STATUS_SUPPRESSED, "shared_hosting_unverified_url")

    return (include_unverified, VERIFICATION_STATUS_UNVERIFIED, reason)

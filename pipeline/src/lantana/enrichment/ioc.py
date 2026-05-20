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
from typing import TYPE_CHECKING

import polars as pl

if TYPE_CHECKING:
    from pathlib import Path

    from lantana.common.redact import RedactionConfig


def extract_ips(df: pl.DataFrame) -> set[str]:
    """Return unique non-null src_ip values from a bronze DataFrame."""
    if "src_ip" not in df.columns:
        return set()
    values = df.get_column("src_ip").drop_nulls().unique().cast(pl.Utf8).to_list()
    return {ip for ip in values if ip}


def extract_hashes_from_bronze(df: pl.DataFrame) -> set[str]:
    """Return unique non-null shasum values from a bronze DataFrame.

    Cowrie's `cowrie.session.file_download` events carry the SHA256 of
    the downloaded artifact in the `shasum` field; the field is absent
    on other event types and on datasets that don't track downloads
    (suricata, nftables, dionaea), in which case the function returns
    an empty set.
    """
    if "shasum" not in df.columns:
        return set()
    values = df.get_column("shasum").drop_nulls().unique().cast(pl.Utf8).to_list()
    return {h for h in values if h}


def extract_hashes_from_disk(sensor_dir: Path) -> set[str]:
    """Compute SHA256 for every artifact under <sensor>/<honeypot>/{downloads,binaries}.

    Used as a defensive sweep for any file the bronze event pipeline
    may have missed. Files larger than 100 MiB are skipped to keep the
    daily run bounded.
    """
    download_dirs = list(sensor_dir.glob("*/downloads")) + list(sensor_dir.glob("*/binaries"))
    hashes: set[str] = set()
    for download_dir in download_dirs:
        if not download_dir.exists():
            continue
        for file_path in download_dir.iterdir():
            if file_path.is_file() and file_path.stat().st_size <= 100 * 1024 * 1024:
                hashes.add(hashlib.sha256(file_path.read_bytes()).hexdigest())
    return hashes


# Non-routable IPv4/IPv6 ranges that should never be sent to a threat-intel
# provider. Threat-intel providers have no useful data on these by construction.
# Deliberately does NOT include RFC 5737 TEST-NET (203.0.113.0/24 etc.) — those
# are reserved-but-not-private, valid stand-ins for attacker addresses in tests
# and docs.
_NON_ROUTABLE_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),      # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),     # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT (RFC6598)
    ipaddress.ip_network("169.254.0.0/16"),     # link-local IPv4
    ipaddress.ip_network("127.0.0.0/8"),        # loopback IPv4
    ipaddress.ip_network("0.0.0.0/8"),          # current network / unspecified
    ipaddress.ip_network("224.0.0.0/4"),        # multicast IPv4
    ipaddress.ip_network("240.0.0.0/4"),        # reserved IPv4
    ipaddress.ip_network("fc00::/7"),           # ULA IPv6
    ipaddress.ip_network("fe80::/10"),          # link-local IPv6
    ipaddress.ip_network("::1/128"),            # loopback IPv6
    ipaddress.ip_network("::/128"),             # unspecified IPv6
    ipaddress.ip_network("ff00::/8"),           # multicast IPv6
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

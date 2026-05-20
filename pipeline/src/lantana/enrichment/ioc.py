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


def filter_internal_ips(ips: set[str], config: RedactionConfig) -> set[str]:
    """Drop operation-owned addresses before any provider call.

    OPSEC defense in depth behind Vector's Layer-1 source filter.
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
            kept.add(ip)
            continue
        if any(addr in net for net in cidr_nets):
            continue
        kept.add(ip)
    return kept

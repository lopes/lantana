"""OPSEC redaction: strip infrastructure IPs from shared outputs.

Layer 2 safeguard. Vector (Layer 1) drops internal-source noise.
This module handles destination IP pseudonymization in silver,
ensuring external/WAN IPs never appear in shareable data.
"""

from __future__ import annotations

import ipaddress
from functools import reduce

import polars as pl
from pydantic import BaseModel


class RedactionConfig(BaseModel):
    """Configuration for infrastructure IP redaction."""

    infrastructure_ips: list[str]
    infrastructure_cidrs: list[str]
    pseudonym_map: dict[str, str]


# Columns that may contain destination/infrastructure IPs
DST_IP_COLUMNS: list[str] = [
    "dst_ip",
    "dest_ip",
    "local_ip",
    "dst_host",
    "destination.ip",
    "dst_endpoint_ip",
]

# Columns that should contain ATTACKER source IPs, never the operation's own
# infrastructure. Suricata captures both directions of every flow, so outbound
# response packets from the honeypot itself end up with `src_ip = <our WAN>`.
# Vector's Layer-1 source filter is supposed to drop those at ingest, but the
# default per-honeypot filter only excludes the internal `network.prefixes.*`
# CIDRs — not the WAN address. Until the Suricata Vector filter is extended to
# also drop WAN-source events, drop_infrastructure_source_rows is the Layer-2
# safety net.
SRC_IP_COLUMNS: list[str] = [
    "src_ip",
    "src_endpoint_ip",
    "source.ip",
]


def drop_infrastructure_source_rows(
    df: pl.DataFrame,
    config: RedactionConfig,
) -> pl.DataFrame:
    """Drop rows whose source IP is one of the operation's own addresses.

    These events are noise — outbound packets the honeypot generated in
    response to attackers — and silver should only contain attacker
    behaviour. Without this filter, `validate_no_leaks` catches the
    infrastructure IP in `src_endpoint_ip` and aborts the whole run.

    Exact-match only against `config.infrastructure_ips`. CIDR membership
    is intentionally not checked here: the internal `infrastructure_cidrs`
    are already dropped at Vector's Layer-1 filter, so any survivor in a
    source column is one of the discrete WAN addresses.
    """
    if df.is_empty():
        return df

    infra_set = set(config.infrastructure_ips)
    if not infra_set:
        return df

    src_columns_present = [col for col in SRC_IP_COLUMNS if col in df.columns]
    if not src_columns_present:
        return df

    keep_mask: pl.Expr = pl.lit(value=True)
    for col in src_columns_present:
        keep_mask = keep_mask & ~pl.col(col).is_in(list(infra_set))

    return df.filter(keep_mask)


def redact_infrastructure_ips(
    df: pl.DataFrame,
    config: RedactionConfig,
) -> pl.DataFrame:
    """Replace infrastructure IPs in destination columns with pseudonyms.

    For each destination IP column present in the DataFrame, replaces
    any value matching an infrastructure IP with its pseudonym from the map.
    """
    if df.is_empty():
        return df

    columns_to_redact = [col for col in DST_IP_COLUMNS if col in df.columns]

    if not columns_to_redact:
        return df

    def _apply_redaction(frame: pl.DataFrame, col_name: str) -> pl.DataFrame:
        expr = pl.col(col_name)
        for real_ip, pseudonym in config.pseudonym_map.items():
            expr = pl.when(pl.col(col_name) == real_ip).then(pl.lit(pseudonym)).otherwise(expr)
        return frame.with_columns(expr.alias(col_name))

    return reduce(_apply_redaction, columns_to_redact, df)


def validate_no_leaks(df: pl.DataFrame, config: RedactionConfig) -> bool:
    """Assert that zero infrastructure IPs remain in any string column.

    Checks all string columns for any value matching infrastructure IPs
    or falling within infrastructure CIDRs. Returns True if clean.
    Raises ValueError with details if leaks are found.
    """
    if df.is_empty():
        return True

    ip_set = set(config.infrastructure_ips)
    cidr_nets = [ipaddress.ip_network(cidr) for cidr in config.infrastructure_cidrs]

    string_cols = [col for col, dtype in zip(df.columns, df.dtypes) if dtype == pl.Utf8]

    for col_name in string_cols:
        unique_vals = df.get_column(col_name).drop_nulls().unique().to_list()
        for val in unique_vals:
            if not isinstance(val, str):
                continue
            # Direct match
            if val in ip_set:
                msg = f"Infrastructure IP leak: {val} found in column '{col_name}'"
                raise ValueError(msg)
            # CIDR match
            try:
                addr = ipaddress.ip_address(val)
            except ValueError:
                continue  # Not an IP address string, skip
            for net in cidr_nets:
                if addr in net:
                    msg = f"Infrastructure IP leak: {val} (in {net}) found in column '{col_name}'"
                    raise ValueError(msg)

    return True

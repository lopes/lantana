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
]


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
                for net in cidr_nets:
                    if addr in net:
                        msg = f"Infrastructure IP leak: {val} (in {net}) found in column '{col_name}'"
                        raise ValueError(msg)
            except ValueError:
                continue  # Not an IP address string, skip

    return True

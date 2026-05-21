"""OPSEC redaction: strip infrastructure IPs from shared outputs.

Layer 2 safeguard. Vector (Layer 1) drops internal-source noise.
This module handles two distinct concerns at silver-write time:

* **IP-typed columns** (``src_endpoint_ip`` / ``dst_endpoint_ip`` / …) hold
  exactly one IP per row. They are pseudonymized via exact-match swap and
  CIDR-validated to guarantee no infrastructure address survives.
* **Attacker-content columns** (``unmapped_password`` /
  ``actor_process_cmd_line`` / ``message`` / …) hold arbitrary strings the
  attacker controls. The honeypot WAN IP can land in any of them — an
  attacker who tries ``ssh root@<wan>`` with the WAN IP as the password
  attempt puts it in ``unmapped_password``; an nftables log line preserved
  in ``message`` carries it as ``DST=<wan>``. We substring-replace known
  infra IPs with their pseudonyms here so published intel (gold's
  ``top_passwords``, the daily brief, STIX bundles) cannot leak the WAN
  address. These columns are NOT CIDR-validated — attacker passwords
  legitimately contain arbitrary RFC1918 / loopback / IP-shaped strings.
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

# Attacker-controlled string fields. These can hold arbitrary content,
# including IP-shaped strings that have nothing to do with our infrastructure
# (e.g. attacker uses 10.x.x.x as a password). We substring-replace known
# infrastructure IPs in these columns so they cannot leak into published intel,
# but we do NOT CIDR-validate them — false positives there are how cowrie
# silver for 2026-05-20 got dropped (an attacker tried the WAN IP itself
# as a password, validate_no_leaks aborted the whole batch).
ATTACKER_CONTENT_COLUMNS: list[str] = [
    "user_name",
    "unmapped_password",
    "actor_process_cmd_line",
    "file_url",
    "file_path",
    "file_hash_sha256",
    "finding_title",
    "finding_category",
    "finding_action",
    "message",
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


def _exact_match_redact_expr(col_name: str, pseudonym_map: dict[str, str]) -> pl.Expr:
    """Build a polars expression that pseudonymizes exact-IP matches in a column."""
    expr = pl.col(col_name)
    for real_ip, pseudonym in pseudonym_map.items():
        expr = pl.when(pl.col(col_name) == real_ip).then(pl.lit(pseudonym)).otherwise(expr)
    return expr.alias(col_name)


def _substring_redact_expr(col_name: str, pseudonym_map: dict[str, str]) -> pl.Expr:
    """Build a polars expression that substring-replaces infra IPs in a column.

    Used for attacker-controlled content where the IP can appear embedded
    inside a larger string (e.g. ``message`` carrying a kernel-log line that
    still has ``DST=<wan>``, or a download URL with the WAN IP in the host).
    ``str.replace_all`` operates on a literal string, no regex needed.
    """
    expr = pl.col(col_name)
    for real_ip, pseudonym in pseudonym_map.items():
        expr = expr.str.replace_all(real_ip, pseudonym, literal=True)
    return expr.alias(col_name)


def redact_infrastructure_ips(
    df: pl.DataFrame,
    config: RedactionConfig,
) -> pl.DataFrame:
    """Pseudonymize known infrastructure IPs across IP-typed and content columns.

    Two passes:

    1. **IP-typed columns** (``DST_IP_COLUMNS``) — exact-match swap. Each
       row's destination address is either an infra IP (pseudonymize) or it
       isn't (leave alone).
    2. **Attacker-content columns** (``ATTACKER_CONTENT_COLUMNS``) —
       substring replacement, because the WAN address can be embedded in
       arbitrary attacker-supplied text (kernel-log messages preserved in
       ``message``, malicious download URLs, commands, or the WAN IP itself
       used as a password attempt).

    Source-IP columns are intentionally NOT redacted here:
    ``drop_infrastructure_source_rows`` removes the rows entirely upstream.
    """
    if df.is_empty():
        return df

    dst_columns = [col for col in DST_IP_COLUMNS if col in df.columns]
    content_columns = [
        col
        for col in ATTACKER_CONTENT_COLUMNS
        if col in df.columns and df.schema[col] == pl.Utf8
    ]

    if not dst_columns and not content_columns:
        return df

    def _apply_dst(frame: pl.DataFrame, col_name: str) -> pl.DataFrame:
        return frame.with_columns(_exact_match_redact_expr(col_name, config.pseudonym_map))

    def _apply_content(frame: pl.DataFrame, col_name: str) -> pl.DataFrame:
        return frame.with_columns(_substring_redact_expr(col_name, config.pseudonym_map))

    df = reduce(_apply_dst, dst_columns, df)
    return reduce(_apply_content, content_columns, df)


def validate_no_leaks(df: pl.DataFrame, config: RedactionConfig) -> bool:
    """Assert that zero infrastructure IPs remain in IP-typed columns.

    Scoped deliberately to the columns we redact as IP-bearing
    (``DST_IP_COLUMNS`` + ``SRC_IP_COLUMNS``). Attacker-content columns
    (``unmapped_password``, ``actor_process_cmd_line``, ``message``, …) are
    NOT validated here — they may legitimately hold IP-shaped strings the
    attacker supplied (passwords like ``192.168.1.1``, embedded URLs, etc.).
    Known infrastructure IPs in those columns are pseudonymized by
    ``redact_infrastructure_ips`` above, so the OPSEC promise — no operation
    address in shareable output — still holds without false-positiving on
    attacker noise.

    Raises ``ValueError`` if a leak is found.
    """
    if df.is_empty():
        return True

    ip_set = set(config.infrastructure_ips)
    cidr_nets = [ipaddress.ip_network(cidr) for cidr in config.infrastructure_cidrs]

    ip_cols = [
        col
        for col in DST_IP_COLUMNS + SRC_IP_COLUMNS
        if col in df.columns and df.schema[col] == pl.Utf8
    ]

    for col_name in ip_cols:
        unique_vals = df.get_column(col_name).drop_nulls().unique().to_list()
        for val in unique_vals:
            if not isinstance(val, str):
                continue
            if val in ip_set:
                msg = f"Infrastructure IP leak: {val} found in column '{col_name}'"
                raise ValueError(msg)
            try:
                addr = ipaddress.ip_address(val)
            except ValueError:
                continue  # Not an IP literal — pseudonym or junk, skip.
            for net in cidr_nets:
                if addr in net:
                    msg = (
                        f"Infrastructure IP leak: {val} (in {net}) "
                        f"found in column '{col_name}'"
                    )
                    raise ValueError(msg)

    return True

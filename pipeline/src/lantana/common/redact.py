"""OPSEC redaction: strip infrastructure IPs and hostnames from shared outputs.

Layer 2 safeguard. Vector (Layer 1) drops internal-source noise.
This module handles two distinct concerns at silver-write time:

* **IP-typed columns** (``src_endpoint_ip`` / ``dst_endpoint_ip`` / …) hold
  exactly one IP per row. They are pseudonymized via exact-match swap and
  CIDR-validated (including compressed/expanded IPv6 equivalence) to guarantee
  no infrastructure address survives.
* **Attacker-content columns** (``unmapped_password`` /
  ``actor_process_cmd_line`` / ``message`` / Suricata ``payload*`` / …) hold
  arbitrary strings the attacker controls. The honeypot WAN IP, non-dotted
  ISP PTR encodings (``203_0_113_97``, ``203-0-113-97``, ``97.ip-203-0-113``),
  expanded IPv6, or configured VPS hostnames/FQDNs can land in any of them.
  We replace all derived variants longest-first so published intel cannot leak
  operator identity, without CIDR-validating attacker noise.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from functools import reduce

import polars as pl
from pydantic import BaseModel, Field


class RedactionConfig(BaseModel):
    """Unified OPSEC configuration for infrastructure IP & hostname redaction."""

    infrastructure_ips: list[str] = Field(default_factory=list)
    infrastructure_cidrs: list[str] = Field(default_factory=list)
    pseudonym_map: dict[str, str] = Field(default_factory=dict)
    infrastructure_hostnames: list[str] = Field(default_factory=list)


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
SRC_IP_COLUMNS: list[str] = [
    "src_ip",
    "src_endpoint_ip",
    "source.ip",
]

# Attacker-controlled string fields (including Suricata alert payloads/bodies).
# Substring-scrubbed against all derived WAN/infra IP encodings and configured
# infrastructure hostnames, but NOT CIDR-validated.
ATTACKER_CONTENT_COLUMNS: list[str] = [
    "user_name",
    "unmapped_password",
    "actor_process_cmd_line",
    "file_url",
    "file_path",
    "file_name",
    "destfile",
    "file_hash_sha256",
    "finding_title",
    "finding_category",
    "finding_action",
    "message",
    "payload",
    "payload-printable",
    "payload_printable",
    "packet",
    "http-body",
    "http-body-printable",
    "http_body",
    "http_body_printable",
    "http_body_preview",
    "http_uri",
    "http_host",
    "http_user_agent",
    "download_url",
]


def _parse_infra_ips(
    ips: list[str],
) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse valid IP literals into canonical ipaddress objects."""
    parsed: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for ip_str in ips:
        try:
            parsed.add(ipaddress.ip_address(ip_str.strip()))
        except ValueError:
            continue
    return parsed


def _parse_cidrs(
    cidrs: list[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse CIDR strings into ip_network objects (strict=False tolerates host bits)."""
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            continue
    return nets


def derive_ip_variants(ip_str: str) -> list[str]:
    """Derive literal + non-dotted / PTR / expanded encodings of an infrastructure IP.

    Covers:
    - IPv4 ``a.b.c.d``: dotted, underscore (``a_b_c_d``), dash (``a-b-c-d``),
      reversed dotted (``d.c.b.a``), reversed dash (``d-c-b-a``), and ISP PTR
      label (``d.ip-a-b-c``).
    - IPv6: compressed, fully expanded (39 chars), and dash-delimited variants.
    """
    cleaned = ip_str.strip()
    if not cleaned:
        return []
    variants: list[str] = [cleaned]
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return variants

    if isinstance(addr, ipaddress.IPv4Address):
        dotted = str(addr)
        octets = dotted.split(".")
        rev = list(reversed(octets))
        candidates = [
            dotted,
            "_".join(octets),
            "-".join(octets),
            ".".join(rev),
            "-".join(rev),
            f"{octets[3]}.ip-{octets[0]}-{octets[1]}-{octets[2]}",
        ]
    else:
        compressed = addr.compressed
        exploded = addr.exploded
        candidates = [
            compressed,
            exploded,
            compressed.replace(":", "-"),
            exploded.replace(":", "-"),
        ]

    for candidate in candidates:
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants


def build_content_replacement_map(config: RedactionConfig) -> dict[str, str]:
    """Build mapping of all infra IP variants -> pseudonym for substring scrubbing."""
    mapping: dict[str, str] = {}
    # Start with configured pseudonym_map entries so explicit labels take precedence
    for real_ip, pseudonym in config.pseudonym_map.items():
        if not real_ip:
            continue
        for variant in derive_ip_variants(real_ip):
            mapping.setdefault(variant, pseudonym)

    # Ensure every infrastructure_ip has at least a fallback pseudonym
    for infra_ip in config.infrastructure_ips:
        if not infra_ip:
            continue
        pseudonym = config.pseudonym_map.get(infra_ip, "redacted-infra")
        for variant in derive_ip_variants(infra_ip):
            mapping.setdefault(variant, pseudonym)

    return mapping


def scrub_infra_strings(text: str, config: RedactionConfig) -> str:
    """Scrub all configured infra IP variants and hostnames from an arbitrary string.

    Used by error-message sanitizers (``enrichment_errors.json`` / Discord) and
    tests so raw WAN IPs or hostnames cannot escape via exception text.
    """
    if not text:
        return text
    result = text
    replacements = build_content_replacement_map(config)
    for variant, pseudonym in sorted(replacements.items(), key=lambda kv: len(kv[0]), reverse=True):
        if variant in result:
            result = result.replace(variant, pseudonym)
    for hostname in sorted(
        {h.strip() for h in config.infrastructure_hostnames if h and h.strip()},
        key=len,
        reverse=True,
    ):
        result = re.sub(re.escape(hostname), "honeypot-host", result, flags=re.IGNORECASE)
    return result


def drop_infrastructure_source_rows(
    df: pl.DataFrame,
    config: RedactionConfig,
) -> pl.DataFrame:
    """Drop rows whose source IP is one of the operation's own addresses.

    Checks exact string match, canonical parsed-IP equivalence (catching
    expanded IPv6 WAN addresses not covered by a CIDR), and CIDR membership.
    """
    if df.is_empty():
        return df

    infra_set = set(config.infrastructure_ips)
    parsed_infra = _parse_infra_ips(config.infrastructure_ips)
    cidr_nets = _parse_cidrs(config.infrastructure_cidrs)

    if not infra_set and not parsed_infra and not cidr_nets:
        return df

    src_columns_present = [col for col in SRC_IP_COLUMNS if col in df.columns]
    if not src_columns_present:
        return df

    def _is_infra(val: str) -> bool:
        if val in infra_set:
            return True
        try:
            addr = ipaddress.ip_address(val)
        except ValueError:
            return False
        return addr in parsed_infra or any(addr in net for net in cidr_nets)

    keep_mask: pl.Expr = pl.lit(value=True)
    for col in src_columns_present:
        unique_vals = df.get_column(col).drop_nulls().unique().to_list()
        infra_in_col = {v for v in unique_vals if isinstance(v, str) and _is_infra(v)}
        if infra_in_col:
            keep_mask = keep_mask & ~pl.col(col).is_in(list(infra_in_col))

    return df.filter(keep_mask)


def _exact_match_redact_expr(col_name: str, pseudonym_map: dict[str, str]) -> pl.Expr:
    """Build a polars expression that pseudonymizes exact-IP matches in a column."""
    expr = pl.col(col_name)
    for real_ip, pseudonym in pseudonym_map.items():
        expr = pl.when(pl.col(col_name) == real_ip).then(pl.lit(pseudonym)).otherwise(expr)
    return expr.alias(col_name)


def _substring_redact_expr(
    col_name: str,
    replacements: dict[str, str],
    hostnames: list[str],
) -> pl.Expr:
    """Build a polars expression scrubbing infra IP variants and hostnames.

    Sorted longest-key-first so shorter prefixes (e.g. ``10.50.99.1``) never
    corrupt longer addresses sharing that prefix (``10.50.99.100``).
    Hostnames are matched case-insensitively.
    """
    expr = pl.col(col_name)
    for variant, pseudonym in sorted(replacements.items(), key=lambda kv: len(kv[0]), reverse=True):
        expr = expr.str.replace_all(variant, pseudonym, literal=True)
    for hostname in sorted(
        {h.strip() for h in hostnames if h and h.strip()},
        key=len,
        reverse=True,
    ):
        expr = expr.str.replace_all(f"(?i){re.escape(hostname)}", "honeypot-host")
    return expr.alias(col_name)


def _build_dst_replacement_map(
    df: pl.DataFrame,
    col_name: str,
    config: RedactionConfig,
    parsed_pseudonyms: dict[ipaddress.IPv4Address | ipaddress.IPv6Address, str],
    parsed_infra: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
    cidr_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> dict[str, str]:
    """Build exact string replacement map for an IP column including IPv6 variants and CIDRs."""
    effective_map: dict[str, str] = dict(config.pseudonym_map)
    if df.schema.get(col_name) != pl.Utf8:
        return effective_map

    infra_set = set(config.infrastructure_ips)
    unique_vals = df.get_column(col_name).drop_nulls().unique().to_list()
    for val in unique_vals:
        if not isinstance(val, str) or val in effective_map:
            continue
        try:
            addr = ipaddress.ip_address(val)
        except ValueError:
            continue
        if addr in parsed_pseudonyms:
            effective_map[val] = parsed_pseudonyms[addr]
        elif val in infra_set or addr in parsed_infra or any(addr in net for net in cidr_nets):
            effective_map[val] = "redacted-infra"
    return effective_map


def redact_infrastructure_ips(
    df: pl.DataFrame,
    config: RedactionConfig,
) -> pl.DataFrame:
    """Pseudonymize known infrastructure IPs and hostnames across IP and content columns.

    Two passes:

    1. **IP-typed columns** (``DST_IP_COLUMNS``) — exact-match swap plus
       expanded/compressed IPv6 normalization and CIDR fallback to
       ``"redacted-infra"``.
    2. **Attacker-content columns** (``ATTACKER_CONTENT_COLUMNS``) —
       longest-first substring replacement across dotted, non-dotted
       (underscore/dash/PTR), expanded IPv6 variants, and configured
       ``infrastructure_hostnames``.
    """
    if df.is_empty():
        return df

    dst_columns = [col for col in DST_IP_COLUMNS if col in df.columns]
    content_columns = [
        col for col in ATTACKER_CONTENT_COLUMNS if col in df.columns and df.schema[col] == pl.Utf8
    ]

    if not dst_columns and not content_columns:
        return df

    parsed_pseudonyms: dict[ipaddress.IPv4Address | ipaddress.IPv6Address, str] = {}
    for real_ip, pseudonym in config.pseudonym_map.items():
        try:
            parsed_pseudonyms[ipaddress.ip_address(real_ip)] = pseudonym
        except ValueError:
            continue

    parsed_infra = _parse_infra_ips(config.infrastructure_ips)
    cidr_nets = _parse_cidrs(config.infrastructure_cidrs)
    content_replacements = build_content_replacement_map(config)

    def _apply_dst(frame: pl.DataFrame, col_name: str) -> pl.DataFrame:
        effective_map = _build_dst_replacement_map(
            frame,
            col_name,
            config,
            parsed_pseudonyms,
            parsed_infra,
            cidr_nets,
        )
        return frame.with_columns(_exact_match_redact_expr(col_name, effective_map))

    def _apply_content(frame: pl.DataFrame, col_name: str) -> pl.DataFrame:
        return frame.with_columns(
            _substring_redact_expr(
                col_name,
                content_replacements,
                config.infrastructure_hostnames,
            )
        )

    df = reduce(_apply_dst, dst_columns, df)
    return reduce(_apply_content, content_columns, df)


def validate_no_leaks(df: pl.DataFrame, config: RedactionConfig) -> bool:
    """Assert that zero infrastructure IPs remain in IP-typed columns.

    Checks exact string match, canonical parsed-IP equivalence (catching
    expanded IPv6 WAN addresses), and CIDR membership.

    OPSEC invariant: the ``ValueError`` message NEVER includes the raw leaked
    IP or CIDR string — only the column name, affected row count, and a short
    SHA-256 prefix — so an uncaught validation error recorded in
    ``enrichment_errors.json`` or posted to Discord cannot leak the WAN IP.
    """
    if df.is_empty():
        return True

    ip_set = set(config.infrastructure_ips)
    parsed_infra = _parse_infra_ips(config.infrastructure_ips)
    cidr_nets = _parse_cidrs(config.infrastructure_cidrs)

    ip_cols = [
        col
        for col in DST_IP_COLUMNS + SRC_IP_COLUMNS
        if col in df.columns and df.schema[col] == pl.Utf8
    ]

    for col_name in ip_cols:
        series = df.get_column(col_name).drop_nulls()
        unique_vals = series.unique().to_list()
        for val in unique_vals:
            if not isinstance(val, str):
                continue
            leaked = val in ip_set
            if not leaked:
                try:
                    addr = ipaddress.ip_address(val)
                except ValueError:
                    continue  # Not an IP literal — pseudonym or junk, skip.
                leaked = addr in parsed_infra or any(addr in net for net in cidr_nets)
            if leaked:
                digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:12]
                row_count = int((series == val).sum())
                msg = (
                    f"Infrastructure IP leak in column '{col_name}' "
                    f"({row_count} row(s), sha256={digest})"
                )
                raise ValueError(msg)

    return True

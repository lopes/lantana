"""Raw IOC export for the dashboard's STIX Export page.

Builds a flat, gzipped CSV of every IP / hash / URL observed in silver
on a given date, with provenance (datasets, count, first/last seen) and
``risk_score`` joined for IPs. The long-tail counterpart to
``intel/stix.py``: STIX exports only the threshold-gated subset; this
exports everything, so analysts can retro-hunt, seed IDS rules, or feed
home-lab correlation against the full day's surface.

OPSEC: silver is already pseudonymized (layer 2), so this module does
not re-redact. It does drop parser-noise IPs (unspecified, loopback,
multicast, link-local) and any value that fails ``ipaddress.ip_address``
— pseudonyms like ``honeypot-sensor-01`` fall through the same gate.
"""

from __future__ import annotations

import gzip
import io
import ipaddress

import polars as pl


def _is_real_attacker_ip(ip: str) -> bool:
    """Drop parser-noise and pseudonyms from the IP export.

    Unspecified (``0.0.0.0``, ``::``), loopback, multicast, and
    link-local addresses appear when a parser couldn't extract a real
    source IP from a log line. Strings that don't parse as an IP literal
    (e.g. ``honeypot-sensor-01``) raise ``ValueError`` and are dropped
    by the same gate.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_unspecified or addr.is_loopback or addr.is_multicast or addr.is_link_local)


def _build_ip_rows(
    df: pl.DataFrame,
    reputation: pl.DataFrame,
) -> list[dict[str, object]]:
    """Aggregate IP IOCs per ``src_endpoint_ip`` and join risk_score.

    Returns rows ready for the CSV writer. Datasets are joined as a
    semicolon-separated string so each IOC stays on one row regardless
    of how many honeypot datasets observed it.
    """
    if "src_endpoint_ip" not in df.columns:
        return []

    agg = (
        df.filter(pl.col("src_endpoint_ip").is_not_null())
        .group_by("src_endpoint_ip")
        .agg(
            pl.col("dataset").unique().alias("datasets"),
            pl.len().alias("count"),
            pl.col("time").min().alias("first_seen"),
            pl.col("time").max().alias("last_seen"),
        )
    )

    if not reputation.is_empty() and "risk_score" in reputation.columns:
        agg = agg.join(
            reputation.select(["src_endpoint_ip", "risk_score"]),
            on="src_endpoint_ip",
            how="left",
        )
    else:
        agg = agg.with_columns(
            pl.lit(None, dtype=pl.Float64).alias("risk_score"),
        )

    rows: list[dict[str, object]] = []
    for r in agg.iter_rows(named=True):
        ip = r["src_endpoint_ip"]
        if not isinstance(ip, str) or not _is_real_attacker_ip(ip):
            continue
        datasets = ";".join(sorted(str(d) for d in (r.get("datasets") or []) if d))
        rows.append(
            {
                "ioc_type": "ip",
                "value": ip,
                "datasets": datasets,
                "count": int(r["count"]),
                "risk_score": r.get("risk_score"),
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
        )
    return rows


def _build_value_rows(
    df: pl.DataFrame,
    column: str,
    ioc_type: str,
) -> list[dict[str, object]]:
    """Aggregate string-valued IOCs (file hashes, URLs) on ``column``.

    Same shape as ``_build_ip_rows`` but with ``risk_score`` left null —
    enrichment for hashes is captured separately in VT-derived columns
    that don't fit the per-IP scoring model.
    """
    if column not in df.columns:
        return []

    agg = (
        df.filter(pl.col(column).is_not_null())
        .group_by(column)
        .agg(
            pl.col("dataset").unique().alias("datasets"),
            pl.len().alias("count"),
            pl.col("time").min().alias("first_seen"),
            pl.col("time").max().alias("last_seen"),
        )
    )

    rows: list[dict[str, object]] = []
    for r in agg.iter_rows(named=True):
        value = r[column]
        if not isinstance(value, str) or not value:
            continue
        datasets = ";".join(sorted(str(d) for d in (r.get("datasets") or []) if d))
        rows.append(
            {
                "ioc_type": ioc_type,
                "value": value,
                "datasets": datasets,
                "count": int(r["count"]),
                "risk_score": None,
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
        )
    return rows


def build_raw_ioc_export(
    silver: pl.LazyFrame,
    reputation: pl.DataFrame,
) -> tuple[bytes, int] | None:
    """Build a gzipped CSV containing every IP / hash / URL in silver.

    Returns ``(csv_gz_bytes, ioc_count)`` or ``None`` when there are no
    IOCs to export (silver empty or no IOC-bearing columns).

    Columns: ``ioc_type, value, datasets, count, risk_score,
    first_seen, last_seen``. Sorted by ``(ioc_type, value)`` for stable
    diffs across runs.
    """
    schema = silver.collect_schema()
    needed = ["src_endpoint_ip", "dataset", "time"]
    optional = ["file_hash_sha256", "file_url"]
    select_cols = [c for c in needed + optional if c in schema.names()]
    if "src_endpoint_ip" not in select_cols:
        return None

    df = silver.select(select_cols).collect()
    if df.is_empty():
        return None

    rows: list[dict[str, object]] = []
    rows.extend(_build_ip_rows(df, reputation))
    rows.extend(_build_value_rows(df, "file_hash_sha256", "hash_sha256"))
    rows.extend(_build_value_rows(df, "file_url", "url"))

    if not rows:
        return None

    out_schema: dict[str, pl.DataType] = {
        "ioc_type": pl.Utf8(),
        "value": pl.Utf8(),
        "datasets": pl.Utf8(),
        "count": pl.Int64(),
        "risk_score": pl.Float64(),
        "first_seen": pl.Datetime(time_unit="us", time_zone="UTC"),
        "last_seen": pl.Datetime(time_unit="us", time_zone="UTC"),
    }
    out_df = pl.DataFrame(rows, schema=out_schema).sort(["ioc_type", "value"])

    buf = io.BytesIO()
    out_df.write_csv(buf)
    return gzip.compress(buf.getvalue()), out_df.height

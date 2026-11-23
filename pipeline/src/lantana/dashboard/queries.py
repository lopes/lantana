"""Pure Polars query & multi-day Gold/Silver rollup functions for the Vigil dashboard.

Zero Pandas, zero HTTP dependencies, and zero multi-day Silver OOM:
- Gold views read strictly from Gold Parquet via ``read_gold_range()``.
- Raw IOC export aggregates Silver **one day at a time** into a compact
  dictionary before emitting gzipped CSV bytes.
"""

from __future__ import annotations

import gzip
import io
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING

import polars as pl

from lantana.common.datalake import (
    GOLD_ROOT,
    SILVER_ROOT,
    list_gold_dates,
    read_gold_range,
    read_gold_table,
    read_silver_partition,
)
from lantana.enrichment.allowlist import (
    VERIFICATION_STATUS_SUPPRESSED,
    VERIFICATION_STATUS_UNVERIFIED,
    VERIFICATION_STATUS_VERIFIED,
    should_export_ioc_to_stix,
)
from lantana.intel.iocs import build_raw_ioc_export
from lantana.intel.stix import RISK_HIGH_THRESHOLD, RISK_THRESHOLD, generate_bundle
from lantana.transform.metrics import STAGE_LABELS

if TYPE_CHECKING:
    from pathlib import Path

    import stix2

    from lantana.common.config import ReportingConfig, StixExportConfig

VALID_WINDOW_MODES: tuple[str, ...] = ("latest", "7d", "30d", "custom", "all")


@dataclass(frozen=True)
class DateWindow:
    """Resolved date window selected by the operator in the navbar."""

    mode: str
    start_date: date | None
    end_date: date | None
    dates: list[date]
    available_dates: list[date]
    label: str

    @property
    def is_multi_day(self) -> bool:
        return len(self.dates) > 1


def discover_available_dates(gold_root: Path = GOLD_ROOT) -> list[date]:
    """Return available Gold dates sorted descending (newest first)."""
    dates = list_gold_dates("daily_summary", gold_root=gold_root)
    if dates:
        return dates
    return list_gold_dates("ip_reputation", gold_root=gold_root)


def _parse_iso_date(raw: str | None) -> date | None:
    if not raw:
        return None
    try:
        return date.fromisoformat(raw.strip())
    except ValueError:
        return None


def resolve_window(
    available_dates: list[date],
    *,
    mode: str | None = None,
    start: str | None = None,
    end: str | None = None,
) -> DateWindow:
    """Resolve ``window``/``start``/``end`` query parameters against available Gold dates."""
    clean_mode = (mode or "latest").strip().lower()
    if clean_mode not in VALID_WINDOW_MODES:
        clean_mode = "latest"

    sorted_desc = sorted(set(available_dates), reverse=True)
    if not sorted_desc:
        return DateWindow(
            mode=clean_mode,
            start_date=None,
            end_date=None,
            dates=[],
            available_dates=[],
            label="No data",
        )

    newest = sorted_desc[0]
    oldest = sorted_desc[-1]

    if clean_mode == "latest":
        chosen = [newest]
        label = newest.isoformat()
    elif clean_mode == "7d":
        cutoff = newest - timedelta(days=6)
        chosen = sorted(d for d in sorted_desc if d >= cutoff)
        label = f"Last 7d ({chosen[0].isoformat()} → {chosen[-1].isoformat()})"
    elif clean_mode == "30d":
        cutoff = newest - timedelta(days=29)
        chosen = sorted(d for d in sorted_desc if d >= cutoff)
        label = f"Last 30d ({chosen[0].isoformat()} → {chosen[-1].isoformat()})"
    elif clean_mode == "all":
        chosen = sorted(sorted_desc)
        label = (
            f"All-Time ({oldest.isoformat()} → {newest.isoformat()}, {len(chosen)}d)"
            if len(chosen) > 1
            else newest.isoformat()
        )
    else:  # custom
        parsed_start = _parse_iso_date(start) or oldest
        parsed_end = _parse_iso_date(end) or newest
        if parsed_start > parsed_end:
            parsed_start, parsed_end = parsed_end, parsed_start
        chosen = sorted(d for d in sorted_desc if parsed_start <= d <= parsed_end)
        if not chosen:
            label = f"Custom ({parsed_start.isoformat()} → {parsed_end.isoformat()}, 0d)"
        elif len(chosen) == 1:
            label = chosen[0].isoformat()
        else:
            label = f"{chosen[0].isoformat()} → {chosen[-1].isoformat()} ({len(chosen)}d)"
        return DateWindow(
            mode="custom",
            start_date=parsed_start,
            end_date=parsed_end,
            dates=chosen,
            available_dates=sorted_desc,
            label=label,
        )

    return DateWindow(
        mode=clean_mode,
        start_date=chosen[0],
        end_date=chosen[-1],
        dates=chosen,
        available_dates=sorted_desc,
        label=label,
    )


def _merge_top_n_structs(
    summary_df: pl.DataFrame,
    column: str,
    *,
    limit: int = 15,
) -> list[dict[str, object]]:
    """Aggregate ``list[struct{value, count}]`` top-N columns across daily_summary rows."""
    if summary_df.is_empty() or column not in summary_df.columns:
        return []
    counts: dict[str, int] = {}
    for entries in summary_df.get_column(column).to_list():
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            val = item.get("value")
            cnt = item.get("count")
            if val is None or cnt is None:
                continue
            key = str(val)
            counts[key] = counts.get(key, 0) + int(cnt)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return [
        {"rank": idx, "value": val, "count": cnt} for idx, (val, cnt) in enumerate(ranked, start=1)
    ]


def _merge_credential_pairs(
    summary_df: pl.DataFrame,
    *,
    limit: int = 15,
) -> list[dict[str, object]]:
    """Aggregate ``top_credential_pairs`` struct lists across dates."""
    if summary_df.is_empty() or "top_credential_pairs" not in summary_df.columns:
        return []
    counts: dict[tuple[str, str], int] = {}
    for entries in summary_df.get_column("top_credential_pairs").to_list():
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            u = item.get("username")
            p = item.get("password")
            cnt = item.get("count")
            if u is None or p is None or cnt is None:
                continue
            key = (str(u), str(p))
            counts[key] = counts.get(key, 0) + int(cnt)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1]))[:limit]
    return [
        {"rank": idx, "username": u, "password": p, "count": cnt}
        for idx, ((u, p), cnt) in enumerate(ranked, start=1)
    ]


def aggregate_ip_reputation(dates: list[date], gold_root: Path = GOLD_ROOT) -> pl.DataFrame:
    """Aggregate ``ip_reputation`` across ``dates`` to one row per unique ``src_endpoint_ip``."""
    df = read_gold_range("ip_reputation", dates, gold_root=gold_root)
    if df.is_empty() or "src_endpoint_ip" not in df.columns:
        return pl.DataFrame()
    df = df.filter(pl.col("src_endpoint_ip").is_not_null())
    if df.is_empty():
        return pl.DataFrame()
    if len(dates) <= 1:
        return df.drop("report_date") if "report_date" in df.columns else df

    aggs: list[pl.Expr] = [
        pl.col("risk_score").max().alias("risk_score"),
        pl.col("total_events").sum().alias("total_events"),
    ]
    for col in (
        "enrichment_risk_score",
        "behavioral_risk_score",
        "abuseipdb_risk_score",
        "virustotal_risk_score",
        "shodan_risk_score",
        "greynoise_risk_score",
        "abuseipdb_score",
        "abuseipdb_reports",
        "vt_malicious",
    ):
        if col in df.columns:
            aggs.append(pl.col(col).max().alias(col))
    for col in (
        "auth_attempts",
        "auth_successes",
        "commands_executed",
        "downloads",
        "findings_triggered",
    ):
        if col in df.columns:
            aggs.append(pl.col(col).sum().alias(col))
    for col in (
        "geo_country",
        "geo_city",
        "geo_latitude",
        "geo_longitude",
        "geo_asn",
        "geo_isp",
        "greynoise_class",
        "greynoise_name",
        "shodan_ports",
        "shodan_os",
        "shodan_vulns",
        "shodan_org",
        "gti_verdict",
        "gti_threat_actors",
    ):
        if col in df.columns:
            aggs.append(pl.col(col).drop_nulls().first().alias(col))
    if "greynoise_riot" in df.columns:
        aggs.append(pl.col("greynoise_riot").fill_null(False).any().alias("greynoise_riot"))
    if "first_seen" in df.columns:
        aggs.append(pl.col("first_seen").min().alias("first_seen"))
    if "last_seen" in df.columns:
        aggs.append(pl.col("last_seen").max().alias("last_seen"))
    if "datasets" in df.columns:
        aggs.append(pl.col("datasets").explode().drop_nulls().unique().alias("datasets"))
    if "report_date" in df.columns:
        aggs.append(pl.col("report_date").n_unique().alias("active_days"))

    return (
        df.group_by("src_endpoint_ip")
        .agg(aggs)
        .sort(["risk_score", "total_events"], descending=[True, True])
    )


def aggregate_extracted_iocs(dates: list[date], gold_root: Path = GOLD_ROOT) -> pl.DataFrame:
    """Aggregate ``extracted_iocs`` across ``dates`` grouped by ``(ioc_type, ioc_value)``."""
    df = read_gold_range("extracted_iocs", dates, gold_root=gold_root)
    if df.is_empty():
        return pl.DataFrame()
    if len(dates) <= 1:
        return df.drop("report_date") if "report_date" in df.columns else df

    aggs: list[pl.Expr] = [
        pl.col("event_count").sum().alias("event_count"),
        pl.col("unique_src_ips").sum().alias("unique_src_ips"),
    ]
    if "first_seen" in df.columns:
        aggs.append(pl.col("first_seen").min().alias("first_seen"))
    if "last_seen" in df.columns:
        aggs.append(pl.col("last_seen").max().alias("last_seen"))
    for col in (
        "vhash",
        "vt_status",
        "gti_verdict",
        "malware_family",
        "actor_associations",
    ):
        if col in df.columns:
            aggs.append(pl.col(col).drop_nulls().first().alias(col))
    for col in ("vt_malicious", "gti_score"):
        if col in df.columns:
            aggs.append(pl.col(col).max().alias(col))
    if "verification_status" in df.columns:
        rank_expr = (
            pl.when(pl.col("verification_status") == VERIFICATION_STATUS_SUPPRESSED)
            .then(pl.lit(3))
            .when(pl.col("verification_status") == VERIFICATION_STATUS_VERIFIED)
            .then(pl.lit(2))
            .when(pl.col("verification_status") == VERIFICATION_STATUS_UNVERIFIED)
            .then(pl.lit(1))
            .otherwise(pl.lit(0))
        )
        df = df.with_columns(rank_expr.alias("_verif_rank"))
        aggs.append(
            pl.col("verification_status")
            .sort_by("_verif_rank", descending=True)
            .first()
            .alias("verification_status")
        )
        if "verification_reason" in df.columns:
            aggs.append(
                pl.col("verification_reason")
                .sort_by("_verif_rank", descending=True)
                .first()
                .alias("verification_reason")
            )
    if "report_date" in df.columns:
        aggs.append(pl.col("report_date").n_unique().alias("active_days"))

    return (
        df.group_by(["ioc_type", "ioc_value"])
        .agg(aggs)
        .sort(["event_count", "ioc_value"], descending=[True, False])
    )


def aggregate_campaign_clusters(dates: list[date], gold_root: Path = GOLD_ROOT) -> pl.DataFrame:
    """Roll up ``campaign_clusters`` across dates by exact IP set union per credential pair."""
    df = read_gold_range("campaign_clusters", dates, gold_root=gold_root)
    if df.is_empty():
        return pl.DataFrame()
    if len(dates) <= 1:
        return df.drop("report_date") if "report_date" in df.columns else df

    aggs: list[pl.Expr] = [
        pl.col("ips").explode().drop_nulls().unique().sort().alias("ips"),
        pl.col("total_events").sum().alias("total_events"),
    ]
    if "cluster_id" in df.columns:
        aggs.append(pl.col("cluster_id").first().alias("cluster_id"))
    if "first_seen" in df.columns:
        aggs.append(pl.col("first_seen").min().alias("first_seen"))
    if "last_seen" in df.columns:
        aggs.append(pl.col("last_seen").max().alias("last_seen"))

    return (
        df.group_by(["shared_username", "shared_password"])
        .agg(aggs)
        .with_columns(pl.col("ips").list.len().cast(pl.Int64).alias("ip_count"))
        .sort(["ip_count", "total_events"], descending=[True, True])
    )


def aggregate_detection_findings(dates: list[date], gold_root: Path = GOLD_ROOT) -> pl.DataFrame:
    """Roll up ``detection_findings`` across dates preserving ``finding_uid`` and IP-days."""
    df = read_gold_range("detection_findings", dates, gold_root=gold_root)
    if df.is_empty():
        return pl.DataFrame()
    if len(dates) <= 1:
        return (
            df.drop("report_date").sort("event_count", descending=True)
            if "report_date" in df.columns
            else df.sort("event_count", descending=True)
        )

    group_keys = ["finding_title"]
    if "finding_uid" in df.columns:
        group_keys.append("finding_uid")

    aggs: list[pl.Expr] = [
        pl.col("event_count").sum().alias("event_count"),
        pl.col("unique_ips").sum().alias("unique_ips"),
    ]
    if "severity_id" in df.columns:
        aggs.append(pl.col("severity_id").max().alias("severity_id"))
    if "category" in df.columns:
        aggs.append(pl.col("category").drop_nulls().first().alias("category"))
    if "first_seen" in df.columns:
        aggs.append(pl.col("first_seen").min().alias("first_seen"))
    if "last_seen" in df.columns:
        aggs.append(pl.col("last_seen").max().alias("last_seen"))

    return df.group_by(group_keys).agg(aggs).sort("event_count", descending=True)


def aggregate_behavioral_progression(
    dates: list[date],
    gold_root: Path = GOLD_ROOT,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """Return ``(window_progression, multiday_rollup)`` over ``behavioral_progression``.

    When the active window is a single day, ``multiday_rollup`` automatically
    computes the trailing 7-day lookback ending on that day; for multi-day
    windows, it summarizes active days across the selected window itself.
    """
    window_df = read_gold_range("behavioral_progression", dates, gold_root=gold_root)
    if not window_df.is_empty() and "src_endpoint_ip" in window_df.columns:
        window_df = window_df.filter(pl.col("src_endpoint_ip").is_not_null())

    if window_df.is_empty():
        return pl.DataFrame(), pl.DataFrame()

    if len(dates) > 1:
        aggs: list[pl.Expr] = [
            pl.col("max_stage").max().alias("max_stage"),
            pl.col("is_automated").fill_null(False).any().alias("is_automated"),
            pl.col("scan_events").sum().alias("scan_events"),
            pl.col("auth_attempts").sum().alias("auth_attempts"),
            pl.col("auth_successes").sum().alias("auth_successes"),
            pl.col("commands_executed").sum().alias("commands_executed"),
            pl.col("first_seen").min().alias("first_seen"),
            pl.col("last_seen").max().alias("last_seen"),
        ]
        for timing_col in ("seconds_to_auth", "seconds_to_success", "seconds_to_command"):
            if timing_col in window_df.columns:
                aggs.append(pl.col(timing_col).min().alias(timing_col))
        per_ip = (
            window_df.group_by("src_endpoint_ip")
            .agg(aggs)
            .with_columns(
                pl.col("max_stage")
                .replace_strict(STAGE_LABELS, default="unknown")
                .alias("stage_label")
            )
            .sort(["max_stage", "commands_executed"], descending=[True, True])
        )
        lookback_source = window_df
    else:
        per_ip = window_df.drop("report_date") if "report_date" in window_df.columns else window_df
        anchor = dates[0]
        lookback_dates = [anchor - timedelta(days=offset) for offset in range(7)]
        lookback_source = read_gold_range(
            "behavioral_progression", lookback_dates, gold_root=gold_root
        )
        if not lookback_source.is_empty() and "src_endpoint_ip" in lookback_source.columns:
            lookback_source = lookback_source.filter(pl.col("src_endpoint_ip").is_not_null())

    if lookback_source.is_empty():
        return per_ip, pl.DataFrame()

    multiday = (
        lookback_source.group_by("src_endpoint_ip")
        .agg(
            pl.col("report_date").min().alias("first_seen_date"),
            pl.col("report_date").max().alias("last_seen_date"),
            pl.col("report_date").n_unique().alias("active_days"),
            pl.col("max_stage").max().alias("max_stage"),
        )
        .with_columns(
            pl.col("max_stage")
            .replace_strict(STAGE_LABELS, default="unknown")
            .alias("stage_label"),
            (pl.col("last_seen_date") - pl.col("first_seen_date"))
            .dt.total_days()
            .cast(pl.Int64)
            .alias("progression_velocity_days"),
        )
        .with_columns((pl.col("active_days") > 1).alias("is_multi_day"))
        .sort(["progression_velocity_days", "active_days"], descending=[True, True])
    )
    return per_ip, multiday


@dataclass(frozen=True)
class OverviewBundle:
    total_events: int
    unique_ips: int
    auth_attempts: int
    auth_successes: int
    auth_failures: int
    commands_executed: int
    downloads_captured: int
    unique_malware_hashes: int
    outbound_c2_and_urls: int
    findings_detected: int
    network_events: int
    daily_trend: pl.DataFrame
    top_usernames: list[dict[str, object]]
    top_passwords: list[dict[str, object]]
    top_commands: list[dict[str, object]]
    top_countries: list[dict[str, object]]
    top_asns: list[dict[str, object]]


def load_overview(dates: list[date], gold_root: Path = GOLD_ROOT) -> OverviewBundle | None:
    """Compute overview KPIs, multi-day trend, and top-N tables across ``dates``."""
    summary_df = read_gold_range("daily_summary", dates, gold_root=gold_root)
    if summary_df.is_empty():
        return None

    ip_rep = aggregate_ip_reputation(dates, gold_root=gold_root)
    iocs = aggregate_extracted_iocs(dates, gold_root=gold_root)

    def _sum_col(name: str) -> int:
        if name not in summary_df.columns:
            return 0
        raw = summary_df.get_column(name).fill_null(0).sum()
        return int(raw) if isinstance(raw, (int, float)) else 0

    unique_ips = ip_rep.height if not ip_rep.is_empty() else _sum_col("unique_source_ips")

    unique_hashes = 0
    outbound_c2_urls = 0
    if not iocs.is_empty() and "ioc_type" in iocs.columns:
        unique_hashes = iocs.filter(pl.col("ioc_type") == "malware_hash").height
        outbound_c2_urls = iocs.filter(
            pl.col("ioc_type").is_in(["c2_ip", "stager_url", "stager_domain"])
        ).height

    # Top ASNs derived from aggregated ip_reputation (deduplicated across window)
    top_asns: list[dict[str, object]] = []
    if not ip_rep.is_empty() and "geo_asn" in ip_rep.columns:
        asn_df = (
            ip_rep.filter(pl.col("geo_asn").is_not_null())
            .with_columns(
                pl.col("geo_isp").fill_null("Unknown")
                if "geo_isp" in ip_rep.columns
                else pl.lit("Unknown").alias("geo_isp")
            )
            .group_by(["geo_asn", "geo_isp"])
            .agg(
                pl.col("src_endpoint_ip").n_unique().alias("unique_ips"),
                pl.col("total_events").sum().alias("events"),
            )
            .sort(["unique_ips", "events"], descending=[True, True])
            .head(10)
        )
        for idx, row in enumerate(asn_df.iter_rows(named=True), start=1):
            top_asns.append(
                {
                    "rank": idx,
                    "asn": f"AS{row['geo_asn']}",
                    "isp": str(row["geo_isp"]),
                    "unique_ips": int(row["unique_ips"]),
                    "events": int(row["events"]),
                }
            )

    trend_cols = [
        c
        for c in (
            "report_date",
            "total_events",
            "unique_source_ips",
            "auth_attempts",
            "commands_executed",
            "findings_detected",
        )
        if c in summary_df.columns
    ]
    daily_trend = summary_df.select(trend_cols).sort("report_date")

    return OverviewBundle(
        total_events=_sum_col("total_events"),
        unique_ips=unique_ips,
        auth_attempts=_sum_col("auth_attempts"),
        auth_successes=_sum_col("auth_successes"),
        auth_failures=_sum_col("auth_failures"),
        commands_executed=_sum_col("commands_executed"),
        downloads_captured=_sum_col("downloads_captured"),
        unique_malware_hashes=unique_hashes,
        outbound_c2_and_urls=outbound_c2_urls,
        findings_detected=_sum_col("findings_detected"),
        network_events=_sum_col("network_events"),
        daily_trend=daily_trend,
        top_usernames=_merge_top_n_structs(summary_df, "top_usernames", limit=10),
        top_passwords=_merge_top_n_structs(summary_df, "top_passwords", limit=10),
        top_commands=_merge_top_n_structs(summary_df, "top_commands", limit=10),
        top_countries=_merge_top_n_structs(summary_df, "top_source_countries", limit=10),
        top_asns=top_asns,
    )


def count_stix_composition(
    reputation: pl.DataFrame,
    clusters: pl.DataFrame,
    extracted_iocs: pl.DataFrame,
    *,
    stix_config: StixExportConfig | None = None,
) -> dict[str, int]:
    """Count every STIX object category emitted by ``intel/stix.py`` for preview KPIs."""
    ip_count = 0
    if not reputation.is_empty():
        mask = pl.col("risk_score") >= RISK_THRESHOLD
        if "behavioral_risk_score" in reputation.columns:
            mask = mask & (pl.col("behavioral_risk_score").fill_null(0.0) > 0.0)
        if "greynoise_riot" in reputation.columns:
            mask = mask & ~pl.col("greynoise_riot").fill_null(False)
        if "greynoise_class" in reputation.columns:
            mask = mask & (pl.col("greynoise_class").fill_null("") != "benign")
        ip_count = reputation.filter(mask).height

    ioc_counts = {
        "malware_hash": 0,
        "c2_ip": 0,
        "stager_url": 0,
        "stager_domain": 0,
        "ssh_key": 0,
    }
    if not extracted_iocs.is_empty() and "ioc_type" in extracted_iocs.columns:
        for row in extracted_iocs.iter_rows(named=True):
            t = str(row.get("ioc_type") or "")
            if t not in ioc_counts:
                continue
            eligible, _, _ = should_export_ioc_to_stix(row, stix_config)
            if eligible:
                ioc_counts[t] += 1

    return {
        "inbound_ips": ip_count,
        "malware_hashes": ioc_counts["malware_hash"],
        "c2_ips": ioc_counts["c2_ip"],
        "stager_urls": ioc_counts["stager_url"],
        "stager_domains": ioc_counts["stager_domain"],
        "ssh_keys": ioc_counts["ssh_key"],
        "campaigns": clusters.height if not clusters.is_empty() else 0,
    }


def build_window_stix_bundle(
    window: DateWindow,
    reporting: ReportingConfig,
    *,
    gold_root: Path = GOLD_ROOT,
) -> stix2.Bundle:
    """Build a STIX 2.1 bundle for the active window (single-day or rolled-up multi-day)."""
    anchor_date = window.end_date or datetime.now(tz=UTC).date()
    reputation = aggregate_ip_reputation(window.dates, gold_root=gold_root)
    progression, _ = aggregate_behavioral_progression(window.dates, gold_root=gold_root)
    clusters = aggregate_campaign_clusters(window.dates, gold_root=gold_root)
    extracted = aggregate_extracted_iocs(window.dates, gold_root=gold_root)
    summary = (
        read_gold_table("daily_summary", anchor_date, gold_root=gold_root)
        if len(window.dates) == 1
        else None
    )
    return generate_bundle(
        gold_date=anchor_date,
        reporting=reporting,
        reputation=reputation,
        progression=progression,
        clusters=clusters,
        summary=summary,
        extracted_iocs=extracted,
    )


def build_window_raw_ioc_csv_gz(
    dates: list[date],
    *,
    silver_root: Path = SILVER_ROOT,
    gold_root: Path = GOLD_ROOT,
) -> tuple[bytes, int] | None:
    """Incrementally aggregate raw Silver IOCs one day at a time to avoid multi-day Silver OOM."""
    if not dates:
        return None

    if len(dates) == 1:
        d = dates[0]
        return build_raw_ioc_export(
            read_silver_partition(d, silver_root=silver_root),
            read_gold_table("ip_reputation", d, gold_root=gold_root),
        )

    merged: dict[tuple[str, str], dict[str, object]] = {}
    for d in sorted(set(dates)):
        silver = read_silver_partition(d, silver_root=silver_root)
        reputation = read_gold_table("ip_reputation", d, gold_root=gold_root)
        day_export = build_raw_ioc_export(silver, reputation)
        if day_export is None:
            continue
        gz_bytes, _ = day_export
        day_df = pl.read_csv(io.BytesIO(gzip.decompress(gz_bytes)))
        for row in day_df.iter_rows(named=True):
            key = (str(row["ioc_type"]), str(row["value"]))
            ds_set = {s for s in str(row.get("datasets") or "").split(";") if s}
            cnt = int(row.get("count") or 0)
            score_raw = row.get("risk_score")
            score = float(score_raw) if isinstance(score_raw, (int, float)) else None
            fs = str(row.get("first_seen") or "")
            ls = str(row.get("last_seen") or "")

            existing = merged.get(key)
            if existing is None:
                merged[key] = {
                    "ioc_type": key[0],
                    "value": key[1],
                    "datasets": ds_set,
                    "count": cnt,
                    "risk_score": score,
                    "first_seen": fs,
                    "last_seen": ls,
                }
            else:
                prev_ds = existing["datasets"]
                if isinstance(prev_ds, set):
                    prev_ds.update(ds_set)
                prev_cnt = existing["count"]
                existing["count"] = (prev_cnt if isinstance(prev_cnt, int) else 0) + cnt
                prev_score = existing["risk_score"]
                if score is not None and (not isinstance(prev_score, float) or score > prev_score):
                    existing["risk_score"] = score
                prev_fs = str(existing["first_seen"] or "")
                prev_ls = str(existing["last_seen"] or "")
                if fs and (not prev_fs or fs < prev_fs):
                    existing["first_seen"] = fs
                if ls and (not prev_ls or ls > prev_ls):
                    existing["last_seen"] = ls

    if not merged:
        return None

    out_rows = []
    for key in sorted(merged):
        item = merged[key]
        ds_val = item["datasets"]
        datasets_str = ";".join(sorted(ds_val)) if isinstance(ds_val, set) else ""
        out_rows.append(
            {
                "ioc_type": item["ioc_type"],
                "value": item["value"],
                "datasets": datasets_str,
                "count": item["count"],
                "risk_score": item["risk_score"],
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
            }
        )

    out_df = pl.DataFrame(
        out_rows,
        schema={
            "ioc_type": pl.Utf8,
            "value": pl.Utf8,
            "datasets": pl.Utf8,
            "count": pl.Int64,
            "risk_score": pl.Float64,
            "first_seen": pl.Utf8,
            "last_seen": pl.Utf8,
        },
    )
    buf = io.BytesIO()
    out_df.write_csv(buf)
    return gzip.compress(buf.getvalue()), out_df.height


def risk_level_label(score: float) -> str:
    """Map composite ``risk_score`` to High / Medium / Low using STIX thresholds."""
    if score >= RISK_HIGH_THRESHOLD:
        return "High"
    if score >= RISK_THRESHOLD:
        return "Medium"
    return "Low"

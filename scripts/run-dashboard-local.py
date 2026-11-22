#!/usr/bin/env python3
"""Build all 7 Gold tables from local/fetched VPS data and launch the Vigil dashboard.

Arguments:
    --live-root  Path to fetched VPS data (default: pipeline/tests/fixtures/live)
    --wan-ip     Real WAN IP address to scrub as infrastructure (repeatable)
    --port       Local HTTP port on 127.0.0.1 (default: 8501)

Example:
    cd pipeline && uv run python ../scripts/run-dashboard-local.py
    cd pipeline && uv run python ../scripts/run-dashboard-local.py --live-root /tmp/vps-data
    cd pipeline && uv run python ../scripts/run-dashboard-local.py --wan-ip 203.0.113.10
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

import polars as pl

from lantana.common.datalake import (
    read_bronze_ndjson,
    write_gold_table,
    write_silver_partition,
)
from lantana.common.redact import (
    RedactionConfig,
    drop_infrastructure_source_rows,
    redact_infrastructure_ips,
    validate_no_leaks,
)
from lantana.dashboard.app import serve
from lantana.models.normalize import normalize_dataset
from lantana.transform.metrics import (
    compute_behavioral_progression,
    compute_campaign_clusters,
    compute_daily_summary,
    compute_detection_findings,
    compute_extracted_iocs,
    compute_geographic_summary,
    compute_ip_reputation,
)

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
PIPELINE_DIR = PROJECT_ROOT / "pipeline"
DEFAULT_LIVE_ROOT = PIPELINE_DIR / "tests" / "fixtures" / "live"

BASE_INFRA_IPS = ["10.50.99.1", "10.50.99.10", "10.50.99.100"]
BASE_INFRA_CIDRS = ["10.50.99.0/24"]
BASE_PSEUDONYM_MAP = {
    "10.50.99.1": "honeypot-wan",
    "10.50.99.10": "honeypot-collector",
    "10.50.99.100": "honeypot-sensor-01",
}

ENRICHMENT_STUBS: dict[str, pl.Expr] = {
    "abuseipdb_confidence_score": pl.lit(None).cast(pl.Int64),
    "greynoise_classification": pl.lit(None).cast(pl.Utf8),
    "greynoise_noise": pl.lit(None).cast(pl.Boolean),
    "geo.country_code": pl.lit(None).cast(pl.Utf8),
    "geo.asn": pl.lit(None).cast(pl.Int64),
    "geo.isp": pl.lit(None).cast(pl.Utf8),
}

OPTIONAL_COLS: dict[str, pl.DataType] = {
    "session": pl.Utf8(),
    "user_name": pl.Utf8(),
    "unmapped_password": pl.Utf8(),
    "actor_process_cmd_line": pl.Utf8(),
    "finding_title": pl.Utf8(),
    "finding_uid": pl.Utf8(),
    "file_hash_sha256": pl.Utf8(),
    "file_url": pl.Utf8(),
    "file_path": pl.Utf8(),
}

LIVE_ROOT: Path = Path()
BRONZE_ROOT: Path = Path()
SILVER_ROOT: Path = Path()
GOLD_ROOT: Path = Path()


def build_redact_config(wan_ips: list[str]) -> RedactionConfig:
    """Build RedactionConfig combining internal prefixes with optional WAN IPs."""
    infra_ips = list(BASE_INFRA_IPS)
    pseudonym_map = dict(BASE_PSEUDONYM_MAP)

    for idx, raw_ip in enumerate(wan_ips, start=1):
        clean_ip = raw_ip.strip()
        if not clean_ip:
            continue
        if clean_ip not in infra_ips:
            infra_ips.append(clean_ip)
        label = "honeypot-wan" if idx == 1 else f"honeypot-wan-{idx}"
        pseudonym_map[clean_ip] = label

    return RedactionConfig(
        infrastructure_ips=infra_ips,
        infrastructure_cidrs=list(BASE_INFRA_CIDRS),
        pseudonym_map=pseudonym_map,
    )


def discover_dates() -> list[date]:
    dates: set[date] = set()
    for d in BRONZE_ROOT.glob("dataset=*/date=*/"):
        if d.name.startswith("date="):
            try:
                dates.add(date.fromisoformat(d.name[5:]))
            except ValueError:
                continue
    return sorted(dates)


def build_gold(target_date: date, redact_config: RedactionConfig) -> None:
    print(f"  Building gold for {target_date} ...")
    datasets: list[str] = []
    for ds_dir in BRONZE_ROOT.glob("dataset=*/"):
        if ds_dir.name.startswith("dataset="):
            datasets.append(ds_dir.name[8:])

    parts: list[pl.DataFrame] = []
    for dataset in sorted(datasets):
        df = read_bronze_ndjson(target_date, dataset=dataset, bronze_root=BRONZE_ROOT)
        if df.is_empty():
            continue

        normalized = normalize_dataset(df, dataset)
        filtered = drop_infrastructure_source_rows(normalized, redact_config)
        if filtered.is_empty():
            continue

        redacted = redact_infrastructure_ips(filtered, redact_config)
        validate_no_leaks(redacted, redact_config)

        stub_cols = [
            expr.alias(n) for n, expr in ENRICHMENT_STUBS.items() if n not in redacted.columns
        ]
        if stub_cols:
            redacted = redacted.with_columns(stub_cols)
        opt_cols = [
            pl.lit(None).cast(dt).alias(n)
            for n, dt in OPTIONAL_COLS.items()
            if n not in redacted.columns
        ]
        if opt_cols:
            redacted = redacted.with_columns(opt_cols)

        server = "unknown"
        if not redacted.is_empty() and "server" in redacted.columns:
            unique_servers = redacted.get_column("server").drop_nulls().unique().to_list()
            if unique_servers:
                server = str(unique_servers[0])

        write_silver_partition(redacted, target_date, dataset, server, silver_root=SILVER_ROOT)

        parts.append(redacted)
        print(f"    {dataset}: {len(redacted):,} events")

    if not parts:
        print(f"  No data for {target_date}")
        return

    silver = pl.concat(parts, how="diagonal_relaxed")

    for name, fn in [
        ("daily_summary", compute_daily_summary),
        ("ip_reputation", compute_ip_reputation),
        ("behavioral_progression", compute_behavioral_progression),
        ("campaign_clusters", compute_campaign_clusters),
        ("geographic_summary", compute_geographic_summary),
        ("detection_findings", compute_detection_findings),
    ]:
        result = fn(silver)
        if not result.is_empty():
            write_gold_table(result, name, target_date, gold_root=GOLD_ROOT)
            print(f"    gold/{name}: {len(result):,} rows")

    iocs = compute_extracted_iocs(silver, redact_config=redact_config)
    if not iocs.is_empty():
        write_gold_table(iocs, "extracted_iocs", target_date, gold_root=GOLD_ROOT)
        print(f"    gold/extracted_iocs: {len(iocs):,} rows")


def main() -> None:
    global LIVE_ROOT, BRONZE_ROOT, SILVER_ROOT, GOLD_ROOT

    parser = argparse.ArgumentParser(
        description="Build all 7 gold tables from live VPS data and launch Vigil dashboard",
    )
    parser.add_argument(
        "--live-root",
        type=Path,
        default=DEFAULT_LIVE_ROOT,
        help="Path to fetched VPS data (default: pipeline/tests/fixtures/live)",
    )
    parser.add_argument(
        "--wan-ip",
        action="append",
        default=[],
        help="Real WAN IP address to scrub as infrastructure (repeatable).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8501,
        help="Local HTTP port on 127.0.0.1 (default: 8501).",
    )
    args = parser.parse_args()

    LIVE_ROOT = args.live_root.resolve()
    BRONZE_ROOT = LIVE_ROOT / "datalake" / "bronze"
    SILVER_ROOT = LIVE_ROOT / "datalake" / "silver"
    GOLD_ROOT = LIVE_ROOT / "datalake" / "gold"

    redact_config = build_redact_config(args.wan_ip)

    if not BRONZE_ROOT.exists():
        print(f"No bronze data at {BRONZE_ROOT}. Run from project root:")
        print("  scripts/fetch-vps-data.sh <host> <key> <port>")
        print("  cd pipeline && uv run python ../scripts/inject-vps-data.py")
        sys.exit(1)

    dates = discover_dates()
    if not dates:
        print("No date partitions found in bronze.")
        sys.exit(1)

    print(f"Found {len(dates)} date(s): {', '.join(d.isoformat() for d in dates)}")
    print()

    for d in dates:
        build_gold(d, redact_config)

    print()
    print(f"Launching air-gapped Vigil dashboard on http://127.0.0.1:{args.port}/overview ...")
    print()
    serve(host="127.0.0.1", port=args.port, gold_root=GOLD_ROOT, silver_root=SILVER_ROOT)


if __name__ == "__main__":
    main()

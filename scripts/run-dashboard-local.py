#!/usr/bin/env python3
"""Build gold tables from live VPS data and launch the Streamlit dashboard.

Arguments:
    --live-root  Path to fetched VPS data (default: pipeline/tests/fixtures/live)

Example:
    cd pipeline && uv run python ../scripts/run-dashboard-local.py
    cd pipeline && uv run python ../scripts/run-dashboard-local.py --live-root /tmp/vps-data
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

# Ensure we're in pipeline/ for imports and Streamlit
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
PIPELINE_DIR = PROJECT_ROOT / "pipeline"
os.chdir(PIPELINE_DIR)

import polars as pl  # noqa: E402

from lantana.common.datalake import read_bronze_ndjson, write_gold_table, write_silver_partition  # noqa: E402
from lantana.common.redact import RedactionConfig, redact_infrastructure_ips  # noqa: E402
from lantana.models.normalize import normalize_dataset  # noqa: E402
from lantana.transform.metrics import (  # noqa: E402
    compute_behavioral_progression,
    compute_behavioral_progression_multiday,
    compute_campaign_clusters,
    compute_daily_summary,
    compute_detection_findings,
    compute_geographic_summary,
    compute_ip_reputation,
)

REDACT_CONFIG = RedactionConfig(
    infrastructure_ips=["10.50.99.1", "10.50.99.10", "10.50.99.100"],
    infrastructure_cidrs=["10.50.99.0/24"],
    pseudonym_map={
        "10.50.99.1": "honeypot-wan",
        "10.50.99.10": "honeypot-collector",
        "10.50.99.100": "honeypot-sensor-01",
    },
)

ENRICHMENT_STUBS: dict[str, pl.Expr] = {
    "abuseipdb_confidence_score": pl.lit(None).cast(pl.Int64),
    "greynoise_classification": pl.lit(None).cast(pl.Utf8),
    "greynoise_noise": pl.lit(None).cast(pl.Boolean),
    "geo.country_code": pl.lit(None).cast(pl.Utf8),
    "geo.asn": pl.lit(None).cast(pl.Utf8),
    "geo.isp": pl.lit(None).cast(pl.Utf8),
}

OPTIONAL_COLS: dict[str, pl.DataType] = {
    "session": pl.Utf8,
    "user_name": pl.Utf8,
    "unmapped_password": pl.Utf8,
    "actor_process_cmd_line": pl.Utf8,
    "finding_title": pl.Utf8,
    "finding_uid": pl.Utf8,
    "file_hash_sha256": pl.Utf8,
    "file_url": pl.Utf8,
    "file_path": pl.Utf8,
}


def discover_dates() -> list[date]:
    dates: set[date] = set()
    for d in BRONZE_ROOT.glob("dataset=*/date=*/"):
        if d.name.startswith("date="):
            try:
                dates.add(date.fromisoformat(d.name[5:]))
            except ValueError:
                continue
    return sorted(dates)


def build_gold(target_date: date) -> None:
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
        redacted = redact_infrastructure_ips(normalized, REDACT_CONFIG)

        stub_cols = [expr.alias(n) for n, expr in ENRICHMENT_STUBS.items() if n not in redacted.columns]
        if stub_cols:
            redacted = redacted.with_columns(stub_cols)
        opt_cols = [
            pl.lit(None).cast(dt).alias(n)
            for n, dt in OPTIONAL_COLS.items()
            if n not in redacted.columns
        ]
        if opt_cols:
            redacted = redacted.with_columns(opt_cols)

        server = (
            redacted.get_column("server").unique().to_list()[0]
            if "server" in redacted.columns
            else "unknown"
        )
        write_silver_partition(redacted, target_date, dataset, str(server), silver_root=SILVER_ROOT)

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

    multiday = compute_behavioral_progression_multiday([(target_date, silver)])
    if not multiday.is_empty():
        write_gold_table(multiday, "behavioral_progression_multiday", target_date, gold_root=GOLD_ROOT)
        print(f"    gold/behavioral_progression_multiday: {len(multiday):,} rows")


def main() -> None:
    global LIVE_ROOT, BRONZE_ROOT, SILVER_ROOT, GOLD_ROOT  # noqa: PLW0603

    parser = argparse.ArgumentParser(
        description="Build gold tables from live VPS data and launch Streamlit dashboard",
    )
    parser.add_argument(
        "--live-root",
        type=Path,
        default=Path("tests/fixtures/live"),
        help="Path to fetched VPS data (default: tests/fixtures/live)",
    )
    args = parser.parse_args()

    LIVE_ROOT = args.live_root
    BRONZE_ROOT = LIVE_ROOT / "datalake" / "bronze"
    SILVER_ROOT = LIVE_ROOT / "datalake" / "silver"
    GOLD_ROOT = LIVE_ROOT / "datalake" / "gold"

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
        build_gold(d)

    print()
    print("Launching Streamlit dashboard ...")
    print()

    env = {**os.environ, "LANTANA_GOLD_ROOT": str(GOLD_ROOT.resolve())}
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", "src/lantana/dashboard/app.py"],
        env=env,
    )


if __name__ == "__main__":
    main()

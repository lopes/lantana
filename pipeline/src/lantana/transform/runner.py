"""Gold aggregation runner — reads silver, computes metrics, writes gold.

Daily workflow:
1. Read all silver Parquet for the target date (cross-dataset)
2. Collect LazyFrame once into eager DataFrame
3. Compute 6 gold metric tables
4. Write each to gold layer
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    import polars as pl

from lantana.common.datalake import (
    GOLD_ROOT,
    SILVER_ROOT,
    read_silver_partition,
    write_gold_table,
)
from lantana.transform.metrics import (
    compute_behavioral_progression,
    compute_behavioral_progression_multiday,
    compute_campaign_clusters,
    compute_daily_summary,
    compute_detection_findings,
    compute_geographic_summary,
    compute_ip_reputation,
)

LOOKBACK_DAYS: int = 7

ERRORS_PATH = Path(
    os.environ.get("LANTANA_ENRICHMENT_ERRORS", "/var/lib/lantana/datalake/enrichment_errors.json")
)

logger = structlog.get_logger()


def _append_transform_failed_row(target_date: date, exc: BaseException, errors_path: Path) -> None:
    """Append a ``transform_failed`` row to the shared errors NDJSON.

    Mirrors the schema used by ``_write_error_summary`` in
    ``enrichment.runner`` so ``lantana-alert`` can read both error sources
    out of one file. Same severity rules apply downstream: this row gets
    classified as critical (gold for the date is missing).
    """
    try:
        errors_path.parent.mkdir(parents=True, exist_ok=True)
        with errors_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "date": target_date.isoformat(),
                "provider": "transform",
                "error_type": "transform_failed",
                "count": 1,
                "message": repr(exc),
                "timestamp": datetime.now(tz=UTC).isoformat(),
            }) + "\n")
    except OSError as write_exc:
        # If we can't even append the error row, log it — but don't mask the
        # original transform failure by raising a different exception.
        logger.error("transform_error_log_write_failed", exc_repr=repr(write_exc))


def run_transform(
    target_date: date,
    silver_root: Path = SILVER_ROOT,
    gold_root: Path = GOLD_ROOT,
) -> None:
    """Run the full transform pipeline for a given date."""
    logger.info("transform_start", date=target_date.isoformat())

    silver_lf = read_silver_partition(target_date, silver_root=silver_root)
    silver = silver_lf.collect()

    if silver.is_empty():
        logger.info("transform_skip_empty", date=target_date.isoformat())
        return

    logger.info("silver_loaded", rows=len(silver), columns=len(silver.columns))

    # Compute and write each gold table
    tables = [
        ("daily_summary", compute_daily_summary),
        ("ip_reputation", compute_ip_reputation),
        ("behavioral_progression", compute_behavioral_progression),
        ("campaign_clusters", compute_campaign_clusters),
        ("geographic_summary", compute_geographic_summary),
        ("detection_findings", compute_detection_findings),
    ]

    for table_name, compute_fn in tables:
        result = compute_fn(silver)
        if not result.is_empty():
            write_gold_table(result, table_name, target_date, gold_root=gold_root)
            logger.info("gold_written", table=table_name, rows=len(result))
        else:
            logger.info("gold_skip_empty", table=table_name)

    # Multi-day behavioral progression (lookback window)
    lookback_frames: list[tuple[date, pl.DataFrame]] = []
    for offset in range(LOOKBACK_DAYS):
        d = target_date - timedelta(days=offset)
        lf = read_silver_partition(d, silver_root=silver_root)
        day_df = lf.collect()
        if not day_df.is_empty():
            lookback_frames.append((d, day_df))

    if lookback_frames:
        multiday = compute_behavioral_progression_multiday(lookback_frames)
        if not multiday.is_empty():
            write_gold_table(
                multiday,
                "behavioral_progression_multiday",
                target_date,
                gold_root=gold_root,
            )
            logger.info("gold_written", table="behavioral_progression_multiday", rows=len(multiday))

    logger.info("transform_done", date=target_date.isoformat())


def main() -> None:
    """CLI entry point for lantana-transform.

    Wraps ``run_transform`` so any uncaught exception is recorded as a
    ``transform_failed`` row in the shared errors NDJSON before being
    re-raised. Without this, a transform crash exits silently (cron doesn't
    capture stderr by default), gold for the date never appears, and the
    operator only notices via a quiet dashboard — exactly the 2026-05-21
    02:00 UTC failure mode.
    """
    parser = argparse.ArgumentParser(
        prog="lantana-transform",
        description="Aggregate silver Parquet into gold tables for a given date.",
    )
    parser.add_argument(
        "--date",
        type=date.fromisoformat,
        default=None,
        metavar="YYYY-MM-DD",
        help="Date to transform (UTC). Defaults to yesterday.",
    )
    args = parser.parse_args()
    target = args.date if args.date is not None else date.today() - timedelta(days=1)
    try:
        run_transform(target)
    except Exception as exc:
        logger.error("transform_failed", date=target.isoformat(), exc_repr=repr(exc))
        _append_transform_failed_row(target, exc, ERRORS_PATH)
        raise

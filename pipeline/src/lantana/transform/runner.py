"""Gold aggregation runner — reads silver, computes metrics, writes gold.

Daily workflow:
1. Read all silver Parquet for the target date (cross-dataset)
2. Collect LazyFrame once into eager DataFrame
3. Compute 4 gold metric tables
4. Write each to gold layer
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path  # noqa: TC003 — used in function defaults
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
    compute_ip_reputation,
)

LOOKBACK_DAYS: int = 7

logger = structlog.get_logger()


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
    """CLI entry point for lantana-transform."""
    yesterday = date.today() - timedelta(days=1)
    run_transform(yesterday)

"""Gold aggregation runner -- reads silver, computes metrics, writes gold.

Daily workflow:
1. Read all silver Parquet for the target date (cross-dataset)
2. Collect LazyFrame once into eager DataFrame
3. Compute 4 gold metric tables
4. Write each to gold layer
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path  # noqa: TC003 -- used in function defaults

import structlog

from lantana.common.datalake import (
    GOLD_ROOT,
    SILVER_ROOT,
    read_silver_partition,
    write_gold_table,
)
from lantana.transform.metrics import (
    compute_behavioral_progression,
    compute_campaign_clusters,
    compute_daily_summary,
    compute_ip_reputation,
)

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

    logger.info("transform_done", date=target_date.isoformat())


def main() -> None:
    """CLI entry point for lantana-transform."""
    yesterday = date.today() - timedelta(days=1)
    run_transform(yesterday)

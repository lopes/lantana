"""Functions for reading/writing the partitioned datalake."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import polars as pl

BRONZE_ROOT: Path = Path("/var/lib/lantana/datalake/bronze")
SILVER_ROOT: Path = Path("/var/lib/lantana/datalake/silver")
GOLD_ROOT: Path = Path("/var/lib/lantana/datalake/gold")


def read_bronze_ndjson(
    target_date: date,
    dataset: str | None = None,
    bronze_root: Path = BRONZE_ROOT,
) -> pl.DataFrame:
    """Read bronze-layer NDJSON files for a given date and optional dataset.

    Bronze files are newline-delimited JSON written by Vector.
    Returns a DataFrame with all events for the day.
    """
    date_str = target_date.isoformat()
    pattern = f"dataset={dataset}" if dataset else "dataset=*"
    glob_path = bronze_root / pattern / f"date={date_str}" / "server=*" / "events.json"

    matching_files = list(bronze_root.glob(
        f"{pattern}/date={date_str}/server=*/events.json"
    ))

    if not matching_files:
        return pl.DataFrame()

    frames: list[pl.DataFrame] = []
    for file_path in matching_files:
        # Extract partition values from path
        parts = file_path.parts
        ds = _extract_partition_value(parts, "dataset")
        server = _extract_partition_value(parts, "server")

        # Read NDJSON line by line
        lines = file_path.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            continue

        records = [json.loads(line) for line in lines]
        df = pl.DataFrame(records)

        # Add partition columns if not already present
        if "dataset" not in df.columns:
            df = df.with_columns(pl.lit(ds).alias("dataset"))
        if "server" not in df.columns:
            df = df.with_columns(pl.lit(server).alias("server"))

        frames.append(df)

    if not frames:
        return pl.DataFrame()

    return pl.concat(frames, how="diagonal")


def read_silver_partition(
    target_date: date,
    dataset: str | None = None,
    silver_root: Path = SILVER_ROOT,
) -> pl.LazyFrame:
    """Read silver-layer Parquet files for a given date and optional dataset."""
    date_str = target_date.isoformat()
    pattern = f"dataset={dataset}" if dataset else "dataset=*"

    matching_files = list(silver_root.glob(
        f"{pattern}/date={date_str}/server=*/events.parquet"
    ))

    if not matching_files:
        return pl.LazyFrame()

    return pl.scan_parquet(
        matching_files,
        hive_partitioning=False,  # We handle partition columns explicitly
    )


def write_silver_partition(
    df: pl.DataFrame,
    target_date: date,
    dataset: str,
    server: str,
    silver_root: Path = SILVER_ROOT,
) -> Path:
    """Write a DataFrame to the silver layer as Parquet."""
    date_str = target_date.isoformat()
    output_dir = silver_root / f"dataset={dataset}" / f"date={date_str}" / f"server={server}"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "events.parquet"
    df.write_parquet(output_path)
    return output_path


def write_gold_table(
    df: pl.DataFrame,
    table_name: str,
    target_date: date,
    gold_root: Path = GOLD_ROOT,
) -> Path:
    """Write a DataFrame to the gold layer as a named table."""
    date_str = target_date.isoformat()
    output_dir = gold_root / table_name / f"date={date_str}"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "summary.parquet"
    df.write_parquet(output_path)
    return output_path


def _extract_partition_value(parts: tuple[str, ...], key: str) -> str:
    """Extract a Hive partition value from path components."""
    prefix = f"{key}="
    for part in parts:
        if part.startswith(prefix):
            return part[len(prefix):]
    return ""

"""Functions for reading/writing the partitioned datalake."""

from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path

import polars as pl

BRONZE_ROOT: Path = Path(os.environ.get("LANTANA_BRONZE_ROOT", "/var/lib/lantana/datalake/bronze"))
SILVER_ROOT: Path = Path(os.environ.get("LANTANA_SILVER_ROOT", "/var/lib/lantana/datalake/silver"))
GOLD_ROOT: Path = Path(os.environ.get("LANTANA_GOLD_ROOT", "/var/lib/lantana/datalake/gold"))


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

        # Real honeypot logs have mixed-type fields (e.g., a field is a
        # string in some events but an empty list in others).  Coerce
        # list/dict values to JSON strings so Polars gets a uniform schema.
        for rec in records:
            for k, v in rec.items():
                if isinstance(v, (list, dict)):
                    rec[k] = json.dumps(v)

        df = pl.DataFrame(records, infer_schema_length=None)

        # Ensure timestamp is Datetime (raw logs store it as string).
        # Cowrie uses "Z" suffix, Suricata uses "+0000". Strip both
        # and parse as naive datetime (all events are UTC).
        if "timestamp" in df.columns and df.schema["timestamp"] == pl.Utf8:
            ts = (
                df.get_column("timestamp")
                .str.replace(r"[+-]\d{4}$", "")
                .str.replace(r"Z$", "")
                .str.to_datetime(strict=False)
            )
            df = df.with_columns(ts.alias("timestamp"))

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


def read_gold_table(
    table_name: str,
    target_date: date,
    gold_root: Path = GOLD_ROOT,
) -> pl.DataFrame:
    """Read a gold-layer Parquet table for a given date."""
    date_str = target_date.isoformat()
    path = gold_root / table_name / f"date={date_str}" / "summary.parquet"
    if not path.exists():
        return pl.DataFrame()
    return pl.read_parquet(path)


def list_gold_dates(
    table_name: str,
    gold_root: Path = GOLD_ROOT,
) -> list[date]:
    """List available dates for a gold table, sorted descending (newest first)."""
    table_dir = gold_root / table_name
    if not table_dir.exists():
        return []
    dates: list[date] = []
    for entry in table_dir.iterdir():
        if entry.is_dir() and entry.name.startswith("date="):
            date_str = entry.name[5:]  # strip "date="
            dates.append(date.fromisoformat(date_str))
    return sorted(dates, reverse=True)


def _extract_partition_value(parts: tuple[str, ...], key: str) -> str:
    """Extract a Hive partition value from path components."""
    prefix = f"{key}="
    for part in parts:
        if part.startswith(prefix):
            return part[len(prefix):]
    return ""

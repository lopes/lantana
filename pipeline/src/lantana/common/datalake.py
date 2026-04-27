"""Functions for reading/writing the partitioned Parquet datalake."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import polars as pl

BRONZE_ROOT: Path = Path("/var/lib/lantana/datalake/bronze")
SILVER_ROOT: Path = Path("/var/lib/lantana/datalake/silver")
GOLD_ROOT: Path = Path("/var/lib/lantana/datalake/gold")


def read_bronze_partition(date: date, dataset: str | None = None) -> pl.LazyFrame:
    """Read bronze-layer Parquet files for a given date and optional dataset filter."""
    raise NotImplementedError("TODO")


def read_silver_partition(date: date, dataset: str | None = None) -> pl.LazyFrame:
    """Read silver-layer Parquet files for a given date and optional dataset filter."""
    raise NotImplementedError("TODO")


def write_silver_partition(
    df: pl.DataFrame, date: date, dataset: str, server: str
) -> Path:
    """Write a DataFrame to the silver layer, returning the output path."""
    raise NotImplementedError("TODO")


def write_gold_table(df: pl.DataFrame, table_name: str, date: date) -> Path:
    """Write a DataFrame to the gold layer as a named table, returning the output path."""
    raise NotImplementedError("TODO")

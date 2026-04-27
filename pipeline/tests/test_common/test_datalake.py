"""Tests for lantana.common.datalake."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import polars as pl
import pytest

from lantana.common.datalake import (
    read_bronze_ndjson,
    read_silver_partition,
    write_gold_table,
    write_silver_partition,
)


@pytest.fixture()
def bronze_with_data(tmp_path: Path) -> Path:
    """Create a bronze partition with sample NDJSON data."""
    bronze_dir = tmp_path / "dataset=cowrie" / "date=2026-04-25" / "server=sn-01"
    bronze_dir.mkdir(parents=True)
    events = [
        {"src_ip": "203.0.113.50", "dst_ip": "10.50.99.100", "eventid": "cowrie.login.success"},
        {"src_ip": "198.51.100.22", "dst_ip": "10.50.99.100", "eventid": "cowrie.login.failed"},
    ]
    (bronze_dir / "events.json").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def test_read_bronze_ndjson_returns_dataframe(bronze_with_data: Path) -> None:
    """Bronze reader returns a DataFrame with correct row count."""
    df = read_bronze_ndjson(date(2026, 4, 25), dataset="cowrie", bronze_root=bronze_with_data)
    assert len(df) == 2
    assert "src_ip" in df.columns
    assert "dataset" in df.columns


def test_read_bronze_ndjson_empty_for_missing_date(tmp_path: Path) -> None:
    """Bronze reader returns empty DataFrame for dates with no data."""
    df = read_bronze_ndjson(date(2099, 1, 1), bronze_root=tmp_path)
    assert df.is_empty()


def test_read_bronze_ndjson_adds_partition_columns(bronze_with_data: Path) -> None:
    """Bronze reader adds dataset and server columns from path."""
    df = read_bronze_ndjson(date(2026, 4, 25), dataset="cowrie", bronze_root=bronze_with_data)
    assert df.get_column("dataset").to_list() == ["cowrie", "cowrie"]
    assert df.get_column("server").to_list() == ["sn-01", "sn-01"]


def test_write_and_read_silver_roundtrip(tmp_path: Path) -> None:
    """Write to silver, read back, verify data matches."""
    df = pl.DataFrame({
        "src_ip": ["203.0.113.50"],
        "dst_ip": ["honeypot-wan"],
        "event": ["scan"],
    })
    path = write_silver_partition(df, date(2026, 4, 25), "cowrie", "sn-01", silver_root=tmp_path)
    assert path.exists()

    result = read_silver_partition(date(2026, 4, 25), dataset="cowrie", silver_root=tmp_path)
    collected = result.collect()
    assert len(collected) == 1
    assert collected.get_column("src_ip").to_list() == ["203.0.113.50"]


def test_write_gold_table_creates_parquet(tmp_path: Path) -> None:
    """Gold writer creates a Parquet file at the expected path."""
    df = pl.DataFrame({
        "metric": ["unique_ips"],
        "value": [47],
    })
    path = write_gold_table(df, "daily_summary", date(2026, 4, 25), gold_root=tmp_path)
    assert path.exists()
    assert "daily_summary" in str(path)
    assert "date=2026-04-25" in str(path)

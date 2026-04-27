"""Integration tests for the gold aggregation runner."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path  # noqa: TC003 -- used in function signatures

import polars as pl

from lantana.common.datalake import write_silver_partition
from lantana.models.ocsf import (
    CLASS_AUTHENTICATION,
    CLASS_NETWORK_ACTIVITY,
    STATUS_SUCCESS,
    STATUS_UNKNOWN,
)
from lantana.transform.runner import run_transform


def _ts(minute: int = 0) -> datetime:
    return datetime(2026, 4, 25, 10, minute, 0, tzinfo=UTC)


def _write_test_silver(datalake_root: Path, target_date: date) -> None:
    """Write a small silver Parquet with events from two datasets."""
    silver_root = datalake_root / "silver"
    rows: list[dict[str, object]] = [
        {
            "class_uid": CLASS_AUTHENTICATION,
            "category_uid": 3,
            "severity_id": 3,
            "activity_id": 1,
            "type_uid": 300201,
            "time": _ts(0),
            "message": "login attempt",
            "status_id": STATUS_SUCCESS,
            "src_endpoint_ip": "203.0.113.50",
            "src_endpoint_port": 54321,
            "dst_endpoint_ip": "honeypot-sensor-01",
            "dst_endpoint_port": 2222,
            "dataset": "cowrie",
            "server": "sensor-01",
            "operation": "op_test",
            "session": "sess-1",
            "user_name": "root",
            "unmapped_password": "admin",
            "actor_process_cmd_line": None,
            "finding_title": None,
            "finding_uid": None,
            "geo.country_code": "CN",
            "geo.asn": "4134",
            "geo.isp": "ChinaNet",
            "abuseipdb_confidence_score": 85,
            "greynoise_classification": "malicious",
            "greynoise_noise": True,
        },
        {
            "class_uid": CLASS_NETWORK_ACTIVITY,
            "category_uid": 4,
            "severity_id": 1,
            "activity_id": 5,
            "type_uid": 400105,
            "time": _ts(1),
            "message": "drop input",
            "status_id": STATUS_UNKNOWN,
            "src_endpoint_ip": "198.51.100.22",
            "src_endpoint_port": 12345,
            "dst_endpoint_ip": "honeypot-sensor-01",
            "dst_endpoint_port": 23,
            "dataset": "nftables",
            "server": "sensor-01",
            "operation": "op_test",
            "session": None,
            "user_name": None,
            "unmapped_password": None,
            "actor_process_cmd_line": None,
            "finding_title": None,
            "finding_uid": None,
            "geo.country_code": "RU",
            "geo.asn": "12389",
            "geo.isp": "Rostelecom",
            "abuseipdb_confidence_score": 10,
            "greynoise_classification": "benign",
            "greynoise_noise": False,
        },
    ]
    df = pl.DataFrame(rows)
    write_silver_partition(df, target_date, "cowrie", "sensor-01", silver_root=silver_root)


def test_run_transform_writes_gold_tables(tmp_datalake: Path) -> None:
    """Runner reads silver, computes metrics, writes gold Parquet files."""
    target_date = date(2026, 4, 25)
    _write_test_silver(tmp_datalake, target_date)

    silver_root = tmp_datalake / "silver"
    gold_root = tmp_datalake / "gold"

    run_transform(target_date, silver_root=silver_root, gold_root=gold_root)

    # Verify gold tables were written
    date_str = target_date.isoformat()
    for table_name in ("daily_summary", "ip_reputation", "behavioral_progression"):
        path = gold_root / table_name / f"date={date_str}" / "summary.parquet"
        assert path.exists(), f"Gold table {table_name} not written"
        gold_df = pl.read_parquet(path)
        assert not gold_df.is_empty(), f"Gold table {table_name} is empty"


def test_run_transform_empty_silver(tmp_datalake: Path) -> None:
    """Runner handles missing silver data gracefully."""
    silver_root = tmp_datalake / "silver"
    gold_root = tmp_datalake / "gold"

    # No silver written -- should not crash
    run_transform(date(2026, 4, 25), silver_root=silver_root, gold_root=gold_root)

    # Gold directory should be empty
    assert not list(gold_root.iterdir())

"""Tests for lantana-prune: datalake-only retention and non-root usable disk monitoring."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path  # noqa: TC003 - used at runtime in tmp_path fixtures
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from lantana import prune as prune_mod
from lantana.prune import (
    BRONZE_RETENTION_DAYS,
    EMERGENCY_BRONZE_RETENTION_DAYS,
    SILVER_GOLD_RETENTION_DAYS,
    _cleanup_empty_dirs,
    _prune_bronze_partitions,
    _prune_date_partitions,
    _prune_enrichment_errors,
    check_disk_usage,
    main,
    run_prune,
)


def _create_date_partition(
    root: Path,
    ds: str,
    d: date,
    *,
    filename: str = "events.parquet",
    payload: bytes = b"dummy",
) -> Path:
    """Create a datalake date partition directory with a dummy file."""
    partition = root / f"dataset={ds}" / f"date={d.isoformat()}" / "server=sn-01"
    partition.mkdir(parents=True, exist_ok=True)
    (partition / filename).write_bytes(payload)
    return partition


class TestRetentionConstants:
    def test_v151_datalake_only_contract(self) -> None:
        assert BRONZE_RETENTION_DAYS == 14
        assert SILVER_GOLD_RETENTION_DAYS == 180
        assert EMERGENCY_BRONZE_RETENTION_DAYS == 3
        # Strict one-way isolation: nectar prune must not reference sensor dirs
        assert not hasattr(prune_mod, "DEFAULT_SENSOR_DIR")
        assert not hasattr(prune_mod, "DEFAULT_SENSOR_SUBDIRS")
        assert not hasattr(prune_mod, "_prune_old_files")


class TestPruneDatePartitions:
    def test_deletes_old_partitions(self, tmp_path: Path) -> None:
        old_date = datetime.now(UTC).date() - timedelta(days=200)
        recent_date = datetime.now(UTC).date() - timedelta(days=10)
        _create_date_partition(tmp_path, "cowrie", old_date)
        _create_date_partition(tmp_path, "cowrie", recent_date)

        cutoff = datetime.now(UTC).date() - timedelta(days=180)
        deleted = _prune_date_partitions(tmp_path, cutoff)

        assert deleted == 1
        assert not (tmp_path / f"dataset=cowrie/date={old_date.isoformat()}").exists()
        assert (tmp_path / f"dataset=cowrie/date={recent_date.isoformat()}").exists()

    def test_handles_missing_root(self, tmp_path: Path) -> None:
        assert _prune_date_partitions(tmp_path / "nonexistent", datetime.now(UTC).date()) == 0

    def test_handles_invalid_date_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "date=not-a-date").mkdir(parents=True)
        deleted = _prune_date_partitions(tmp_path, datetime.now(UTC).date())
        assert deleted == 0


class TestPruneBronzeVerifiedGate:
    def test_prunes_bronze_only_when_silver_verified_non_empty(self, tmp_path: Path) -> None:
        bronze = tmp_path / "bronze"
        silver = tmp_path / "silver"
        old = datetime.now(UTC).date() - timedelta(days=20)
        recent = datetime.now(UTC).date() - timedelta(days=5)

        _create_date_partition(bronze, "cowrie", old, filename="events.json", payload=b"{}\n")
        _create_date_partition(silver, "cowrie", old, filename="events.parquet", payload=b"PAR1")

        _create_date_partition(bronze, "suricata", old, filename="events.json", payload=b"{}\n")

        _create_date_partition(bronze, "dionaea", old, filename="events.json", payload=b"{}\n")
        _create_date_partition(silver, "dionaea", old, filename="events.parquet", payload=b"")

        _create_date_partition(bronze, "nftables", recent, filename="events.json", payload=b"{}\n")
        _create_date_partition(
            silver, "nftables", recent, filename="events.parquet", payload=b"PAR1"
        )

        cutoff = datetime.now(UTC).date() - timedelta(days=14)
        deleted = _prune_bronze_partitions(bronze, silver, cutoff)

        assert deleted == 1
        assert not (bronze / f"dataset=cowrie/date={old.isoformat()}").exists()
        assert (bronze / f"dataset=suricata/date={old.isoformat()}").exists()
        assert (bronze / f"dataset=dionaea/date={old.isoformat()}").exists()
        assert (bronze / f"dataset=nftables/date={recent.isoformat()}").exists()


class TestCleanupEmptyDirs:
    def test_removes_empty_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "a" / "b" / "c").mkdir(parents=True)
        removed = _cleanup_empty_dirs(tmp_path)
        assert removed >= 1
        assert not (tmp_path / "a" / "b" / "c").exists()

    def test_preserves_non_empty_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "keep").mkdir()
        (tmp_path / "keep" / "file.txt").write_text("data")
        _cleanup_empty_dirs(tmp_path)
        assert (tmp_path / "keep" / "file.txt").exists()


class TestRunPrune:
    def test_decoupled_bronze_and_silver_retention(self, tmp_path: Path) -> None:
        """Bronze prunes at 14d (verified Silver gate); Silver & Gold stay until 180d."""
        lake = tmp_path / "lake"
        d20 = datetime.now(UTC).date() - timedelta(days=20)
        d200 = datetime.now(UTC).date() - timedelta(days=200)

        _create_date_partition(
            lake / "bronze", "cowrie", d20, filename="events.json", payload=b"{}"
        )
        _create_date_partition(lake / "silver", "cowrie", d20, filename="events.parquet")
        _create_date_partition(lake / "silver", "cowrie", d200, filename="events.parquet")

        deleted = run_prune(lake)
        assert deleted == 2
        assert not (lake / "bronze" / f"dataset=cowrie/date={d20.isoformat()}").exists()
        assert (lake / "silver" / f"dataset=cowrie/date={d20.isoformat()}").exists()
        assert not (lake / "silver" / f"dataset=cowrie/date={d200.isoformat()}").exists()

    def test_dry_run_deletes_nothing(self, tmp_path: Path) -> None:
        lake = tmp_path / "lake"
        d20 = datetime.now(UTC).date() - timedelta(days=20)
        _create_date_partition(
            lake / "bronze", "cowrie", d20, filename="events.json", payload=b"{}"
        )
        _create_date_partition(lake / "silver", "cowrie", d20, filename="events.parquet")

        would_delete = run_prune(lake, dry_run=True)
        assert would_delete == 1
        assert (lake / "bronze" / f"dataset=cowrie/date={d20.isoformat()}").exists()


class TestPruneEnrichmentErrors:
    def test_trims_old_error_entries_atomically(self, tmp_path: Path) -> None:
        errors_path = tmp_path / "enrichment_errors.json"
        old_d = (datetime.now(UTC).date() - timedelta(days=200)).isoformat()
        recent_d = (datetime.now(UTC).date() - timedelta(days=5)).isoformat()
        errors_path.write_text(
            "\n".join(
                [
                    json.dumps({"date": old_d, "error_type": "rate_limit"}),
                    "not-json-line",
                    json.dumps({"date": recent_d, "error_type": "timeout"}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        removed = _prune_enrichment_errors(
            errors_path, datetime.now(UTC).date() - timedelta(days=180)
        )
        assert removed == 1
        remaining = [json.loads(line) for line in errors_path.read_text().splitlines() if line]
        assert len(remaining) == 1
        assert remaining[0]["date"] == recent_d


class TestCheckDiskUsage:
    def test_returns_percentage(self, tmp_path: Path) -> None:
        usage = check_disk_usage(tmp_path)
        assert 0.0 <= usage <= 100.0

    def test_statvfs_reports_100_percent_when_non_root_bavail_is_zero(self, tmp_path: Path) -> None:
        fake_stat = SimpleNamespace(f_blocks=1000, f_bfree=50, f_bavail=0)
        with patch("lantana.prune.os.statvfs", return_value=fake_stat):
            assert check_disk_usage(tmp_path) == 100.0


class TestEmergencyAlertDecoupling:
    def test_disk_critical_alert_fires_and_steps_down_verified_bronze(self, tmp_path: Path) -> None:
        lake = tmp_path / "lake"
        d5 = datetime.now(UTC).date() - timedelta(days=5)
        _create_date_partition(lake / "bronze", "cowrie", d5, filename="events.json", payload=b"{}")
        _create_date_partition(lake / "silver", "cowrie", d5, filename="events.parquet")

        fake_secrets = SimpleNamespace(discord_webhook="https://discord.example/hook")
        mock_send = AsyncMock()

        with (
            patch("lantana.prune.DEFAULT_LAKE_DIR", lake),
            patch("lantana.prune.check_disk_usage", side_effect=[85.0, 72.0]),
            patch("lantana.common.config.load_secrets", return_value=fake_secrets),
            patch("lantana.notify.discord.send_notification", mock_send),
        ):
            main([])

        assert not (lake / "bronze" / f"dataset=cowrie/date={d5.isoformat()}").exists()
        mock_send.assert_awaited_once()
        assert mock_send.await_args is not None
        kwargs = mock_send.await_args.kwargs
        assert kwargs["level"] == "critical"
        assert "Disk Critical" in kwargs["title"]

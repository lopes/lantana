"""Tests for lantana-prune: datalake retention, symlink-safe sensor prune, and disk monitoring."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path  # noqa: TC003 - used at runtime in tmp_path fixtures
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from lantana.prune import (
    BRONZE_RETENTION_DAYS,
    EMERGENCY_BRONZE_RETENTION_DAYS,
    SENSOR_RETENTION_DAYS,
    SILVER_GOLD_RETENTION_DAYS,
    _cleanup_empty_dirs,
    _prune_bronze_partitions,
    _prune_date_partitions,
    _prune_enrichment_errors,
    _prune_old_files,
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


def _create_old_file(root: Path, subpath: str, age_days: int) -> Path:
    """Create a file with mtime set to age_days ago."""
    path = root / subpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"artifact")
    old_time = time.time() - (age_days * 86400)
    os.utime(path, (old_time, old_time))
    return path


class TestRetentionConstants:
    def test_v15_retention_defaults(self) -> None:
        assert BRONZE_RETENTION_DAYS == 14
        assert SENSOR_RETENTION_DAYS == 14
        assert SILVER_GOLD_RETENTION_DAYS == 180
        assert EMERGENCY_BRONZE_RETENTION_DAYS == 3


class TestPruneDatePartitions:
    def test_deletes_old_partitions(self, tmp_path: Path) -> None:
        """Partitions older than cutoff are deleted."""
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
        """Missing root returns 0 deleted."""
        assert _prune_date_partitions(tmp_path / "nonexistent", datetime.now(UTC).date()) == 0

    def test_handles_invalid_date_dirs(self, tmp_path: Path) -> None:
        """Directories with invalid date names are skipped."""
        (tmp_path / "date=not-a-date").mkdir(parents=True)
        deleted = _prune_date_partitions(tmp_path, datetime.now(UTC).date())
        assert deleted == 0


class TestPruneBronzeVerifiedGate:
    def test_prunes_bronze_only_when_silver_verified_non_empty(self, tmp_path: Path) -> None:
        bronze = tmp_path / "bronze"
        silver = tmp_path / "silver"
        old = datetime.now(UTC).date() - timedelta(days=20)
        recent = datetime.now(UTC).date() - timedelta(days=5)

        # cowrie old: has valid non-empty silver -> MUST prune
        _create_date_partition(bronze, "cowrie", old, filename="events.json", payload=b"{}\n")
        _create_date_partition(silver, "cowrie", old, filename="events.parquet", payload=b"PAR1")

        # suricata old: NO silver -> MUST preserve
        _create_date_partition(bronze, "suricata", old, filename="events.json", payload=b"{}\n")

        # dionaea old: empty 0-byte silver -> MUST preserve
        _create_date_partition(bronze, "dionaea", old, filename="events.json", payload=b"{}\n")
        _create_date_partition(silver, "dionaea", old, filename="events.parquet", payload=b"")

        # nftables recent: within 14d -> MUST preserve even with silver
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


class TestPruneOldFilesSymlinkSafe:
    def test_deletes_old_artifacts_across_cowrie_and_dionaea(self, tmp_path: Path) -> None:
        """Deletes old files across Cowrie and Dionaea scratch trees including nested bistreams."""
        _create_old_file(tmp_path, "cowrie/downloads/malware.bin", 20)
        _create_old_file(tmp_path, "cowrie/downloads/recent.bin", 5)
        _create_old_file(tmp_path, "cowrie/tty/session.log", 20)
        _create_old_file(tmp_path, "dionaea/binaries/abc123", 20)
        _create_old_file(tmp_path, "dionaea/bistreams/2026-06-11/smb-1", 20)
        _create_old_file(tmp_path, "dionaea/tmp/scratch.tmp", 20)
        _create_old_file(tmp_path, "cowrie/keys/ssh_host_key", 200)

        cutoff = datetime.now(UTC).date() - timedelta(days=14)
        deleted = _prune_old_files(
            tmp_path,
            cutoff,
            [
                "cowrie/downloads",
                "cowrie/tty",
                "dionaea/binaries",
                "dionaea/bistreams",
                "dionaea/tmp",
            ],
        )

        assert deleted == 5
        assert not (tmp_path / "cowrie/downloads/malware.bin").exists()
        assert (tmp_path / "cowrie/downloads/recent.bin").exists()
        assert not (tmp_path / "cowrie/tty/session.log").exists()
        assert not (tmp_path / "dionaea/binaries/abc123").exists()
        assert not (tmp_path / "dionaea/bistreams/2026-06-11/smb-1").exists()
        assert not (tmp_path / "dionaea/tmp/scratch.tmp").exists()
        assert (tmp_path / "cowrie/keys/ssh_host_key").exists()

    def test_never_follows_symlinks_into_external_targets(self, tmp_path: Path) -> None:
        """Compromised stigma planting symlinks cannot trick nectar into deleting datalake."""
        sensor = tmp_path / "sensor"
        datalake = tmp_path / "datalake"
        canary_dir = datalake / "gold" / "daily_summary"
        canary_file = _create_old_file(canary_dir, "summary.parquet", 200)
        direct_canary = _create_old_file(datalake, "keep.parquet", 200)

        downloads = sensor / "cowrie" / "downloads"
        downloads.mkdir(parents=True)
        (downloads / "evil_dir_link").symlink_to(canary_dir)
        (downloads / "evil_file_link").symlink_to(direct_canary)

        cutoff = datetime.now(UTC).date() - timedelta(days=14)
        _prune_old_files(sensor, cutoff, ["cowrie/downloads"])

        assert canary_file.exists()
        assert direct_canary.exists()


class TestCleanupEmptyDirs:
    def test_removes_empty_dirs(self, tmp_path: Path) -> None:
        """Empty directories are removed."""
        (tmp_path / "a" / "b" / "c").mkdir(parents=True)
        removed = _cleanup_empty_dirs(tmp_path)
        assert removed >= 1
        assert not (tmp_path / "a" / "b" / "c").exists()

    def test_preserves_non_empty_dirs(self, tmp_path: Path) -> None:
        """Directories with files are preserved."""
        (tmp_path / "keep").mkdir()
        (tmp_path / "keep" / "file.txt").write_text("data")
        _cleanup_empty_dirs(tmp_path)
        assert (tmp_path / "keep" / "file.txt").exists()


class TestRunPrune:
    def test_decoupled_bronze_silver_and_sensor_retention(self, tmp_path: Path) -> None:
        """Bronze & sensor scratch prune at 14d; Silver & Gold stay until 180d."""
        lake = tmp_path / "lake"
        sensor = tmp_path / "sensor"
        d20 = datetime.now(UTC).date() - timedelta(days=20)
        d200 = datetime.now(UTC).date() - timedelta(days=200)

        _create_date_partition(
            lake / "bronze", "cowrie", d20, filename="events.json", payload=b"{}"
        )
        _create_date_partition(lake / "silver", "cowrie", d20, filename="events.parquet")
        _create_date_partition(lake / "silver", "cowrie", d200, filename="events.parquet")
        _create_old_file(sensor, "cowrie/downloads/old.bin", 20)
        _create_old_file(sensor, "dionaea/binaries/old.exe", 20)

        deleted = run_prune(lake, sensor)
        assert deleted >= 4
        assert not (lake / "bronze" / f"dataset=cowrie/date={d20.isoformat()}").exists()
        assert (lake / "silver" / f"dataset=cowrie/date={d20.isoformat()}").exists()
        assert not (lake / "silver" / f"dataset=cowrie/date={d200.isoformat()}").exists()
        assert not (sensor / "cowrie/downloads/old.bin").exists()
        assert not (sensor / "dionaea/binaries/old.exe").exists()

    def test_does_not_rmdir_sensor_root_or_misc_dirs(self, tmp_path: Path) -> None:
        """Sensor root/misc directories are preserved."""
        lake = tmp_path / "lake"
        sensor = tmp_path / "sensor"
        (sensor / "cowrie" / "misc").mkdir(parents=True)
        (sensor / "cowrie" / "downloads").mkdir(parents=True)

        run_prune(lake, sensor)

        assert (sensor / "cowrie" / "misc").exists()
        assert (sensor / "cowrie" / "downloads").exists()

    def test_dry_run_deletes_nothing(self, tmp_path: Path) -> None:
        lake = tmp_path / "lake"
        sensor = tmp_path / "sensor"
        d20 = datetime.now(UTC).date() - timedelta(days=20)
        _create_date_partition(
            lake / "bronze", "cowrie", d20, filename="events.json", payload=b"{}"
        )
        _create_date_partition(lake / "silver", "cowrie", d20, filename="events.parquet")
        f = _create_old_file(sensor, "cowrie/downloads/old.bin", 20)

        would_delete = run_prune(lake, sensor, dry_run=True)
        assert would_delete == 2
        assert (lake / "bronze" / f"dataset=cowrie/date={d20.isoformat()}").exists()
        assert f.exists()


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
        """ext4 root-reserved blocks must not mask non-root ENOSPC as ~95%."""
        fake_stat = SimpleNamespace(f_blocks=1000, f_bfree=50, f_bavail=0)
        with patch("lantana.prune.os.statvfs", return_value=fake_stat):
            assert check_disk_usage(tmp_path) == 100.0


class TestEmergencyAlertDecoupling:
    def test_disk_critical_alert_still_fires_on_permission_error_and_steps_down_bronze(
        self, tmp_path: Path
    ) -> None:
        lake = tmp_path / "lake"
        sensor = tmp_path / "sensor"
        d5 = datetime.now(UTC).date() - timedelta(days=5)
        _create_date_partition(lake / "bronze", "cowrie", d5, filename="events.json", payload=b"{}")
        _create_date_partition(lake / "silver", "cowrie", d5, filename="events.parquet")
        _create_old_file(sensor, "cowrie/downloads/locked.bin", 10)

        fake_secrets = SimpleNamespace(discord_webhook="https://discord.example/hook")
        mock_send = AsyncMock()

        real_unlink = os.unlink

        def _selective_unlink(
            path: str | bytes | os.PathLike[str], *, dir_fd: int | None = None
        ) -> None:
            if str(path) == "locked.bin":
                raise PermissionError(13, "Permission denied")
            real_unlink(path, dir_fd=dir_fd)

        with (
            patch("lantana.prune.DEFAULT_LAKE_DIR", lake),
            patch("lantana.prune.DEFAULT_SENSOR_DIR", sensor),
            patch("lantana.prune.check_disk_usage", side_effect=[85.0, 72.0]),
            patch("lantana.common.config.load_secrets", return_value=fake_secrets),
            patch("lantana.notify.discord.send_notification", mock_send),
            patch("lantana.prune.os.unlink", side_effect=_selective_unlink),
        ):
            main([])

        # Emergency Bronze 3-day step-down reclaimed the 5-day-old verified partition
        assert not (lake / "bronze" / f"dataset=cowrie/date={d5.isoformat()}").exists()
        # Disk Critical webhook fired despite sensor unlink PermissionError
        mock_send.assert_awaited_once()
        assert mock_send.await_args is not None
        kwargs = mock_send.await_args.kwargs
        assert kwargs["level"] == "critical"
        assert "Disk Critical" in kwargs["title"]

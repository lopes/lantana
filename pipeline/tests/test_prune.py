"""Tests for lantana-prune: datalake retention and disk monitoring."""

from __future__ import annotations

import time
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

from lantana.prune import (
    _cleanup_empty_dirs,
    _prune_date_partitions,
    _prune_old_files,
    check_disk_usage,
    run_prune,
)


def _create_date_partition(root: Path, ds: str, d: date) -> Path:
    """Create a datalake date partition directory with a dummy file."""
    partition = root / f"dataset={ds}" / f"date={d.isoformat()}" / "server=sn-01"
    partition.mkdir(parents=True)
    (partition / "events.parquet").write_bytes(b"dummy")
    return partition


def _create_old_file(root: Path, subpath: str, age_days: int) -> Path:
    """Create a file with mtime set to age_days ago."""
    path = root / subpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"artifact")
    old_time = time.time() - (age_days * 86400)
    import os

    os.utime(path, (old_time, old_time))
    return path


class TestPruneDatePartitions:
    def test_deletes_old_partitions(self, tmp_path: Path) -> None:
        """Partitions older than cutoff are deleted."""
        old_date = date.today() - timedelta(days=200)
        recent_date = date.today() - timedelta(days=10)
        _create_date_partition(tmp_path, "cowrie", old_date)
        _create_date_partition(tmp_path, "cowrie", recent_date)

        cutoff = date.today() - timedelta(days=180)
        deleted = _prune_date_partitions(tmp_path, cutoff)

        assert deleted == 1
        # Old partition gone
        assert not (tmp_path / f"dataset=cowrie/date={old_date.isoformat()}").exists()
        # Recent partition preserved
        assert (tmp_path / f"dataset=cowrie/date={recent_date.isoformat()}").exists()

    def test_handles_missing_root(self, tmp_path: Path) -> None:
        """Missing root returns 0 deleted."""
        assert _prune_date_partitions(tmp_path / "nonexistent", date.today()) == 0

    def test_handles_invalid_date_dirs(self, tmp_path: Path) -> None:
        """Directories with invalid date names are skipped."""
        (tmp_path / "date=not-a-date").mkdir(parents=True)
        deleted = _prune_date_partitions(tmp_path, date.today())
        assert deleted == 0


class TestPruneOldFiles:
    def test_deletes_old_artifacts(self, tmp_path: Path) -> None:
        """Files older than cutoff matching patterns are deleted."""
        _create_old_file(tmp_path, "cowrie/downloads/malware.bin", 200)
        _create_old_file(tmp_path, "cowrie/downloads/recent.bin", 10)
        _create_old_file(tmp_path, "cowrie/tty/session.log", 200)

        cutoff = date.today() - timedelta(days=180)
        deleted = _prune_old_files(tmp_path, cutoff, ["downloads/*", "tty/*"])

        assert deleted == 2
        assert not (tmp_path / "cowrie/downloads/malware.bin").exists()
        assert (tmp_path / "cowrie/downloads/recent.bin").exists()
        assert not (tmp_path / "cowrie/tty/session.log").exists()


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
    def test_full_prune(self, tmp_path: Path) -> None:
        """Full prune run deletes old partitions and artifacts."""
        lake = tmp_path / "lake"
        sensor = tmp_path / "sensor"

        old_date = date.today() - timedelta(days=200)
        _create_date_partition(lake, "cowrie", old_date)
        _create_date_partition(lake, "cowrie", date.today())
        _create_old_file(sensor, "cowrie/downloads/old.bin", 200)

        deleted = run_prune(lake, sensor, retention_days=180)
        assert deleted >= 2  # 1 partition + 1 file


class TestCheckDiskUsage:
    def test_returns_percentage(self, tmp_path: Path) -> None:
        """Disk usage returns a float between 0 and 100."""
        usage = check_disk_usage(tmp_path)
        assert 0.0 <= usage <= 100.0

"""Tests for the stigma-owned standalone sensor scratch pruner.

Exercises ``config/ansible/roles/profile_sensor_low/files/lantana-sensor-prune``.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "ansible"
    / "roles"
    / "profile_sensor_low"
    / "files"
    / "lantana-sensor-prune"
)


def _load_sensor_prune_module() -> ModuleType:
    prev = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader = importlib.machinery.SourceFileLoader("lantana_sensor_prune", str(SCRIPT_PATH))
        spec = importlib.util.spec_from_loader("lantana_sensor_prune", loader)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod
    finally:
        sys.dont_write_bytecode = prev


def _create_old_file(root: Path, subpath: str, age_days: int) -> Path:
    path = root / subpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"artifact")
    old_time = time.time() - (age_days * 86400)
    os.utime(path, (old_time, old_time))
    return path


class TestSensorPruneScript:
    def test_deletes_old_artifacts_and_preserves_recent_and_keys(self, tmp_path: Path) -> None:
        mod = _load_sensor_prune_module()
        _create_old_file(tmp_path, "cowrie/downloads/malware.bin", 20)
        _create_old_file(tmp_path, "cowrie/downloads/recent.bin", 5)
        _create_old_file(tmp_path, "cowrie/tty/session.log", 20)
        _create_old_file(tmp_path, "dionaea/binaries/abc123", 20)
        _create_old_file(tmp_path, "dionaea/bistreams/2026-06-11/smb-1", 20)
        _create_old_file(tmp_path, "dionaea/tmp/scratch.tmp", 20)
        _create_old_file(tmp_path, "cowrie/keys/ssh_host_key", 200)
        _create_old_file(tmp_path, "cowrie/misc/keep.txt", 200)
        _create_old_file(tmp_path, "dionaea/wwwroot/index.html", 200)

        deleted = mod.prune_sensor_tree(tmp_path, retention_days=14, dry_run=False)
        assert deleted == 5
        assert not (tmp_path / "cowrie/downloads/malware.bin").exists()
        assert (tmp_path / "cowrie/downloads/recent.bin").exists()
        assert not (tmp_path / "cowrie/tty/session.log").exists()
        assert not (tmp_path / "dionaea/binaries/abc123").exists()
        assert not (tmp_path / "dionaea/bistreams/2026-06-11/smb-1").exists()
        assert not (tmp_path / "dionaea/tmp/scratch.tmp").exists()
        assert (tmp_path / "cowrie/keys/ssh_host_key").exists()
        assert (tmp_path / "cowrie/misc/keep.txt").exists()
        assert (tmp_path / "dionaea/wwwroot/index.html").exists()

    def test_never_follows_symlinks_outside_sensor_tree(self, tmp_path: Path) -> None:
        mod = _load_sensor_prune_module()
        sensor = tmp_path / "sensor"
        outside_dir = tmp_path / "outside"
        canary_nested = _create_old_file(outside_dir, "keep_nested.bin", 200)
        canary_direct = _create_old_file(tmp_path, "keep_direct.bin", 200)

        downloads = sensor / "cowrie" / "downloads"
        downloads.mkdir(parents=True)
        (downloads / "evil_dir").symlink_to(outside_dir)
        (downloads / "evil_file").symlink_to(canary_direct)

        mod.prune_sensor_tree(sensor, retention_days=14, dry_run=False)
        assert canary_nested.exists()
        assert canary_direct.exists()

    def test_depth_capped_and_isolated_across_siblings(self, tmp_path: Path) -> None:
        mod = _load_sensor_prune_module()
        deep = tmp_path / "cowrie" / "downloads"
        for idx in range(45):
            deep = deep / f"d{idx}"
        deep.mkdir(parents=True)

        sibling = tmp_path / "dionaea" / "binaries"
        sibling.mkdir(parents=True)
        old_file = sibling / "old.bin"
        old_file.write_bytes(b"payload")
        old_ts = datetime(2025, 1, 1, tzinfo=UTC).timestamp()
        os.utime(old_file, (old_ts, old_ts))

        deleted = mod.prune_sensor_tree(tmp_path, retention_days=14, dry_run=False)
        assert deleted == 1
        assert not old_file.exists()

    def test_emergency_step_down_above_80_percent_usable_disk(self, tmp_path: Path) -> None:
        mod = _load_sensor_prune_module()
        five_days_old = _create_old_file(tmp_path, "cowrie/downloads/mid.bin", 5)
        one_day_old = _create_old_file(tmp_path, "cowrie/downloads/fresh.bin", 1)

        fake_stat = SimpleNamespace(f_blocks=1000, f_bfree=150, f_bavail=100)  # 89.5% used
        with patch.object(mod.os, "statvfs", return_value=fake_stat):
            rc = mod.main(["--sensor-dir", str(tmp_path)])

        assert rc == 0
        assert not five_days_old.exists()
        assert one_day_old.exists()

    def test_dry_run_deletes_nothing(self, tmp_path: Path) -> None:
        mod = _load_sensor_prune_module()
        old_file = _create_old_file(tmp_path, "dionaea/tmp/old.tmp", 20)

        deleted = mod.prune_sensor_tree(tmp_path, retention_days=14, dry_run=True)
        assert deleted == 1
        assert old_file.exists()

    def test_rejects_absolute_or_parent_traversal_subdirs(self, tmp_path: Path) -> None:
        mod = _load_sensor_prune_module()
        assert mod._open_relative_subdir_nofollow(tmp_path, "/etc") is None
        assert mod._open_relative_subdir_nofollow(tmp_path, "../outside") is None

"""Prune old datalake partitions and sensor artifacts based on retention policy.

Retention: 180 days for all datalake and artifact files.
Emergency prune at >80% disk: delete artifacts older than 14 days.
Disk warning at >70%: notify via Discord.
"""

from __future__ import annotations

import asyncio
import shutil
from datetime import date, timedelta
from pathlib import Path

import structlog

logger = structlog.get_logger()

DEFAULT_LAKE_DIR = Path("/var/lib/lantana/datalake")
DEFAULT_SENSOR_DIR = Path("/var/lib/lantana/sensor")
DEFAULT_RETENTION_DAYS = 180
EMERGENCY_RETENTION_DAYS = 14
DISK_WARNING_THRESHOLD = 70.0
DISK_CRITICAL_THRESHOLD = 80.0


def _cutoff_date(retention_days: int) -> date:
    """Compute the cutoff date: partitions older than this are pruned."""
    return date.today() - timedelta(days=retention_days)


def _prune_date_partitions(root: Path, cutoff: date) -> int:
    """Delete Hive-style date= directories older than cutoff.

    Walks all date=YYYY-MM-DD directories under root (at any depth)
    and removes those where the date is before the cutoff.
    Returns count of deleted directories.
    """
    deleted = 0
    if not root.exists():
        return deleted

    for date_dir in root.rglob("date=*"):
        if not date_dir.is_dir():
            continue
        date_str = date_dir.name[5:]  # strip "date="
        try:
            partition_date = date.fromisoformat(date_str)
        except ValueError:
            continue
        if partition_date < cutoff:
            shutil.rmtree(date_dir)
            deleted += 1
            logger.debug("pruned_partition", path=str(date_dir))

    return deleted


def _prune_old_files(root: Path, cutoff: date, patterns: list[str]) -> int:
    """Delete files matching glob patterns with mtime older than cutoff.

    Returns count of deleted files.
    """
    deleted = 0
    if not root.exists():
        return deleted

    cutoff_ts = cutoff.timetuple()
    import time

    cutoff_epoch = time.mktime(cutoff_ts)

    for pattern in patterns:
        for file_path in root.rglob(pattern):
            if file_path.is_file() and file_path.stat().st_mtime < cutoff_epoch:
                file_path.unlink()
                deleted += 1

    return deleted


def _cleanup_empty_dirs(root: Path) -> int:
    """Remove empty directories under root. Returns count removed."""
    removed = 0
    if not root.exists():
        return removed

    # Walk bottom-up so child dirs are removed before parents
    for dirpath in sorted(root.rglob("*"), reverse=True):
        if dirpath.is_dir() and not any(dirpath.iterdir()):
            dirpath.rmdir()
            removed += 1

    return removed


def run_prune(
    lake_dir: Path = DEFAULT_LAKE_DIR,
    sensor_dir: Path = DEFAULT_SENSOR_DIR,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> int:
    """Delete datalake partitions and sensor artifacts older than retention_days.

    Returns total count of deleted items (directories + files).
    """
    cutoff = _cutoff_date(retention_days)
    total = 0

    # Prune datalake date partitions
    total += _prune_date_partitions(lake_dir, cutoff)

    # Prune sensor artifacts (downloads, TTY recordings)
    total += _prune_old_files(sensor_dir, cutoff, ["downloads/*", "tty/*"])

    # Clean up empty directories
    _cleanup_empty_dirs(lake_dir)
    _cleanup_empty_dirs(sensor_dir)

    logger.info("prune_complete", deleted=total, retention_days=retention_days)
    return total


def check_disk_usage(path: Path) -> float:
    """Return disk usage percentage (0.0-100.0) for the filesystem containing path."""
    usage = shutil.disk_usage(path)
    return (usage.used / usage.total) * 100.0


def main() -> None:
    """CLI entry point for lantana-prune."""
    lake_dir = DEFAULT_LAKE_DIR
    sensor_dir = DEFAULT_SENSOR_DIR

    # Standard prune: 180-day retention
    deleted = run_prune(lake_dir, sensor_dir, DEFAULT_RETENTION_DAYS)
    logger.info("standard_prune_done", deleted=deleted)

    # Check disk usage
    if not lake_dir.exists():
        return

    usage = check_disk_usage(lake_dir)
    logger.info("disk_usage", percent=round(usage, 1))

    # Load webhook URL for notifications
    webhook_url: str | None = None
    try:
        from lantana.common.config import load_secrets

        secrets = load_secrets()
        webhook_url = secrets.discord_webhook or None
    except Exception:
        logger.debug("no_secrets_for_notify")

    if usage > DISK_CRITICAL_THRESHOLD:
        # Emergency prune: keep only 14 days of artifacts
        emergency_deleted = _prune_old_files(
            sensor_dir, _cutoff_date(EMERGENCY_RETENTION_DAYS), ["downloads/*", "tty/*"]
        )
        _cleanup_empty_dirs(sensor_dir)

        after_usage = check_disk_usage(lake_dir)
        logger.warning(
            "emergency_prune",
            before=round(usage, 1),
            after=round(after_usage, 1),
            deleted=emergency_deleted,
        )

        if webhook_url:
            from lantana.notify.discord import send_notification

            asyncio.run(send_notification(
                webhook_url=webhook_url,
                level="critical",
                title="Lantana: Disk Critical",
                message=(
                    f"Disk usage at {usage:.1f}%. Emergency prune executed.\n"
                    f"Deleted {emergency_deleted} artifacts "
                    f"(kept last {EMERGENCY_RETENTION_DAYS} days).\n"
                    f"Usage after prune: {after_usage:.1f}%."
                ),
            ))

    elif usage > DISK_WARNING_THRESHOLD:
        logger.warning("disk_warning", percent=round(usage, 1))

        if webhook_url:
            from lantana.notify.discord import send_notification

            asyncio.run(send_notification(
                webhook_url=webhook_url,
                level="warning",
                title="Lantana: Disk Warning",
                message=f"Disk usage at {usage:.1f}%. Threshold is {DISK_WARNING_THRESHOLD}%.",
            ))

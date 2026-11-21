"""Prune old datalake partitions and sensor artifacts based on retention policy.

Retention defaults (v1.5):
- Bronze NDJSON: 14 days (deleted ONLY after the corresponding Silver partition
  is verified non-empty).
- Silver & Gold Parquet: 180 days.
- Sensor scratch (cowrie downloads/tty, dionaea binaries/bistreams/tmp): 14 days
  via one-way POSIX ACLs (`u:nectar:rwX`) and symlink-safe `O_NOFOLLOW`/`dir_fd`
  traversal so a compromised `stigma` cannot redirect deletes outside sensor trees.
- Emergency prune (>80% non-root usable disk via `statvfs`): step down verified
  Bronze and sensor scratch to 3 days and always send Disk Critical alert even if
  individual deletions fail.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import stat
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import structlog

logger = structlog.get_logger()

DEFAULT_LAKE_DIR = Path("/var/lib/lantana/datalake")
DEFAULT_SENSOR_DIR = Path("/var/lib/lantana/sensor")
BRONZE_RETENTION_DAYS = 14
SILVER_GOLD_RETENTION_DAYS = 180
DEFAULT_RETENTION_DAYS = SILVER_GOLD_RETENTION_DAYS
SENSOR_RETENTION_DAYS = 14
EMERGENCY_BRONZE_RETENTION_DAYS = 3
EMERGENCY_SENSOR_RETENTION_DAYS = 3
EMERGENCY_RETENTION_DAYS = EMERGENCY_SENSOR_RETENTION_DAYS
ERRORS_RETENTION_DAYS = 180
DISK_WARNING_THRESHOLD = 70.0
DISK_CRITICAL_THRESHOLD = 80.0

DEFAULT_SENSOR_SUBDIRS: tuple[str, ...] = (
    "cowrie/downloads",
    "cowrie/tty",
    "dionaea/binaries",
    "dionaea/bistreams",
    "dionaea/tmp",
)


def _cutoff_date(retention_days: int) -> date:
    """Compute the UTC cutoff date: items older than this are pruned."""
    return datetime.now(UTC).date() - timedelta(days=retention_days)


def _cutoff_epoch_utc(cutoff: date) -> float:
    """Convert a UTC cutoff date to POSIX epoch seconds at 00:00:00 UTC."""
    return datetime(cutoff.year, cutoff.month, cutoff.day, tzinfo=UTC).timestamp()


def _silver_partition_verified(silver_root: Path, dataset: str, date_str: str) -> bool:
    """Return True iff Silver has at least one non-empty Parquet file for dataset/date."""
    silver_date_dir = silver_root / f"dataset={dataset}" / f"date={date_str}"
    if not silver_date_dir.is_dir():
        return False
    for parquet_path in silver_date_dir.glob("server=*/events.parquet"):
        try:
            if parquet_path.is_file() and parquet_path.stat().st_size > 0:
                return True
        except OSError:
            continue
    return False


def _prune_bronze_partitions(
    bronze_root: Path,
    silver_root: Path,
    cutoff: date,
    *,
    dry_run: bool = False,
) -> int:
    """Delete Bronze date= partitions older than cutoff ONLY when Silver is verified."""
    deleted = 0
    if not bronze_root.exists():
        return deleted

    for ds_dir in sorted(bronze_root.glob("dataset=*")):
        if not ds_dir.is_dir():
            continue
        dataset = ds_dir.name[len("dataset=") :]
        for date_dir in sorted(ds_dir.glob("date=*")):
            if not date_dir.is_dir():
                continue
            date_str = date_dir.name[5:]
            try:
                partition_date = date.fromisoformat(date_str)
            except ValueError:
                continue
            if partition_date >= cutoff:
                continue
            if not _silver_partition_verified(silver_root, dataset, date_str):
                logger.warning(
                    "bronze_prune_skipped_unverified_silver",
                    dataset=dataset,
                    date=date_str,
                    path=str(date_dir),
                )
                continue
            if dry_run:
                deleted += 1
                continue
            try:
                shutil.rmtree(date_dir)
                deleted += 1
                logger.debug("pruned_bronze_partition", path=str(date_dir))
            except OSError as exc:
                logger.error("prune_partition_failed", path=str(date_dir), error=repr(exc))

    return deleted


def _prune_date_partitions(root: Path, cutoff: date, *, dry_run: bool = False) -> int:
    """Delete Hive-style date= directories older than cutoff under root."""
    deleted = 0
    if not root.exists():
        return deleted

    for date_dir in sorted(root.rglob("date=*")):
        if not date_dir.is_dir():
            continue
        date_str = date_dir.name[5:]
        try:
            partition_date = date.fromisoformat(date_str)
        except ValueError:
            continue
        if partition_date < cutoff:
            if dry_run:
                deleted += 1
                continue
            try:
                shutil.rmtree(date_dir)
                deleted += 1
                logger.debug("pruned_partition", path=str(date_dir))
            except OSError as exc:
                logger.error("prune_partition_failed", path=str(date_dir), error=repr(exc))

    return deleted


def _open_dir_nofollow(path: Path) -> int | None:
    """Open a directory without following symlinks on any path component from path."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        return os.open(str(path), flags)
    except OSError:
        return None


def _prune_dir_fd(
    dir_fd: int,
    cutoff_epoch: float,
    *,
    rel_display: str,
    dry_run: bool,
) -> tuple[int, bool]:
    """Recursively prune regular files older than cutoff_epoch using dir_fd + O_NOFOLLOW.

    Never follows symlinks on files or subdirectories. Returns (deleted_count, is_empty).
    """
    deleted = 0
    remaining_entries = 0
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    try:
        entries = list(os.scandir(dir_fd))
    except OSError as exc:
        logger.error("prune_scandir_failed", path=rel_display, error=repr(exc))
        return 0, False

    for entry in entries:
        try:
            st = os.stat(entry.name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError as exc:
            logger.error(
                "prune_stat_failed",
                path=f"{rel_display}/{entry.name}",
                error=repr(exc),
            )
            remaining_entries += 1
            continue

        mode = st.st_mode
        if stat.S_ISLNK(mode):
            # Never follow symlinks inside untrusted sensor trees.
            logger.warning("prune_symlink_skipped", path=f"{rel_display}/{entry.name}")
            remaining_entries += 1
            continue

        if stat.S_ISDIR(mode):
            try:
                child_fd = os.open(entry.name, flags, dir_fd=dir_fd)
            except OSError as exc:
                logger.error(
                    "prune_open_subdir_failed",
                    path=f"{rel_display}/{entry.name}",
                    error=repr(exc),
                )
                remaining_entries += 1
                continue
            try:
                child_deleted, child_empty = _prune_dir_fd(
                    child_fd,
                    cutoff_epoch,
                    rel_display=f"{rel_display}/{entry.name}",
                    dry_run=dry_run,
                )
            finally:
                os.close(child_fd)

            deleted += child_deleted
            if child_empty and not dry_run:
                try:
                    os.rmdir(entry.name, dir_fd=dir_fd)
                except OSError:
                    remaining_entries += 1
            elif not child_empty:
                remaining_entries += 1
            continue

        if stat.S_ISREG(mode) and st.st_mtime < cutoff_epoch:
            if dry_run:
                deleted += 1
                continue
            try:
                os.unlink(entry.name, dir_fd=dir_fd)
                deleted += 1
            except OSError as exc:
                logger.error(
                    "prune_unlink_failed",
                    path=f"{rel_display}/{entry.name}",
                    error=repr(exc),
                )
                remaining_entries += 1
        else:
            remaining_entries += 1

    return deleted, remaining_entries == 0


def _open_relative_subdir_nofollow(root: Path, rel_subdir: str) -> int | None:
    """Walk path components under root opening each directory strictly with O_NOFOLLOW."""
    current_fd = _open_dir_nofollow(root)
    if current_fd is None:
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parts = [p for p in Path(rel_subdir).parts if p not in ("", ".", "*")]
    for part in parts:
        try:
            next_fd = os.open(part, flags, dir_fd=current_fd)
        except OSError:
            os.close(current_fd)
            return None
        os.close(current_fd)
        current_fd = next_fd
    return current_fd


def _prune_old_files(
    root: Path,
    cutoff: date,
    subdirs: list[str] | tuple[str, ...],
    *,
    dry_run: bool = False,
) -> int:
    """Delete files older than cutoff inside explicit sensor scratch subdirs (symlink-safe)."""
    deleted = 0
    if not root.exists():
        return deleted

    cutoff_epoch = _cutoff_epoch_utc(cutoff)
    for subdir in subdirs:
        cleaned = subdir.rstrip("/*")
        dir_fd = _open_relative_subdir_nofollow(root, cleaned)
        if dir_fd is None:
            continue
        try:
            sub_deleted, _ = _prune_dir_fd(
                dir_fd,
                cutoff_epoch,
                rel_display=str(root / cleaned),
                dry_run=dry_run,
            )
            deleted += sub_deleted
        finally:
            os.close(dir_fd)

    return deleted


def _prune_enrichment_errors(
    errors_path: Path,
    cutoff: date,
    *,
    dry_run: bool = False,
) -> int:
    """Trim entries older than cutoff from append-only enrichment_errors.json atomically."""
    if not errors_path.is_file():
        return 0

    kept_lines: list[str] = []
    removed = 0
    try:
        with errors_path.open("r", encoding="utf-8", errors="replace", newline="\n") as fh:
            for raw_line in fh:
                stripped = raw_line.strip("\x00\r\n\t ")
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                date_val = entry.get("date")
                if isinstance(date_val, str):
                    try:
                        if date.fromisoformat(date_val) < cutoff:
                            removed += 1
                            continue
                    except ValueError:
                        pass
                kept_lines.append(stripped)
    except OSError as exc:
        logger.error("prune_errors_log_read_failed", path=str(errors_path), error=repr(exc))
        return 0

    if removed == 0 or dry_run:
        return removed

    tmp_path = errors_path.with_name(f".{errors_path.name}.{os.getpid()}.tmp")
    try:
        content = ("\n".join(kept_lines) + "\n") if kept_lines else ""
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, errors_path)
    except OSError as exc:
        logger.error("prune_errors_log_write_failed", path=str(errors_path), error=repr(exc))
        tmp_path.unlink(missing_ok=True)
        return 0

    return removed


def _cleanup_empty_dirs(root: Path, *, dry_run: bool = False) -> int:
    """Remove empty directories under a nectar-owned datalake tree."""
    removed = 0
    if not root.exists():
        return removed

    for dirpath in sorted(root.rglob("*"), reverse=True):
        if dirpath.is_dir() and not dirpath.is_symlink():
            try:
                if not any(dirpath.iterdir()):
                    if not dry_run:
                        dirpath.rmdir()
                    removed += 1
            except OSError:
                continue

    return removed


def run_prune(
    lake_dir: Path = DEFAULT_LAKE_DIR,
    sensor_dir: Path = DEFAULT_SENSOR_DIR,
    retention_days: int = SILVER_GOLD_RETENTION_DAYS,
    *,
    bronze_retention_days: int = BRONZE_RETENTION_DAYS,
    sensor_retention_days: int = SENSOR_RETENTION_DAYS,
    dry_run: bool = False,
) -> int:
    """Prune verified Bronze (14d), Silver/Gold (180d), sensor scratch (14d), and error logs."""
    bronze_cutoff = _cutoff_date(bronze_retention_days)
    silver_gold_cutoff = _cutoff_date(retention_days)
    sensor_cutoff = _cutoff_date(sensor_retention_days)
    errors_cutoff = _cutoff_date(ERRORS_RETENTION_DAYS)

    total = 0
    total += _prune_bronze_partitions(
        lake_dir / "bronze", lake_dir / "silver", bronze_cutoff, dry_run=dry_run
    )
    total += _prune_date_partitions(lake_dir / "silver", silver_gold_cutoff, dry_run=dry_run)
    total += _prune_date_partitions(lake_dir / "gold", silver_gold_cutoff, dry_run=dry_run)
    total += _prune_old_files(sensor_dir, sensor_cutoff, DEFAULT_SENSOR_SUBDIRS, dry_run=dry_run)
    _prune_enrichment_errors(lake_dir / "enrichment_errors.json", errors_cutoff, dry_run=dry_run)
    _cleanup_empty_dirs(lake_dir, dry_run=dry_run)

    logger.info(
        "prune_complete",
        deleted=total,
        bronze_days=bronze_retention_days,
        silver_gold_days=retention_days,
        sensor_days=sensor_retention_days,
        dry_run=dry_run,
    )
    return total


def check_disk_usage(path: Path) -> float:
    """Return non-root usable disk usage percentage (0.0-100.0) matching `df`.

    Uses `os.statvfs` with `f_bavail` instead of `shutil.disk_usage` so ext4's
    root-reserved blocks (~3-5%) do not mask unprivileged ENOSPC as ~95-97%.
    """
    st = os.statvfs(path)
    used = st.f_blocks - st.f_bfree
    denom = used + st.f_bavail
    if denom <= 0:
        return 100.0
    return (used / denom) * 100.0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prune Lantana datalake and sensor scratch.")
    parser.add_argument("--dry-run", action="store_true", help="Report deletions without removing.")
    parser.add_argument(
        "--bronze-days",
        type=int,
        default=BRONZE_RETENTION_DAYS,
        help=f"Verified Bronze retention in days (default: {BRONZE_RETENTION_DAYS}).",
    )
    parser.add_argument(
        "--silver-days",
        type=int,
        default=SILVER_GOLD_RETENTION_DAYS,
        help=f"Silver and Gold retention in days (default: {SILVER_GOLD_RETENTION_DAYS}).",
    )
    parser.add_argument(
        "--sensor-days",
        type=int,
        default=SENSOR_RETENTION_DAYS,
        help=f"Sensor scratch retention in days (default: {SENSOR_RETENTION_DAYS}).",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for lantana-prune."""
    args = _build_parser().parse_args(argv)
    lake_dir = DEFAULT_LAKE_DIR
    sensor_dir = DEFAULT_SENSOR_DIR

    try:
        deleted = run_prune(
            lake_dir,
            sensor_dir,
            retention_days=args.silver_days,
            bronze_retention_days=args.bronze_days,
            sensor_retention_days=args.sensor_days,
            dry_run=args.dry_run,
        )
        logger.info("standard_prune_done", deleted=deleted, dry_run=args.dry_run)
    except Exception as exc:
        logger.error("standard_prune_failed", error=repr(exc))

    if not lake_dir.exists():
        return

    usage = check_disk_usage(lake_dir)
    logger.info("disk_usage", percent=round(usage, 1))

    if args.dry_run:
        return

    webhook_url: str | None = None
    try:
        from lantana.common.config import load_secrets

        secrets = load_secrets()
        webhook_url = secrets.discord_webhook or None
    except Exception as exc:
        logger.warning("no_secrets_for_notify", error=repr(exc))

    if usage > DISK_CRITICAL_THRESHOLD:
        emergency_bronze = 0
        emergency_sensor = 0
        try:
            emergency_bronze = _prune_bronze_partitions(
                lake_dir / "bronze",
                lake_dir / "silver",
                _cutoff_date(EMERGENCY_BRONZE_RETENTION_DAYS),
            )
        except Exception as exc:
            logger.error("emergency_bronze_prune_failed", error=repr(exc))
        try:
            emergency_sensor = _prune_old_files(
                sensor_dir,
                _cutoff_date(EMERGENCY_SENSOR_RETENTION_DAYS),
                DEFAULT_SENSOR_SUBDIRS,
            )
        except Exception as exc:
            logger.error("emergency_sensor_prune_failed", error=repr(exc))

        emergency_deleted = emergency_bronze + emergency_sensor
        after_usage = check_disk_usage(lake_dir)
        logger.warning(
            "emergency_prune",
            before=round(usage, 1),
            after=round(after_usage, 1),
            deleted=emergency_deleted,
            bronze_deleted=emergency_bronze,
            sensor_deleted=emergency_sensor,
        )

        if webhook_url:
            from lantana.notify.discord import send_notification

            asyncio.run(
                send_notification(
                    webhook_url=webhook_url,
                    level="critical",
                    title="Lantana: Disk Critical",
                    message=(
                        f"Usable disk usage at {usage:.1f}%. Emergency prune executed.\n"
                        f"Deleted {emergency_bronze} verified Bronze partition(s) and "
                        f"{emergency_sensor} sensor artifact(s) "
                        f"(stepped down to {EMERGENCY_BRONZE_RETENTION_DAYS} days).\n"
                        f"Usage after prune: {after_usage:.1f}%."
                    ),
                )
            )

    elif usage > DISK_WARNING_THRESHOLD:
        logger.warning("disk_warning", percent=round(usage, 1))

        if webhook_url:
            from lantana.notify.discord import send_notification

            asyncio.run(
                send_notification(
                    webhook_url=webhook_url,
                    level="warning",
                    title="Lantana: Disk Warning",
                    message=(
                        f"Usable disk usage at {usage:.1f}%. "
                        f"Threshold is {DISK_WARNING_THRESHOLD}%."
                    ),
                )
            )

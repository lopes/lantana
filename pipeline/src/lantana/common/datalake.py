"""Functions for reading/writing the partitioned datalake."""

from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path

import polars as pl
import structlog

logger = structlog.get_logger()

BRONZE_ROOT: Path = Path(os.environ.get("LANTANA_BRONZE_ROOT", "/var/lib/lantana/datalake/bronze"))
SILVER_ROOT: Path = Path(os.environ.get("LANTANA_SILVER_ROOT", "/var/lib/lantana/datalake/silver"))
GOLD_ROOT: Path = Path(os.environ.get("LANTANA_GOLD_ROOT", "/var/lib/lantana/datalake/gold"))


def _sanitize_value(value: object) -> object:
    """Coerce nested structures to JSON strings and strip embedded NUL bytes."""
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, (list, dict)):
        dumped = json.dumps(value)
        return dumped.replace("\\u0000", "").replace("\x00", "")
    return value


def _normalize_server_name(server: str | None) -> str:
    """Return a safe non-empty server partition key."""
    if server is None:
        return "unknown"
    cleaned = server.strip()
    return cleaned if cleaned else "unknown"


def _write_parquet_atomic(df: pl.DataFrame, output_path: Path) -> Path:
    """Write a Parquet file via a sibling temporary file + os.replace()."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    try:
        df.write_parquet(tmp_path)
        os.replace(tmp_path, output_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return output_path


def read_bronze_ndjson(
    target_date: date,
    dataset: str | None = None,
    bronze_root: Path = BRONZE_ROOT,
) -> pl.DataFrame:
    """Read bronze-layer NDJSON files for a given date and optional dataset.

    Streams files line-by-line (newline='\\n') to avoid buffering huge files in RAM
    and avoid splitting on Unicode separators (U+2028/U+2029), strips sparse NUL
    prefixes from copytruncate, tolerates non-UTF-8 bytes, and skips ENOSPC-truncated
    or malformed lines with a structured warning.
    """
    date_str = target_date.isoformat()
    pattern = f"dataset={dataset}" if dataset else "dataset=*"

    matching_files = sorted(bronze_root.glob(f"{pattern}/date={date_str}/server=*/events.json"))

    if not matching_files:
        return pl.DataFrame()

    frames: list[pl.DataFrame] = []
    for file_path in matching_files:
        parts = file_path.parts
        ds = _extract_partition_value(parts, "dataset") or "unknown"
        server = _normalize_server_name(_extract_partition_value(parts, "server"))

        records: list[dict[str, object]] = []
        malformed_count = 0
        try:
            with file_path.open("r", encoding="utf-8", errors="replace", newline="\n") as fh:
                for line in fh:
                    stripped = line.replace("\x00", "").strip()
                    if not stripped:
                        continue
                    try:
                        parsed = json.loads(stripped)
                        if isinstance(parsed, dict):
                            records.append({k: _sanitize_value(v) for k, v in parsed.items()})
                        else:
                            malformed_count += 1
                    except json.JSONDecodeError:
                        malformed_count += 1
        except OSError as exc:
            logger.error("bronze_file_read_failed", path=str(file_path), error=repr(exc))
            continue

        if malformed_count > 0:
            logger.warning(
                "bronze_malformed_lines_skipped",
                path=str(file_path),
                count=malformed_count,
            )

        if not records:
            continue

        df = pl.DataFrame(records, infer_schema_length=None)

        # Normalize IPv4-mapped IPv6 addresses (::ffff:1.2.3.4 -> 1.2.3.4)
        ip_cols = [
            c
            for c in (
                "src_ip",
                "dst_ip",
                "dest_ip",
                "local_ip",
                "dst_host",
                "src_endpoint_ip",
                "dst_endpoint_ip",
            )
            if c in df.columns and df.schema[c] == pl.Utf8
        ]
        if ip_cols:
            df = df.with_columns(
                pl.col(c).str.replace(r"^(?i)::ffff:", "").alias(c) for c in ip_cols
            )

        # Ensure timestamp is Datetime (raw logs store it as string).
        # Strip ISO-8601 timezone suffixes ("Z", "+0000", "+00:00")
        # and parse as naive datetime (all events are UTC).
        if "timestamp" in df.columns and df.schema["timestamp"] == pl.Utf8:
            ts = (
                df.get_column("timestamp")
                .str.replace(r"(?:[+-]\d{2}:\d{2}|[+-]\d{4}|Z)$", "")
                .str.to_datetime(strict=False)
            )
            df = df.with_columns(ts.alias("timestamp"))

        # Backfill partition columns if absent, null, or empty string
        if "dataset" not in df.columns:
            df = df.with_columns(pl.lit(ds).alias("dataset"))
        else:
            ds_col = pl.col("dataset").cast(pl.Utf8)
            df = df.with_columns(
                pl.when(ds_col.is_null() | (ds_col.str.strip_chars() == ""))
                .then(pl.lit(ds))
                .otherwise(ds_col)
                .alias("dataset")
            )

        if "server" not in df.columns:
            df = df.with_columns(pl.lit(server).alias("server"))
        else:
            srv_col = pl.col("server").cast(pl.Utf8)
            df = df.with_columns(
                pl.when(srv_col.is_null() | (srv_col.str.strip_chars() == ""))
                .then(pl.lit(server))
                .otherwise(srv_col)
                .alias("server")
            )

        frames.append(df)

    if not frames:
        return pl.DataFrame()

    return pl.concat(frames, how="diagonal_relaxed")


def read_silver_partition(
    target_date: date,
    dataset: str | None = None,
    silver_root: Path = SILVER_ROOT,
) -> pl.LazyFrame:
    """Read silver-layer Parquet files for a given date and optional dataset."""
    date_str = target_date.isoformat()
    pattern = f"dataset={dataset}" if dataset else "dataset=*"

    matching_files = sorted(silver_root.glob(f"{pattern}/date={date_str}/server=*/events.parquet"))

    if not matching_files:
        return pl.LazyFrame()

    frames = [pl.scan_parquet(f, hive_partitioning=False) for f in matching_files]
    return pl.concat(frames, how="diagonal_relaxed")


def write_silver_partition(
    df: pl.DataFrame,
    target_date: date,
    dataset: str,
    server: str,
    silver_root: Path = SILVER_ROOT,
) -> Path:
    """Write a DataFrame to the silver layer as Parquet atomically."""
    date_str = target_date.isoformat()
    safe_server = _normalize_server_name(server)
    output_path = (
        silver_root
        / f"dataset={dataset}"
        / f"date={date_str}"
        / f"server={safe_server}"
        / "events.parquet"
    )
    return _write_parquet_atomic(df, output_path)


def write_gold_table(
    df: pl.DataFrame,
    table_name: str,
    target_date: date,
    gold_root: Path = GOLD_ROOT,
) -> Path:
    """Write a DataFrame to the gold layer as a named table atomically."""
    date_str = target_date.isoformat()
    output_path = gold_root / table_name / f"date={date_str}" / "summary.parquet"
    return _write_parquet_atomic(df, output_path)


def read_gold_table(
    table_name: str,
    target_date: date,
    gold_root: Path = GOLD_ROOT,
) -> pl.DataFrame:
    """Read a gold-layer Parquet table for a given date."""
    date_str = target_date.isoformat()
    path = gold_root / table_name / f"date={date_str}" / "summary.parquet"
    try:
        return pl.read_parquet(path)
    except (FileNotFoundError, PermissionError):
        return pl.DataFrame()


def _normalize_legacy_list_nulls(frames: list[pl.DataFrame]) -> list[pl.DataFrame]:
    """Cast legacy ``List(Null)`` columns to concrete list types before diagonal concat.

    Pre-v1.5 gold partitions sometimes wrote empty list columns with dtype
    ``List(Null)`` (e.g. ``top_asns``, ``ips``, ``top_download_hashes``). Polars
    ``diagonal_relaxed`` raises when concatenating ``List(Null)`` with
    ``List(Struct(...))`` or ``List(Utf8)`` unless normalized first.
    """
    target_dtypes: dict[str, pl.DataType] = {}
    for frame in frames:
        for col, dtype in frame.schema.items():
            if isinstance(dtype, pl.List) and dtype.inner != pl.Null:
                target_dtypes.setdefault(col, dtype)

    normalized: list[pl.DataFrame] = []
    for frame in frames:
        casts: list[pl.Expr] = []
        for col, dtype in frame.schema.items():
            if isinstance(dtype, pl.List) and dtype.inner == pl.Null:
                target = target_dtypes.get(col, pl.List(pl.Utf8))
                casts.append(pl.col(col).cast(target).alias(col))
        normalized.append(frame.with_columns(casts) if casts else frame)
    return normalized


def read_gold_range(
    table_name: str,
    dates: list[date],
    gold_root: Path = GOLD_ROOT,
) -> pl.DataFrame:
    """Read and concatenate a gold table across multiple dates with ``report_date``.

    Missing or unreadable dates are skipped cleanly. Legacy ``List(Null)``
    columns are normalized before ``pl.concat(..., how="diagonal_relaxed")`` so
    multi-day and all-time dashboard windows never fail on schema drift.
    """
    frames: list[pl.DataFrame] = []
    for d in sorted(set(dates)):
        df = read_gold_table(table_name, d, gold_root=gold_root)
        if not df.is_empty():
            frames.append(df.with_columns(pl.lit(d).alias("report_date")))
    if not frames:
        return pl.DataFrame()
    if len(frames) == 1:
        return frames[0]
    return pl.concat(_normalize_legacy_list_nulls(frames), how="diagonal_relaxed")


def list_gold_dates(
    table_name: str,
    gold_root: Path = GOLD_ROOT,
) -> list[date]:
    """List available dates for a gold table, sorted descending (newest first)."""
    table_dir = gold_root / table_name
    try:
        entries = list(table_dir.iterdir())
    except (FileNotFoundError, PermissionError):
        return []
    dates: list[date] = []
    for entry in entries:
        if entry.is_dir() and entry.name.startswith("date="):
            date_str = entry.name[5:]
            try:
                dates.append(date.fromisoformat(date_str))
            except ValueError:
                continue
    return sorted(dates, reverse=True)


def _extract_partition_value(parts: tuple[str, ...], key: str) -> str:
    """Extract a Hive partition value from path components."""
    prefix = f"{key}="
    for part in parts:
        if part.startswith(prefix):
            return part[len(prefix) :]
    return ""

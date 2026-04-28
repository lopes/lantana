#!/usr/bin/env python3
"""Inject raw VPS logs into a local bronze datalake.

Reads raw honeypot JSON logs from the fetched VPS data, simulates what
Vector would do (parse, tag, partition by date), and writes Hive-partitioned
bronze NDJSON that the pipeline can process directly.

Usage: .venv/bin/python scripts/inject-vps-data.py [--datalake DIR]

Reads from:  pipeline/tests/fixtures/live/log/lantana/
Writes to:   pipeline/tests/fixtures/live/datalake/bronze/  (default)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# Raw log locations relative to the live fixtures root, mapped to dataset name.
# Adjust if the VPS has logs in different subdirectories.
LOG_SOURCES: dict[str, list[str]] = {
    "cowrie": [
        "log/lantana/sensor/cowrie/cowrie.json",
        "log/lantana/sensor/cowrie/cowrie.json.1",
        "log/lantana/sensor/cowrie/cowrie.json.2",
    ],
    "suricata": [
        "log/lantana/honeywall/suricata/eve.json",
        "log/lantana/honeywall/suricata/eve.json.1",
        "log/lantana/honeywall/suricata/eve.json.2",
    ],
    "nftables": [
        "log/lantana/honeywall/nftables.json",
        "log/lantana/honeywall/nftables.json.1",
        "log/lantana/honeywall/nftables.json.2",
    ],
}

SERVER_NAME = "vps-sensor-01"
OPERATION_NAME = "op_vps"


def extract_date(record: dict[str, object]) -> str | None:
    """Extract YYYY-MM-DD from a record's timestamp field."""
    for key in ("timestamp", "@timestamp", "time"):
        val = record.get(key)
        if isinstance(val, str) and len(val) >= 10:
            return val[:10]
    return None


def ingest_log(path: Path, dataset: str) -> dict[str, list[str]]:
    """Read a raw JSON log, tag records, and group by date.

    Returns {date_str: [json_line, ...]}.
    """
    by_date: dict[str, list[str]] = defaultdict(list)
    skipped = 0

    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            date_str = extract_date(record)
            if date_str is None:
                skipped += 1
                continue

            # Simulate Vector transforms: flatten nested objects that
            # Vector would extract into top-level fields.
            # Suricata: alert.signature -> alert_signature, etc.
            if "alert" in record and isinstance(record["alert"], dict):
                alert = record.pop("alert")
                record["alert_signature"] = alert.get("signature")
                record["alert_signature_id"] = alert.get("signature_id")
                record["alert_severity"] = alert.get("severity")
                record["alert_category"] = alert.get("category")
                record["alert_action"] = alert.get("action")

            # Drop nested objects the pipeline doesn't use (flow, tcp,
            # metadata, etc.) -- they cause Polars schema conflicts.
            for nested_key in (
                "flow", "tcp", "metadata", "stats", "ssh", "dns",
                "http", "tls", "fileinfo", "smb", "sip", "ike",
                "snmp", "krb5", "tftp", "dhcp", "anomaly", "netflow",
                "packet_info",
            ):
                record.pop(nested_key, None)

            # Add Vector tags
            record["dataset"] = dataset
            record["server"] = SERVER_NAME
            record["operation"] = OPERATION_NAME

            by_date[date_str].append(json.dumps(record, separators=(",", ":")))

    if skipped:
        print(f"  [{dataset}] skipped {skipped} unparseable lines")

    return dict(by_date)


def write_bronze(
    by_date: dict[str, list[str]],
    dataset: str,
    bronze_root: Path,
) -> int:
    """Write date-partitioned bronze NDJSON files. Returns total events written."""
    total = 0
    for date_str, lines in sorted(by_date.items()):
        out_dir = bronze_root / f"dataset={dataset}" / f"date={date_str}" / f"server={SERVER_NAME}"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "events.json"

        # Append if file exists (multiple source logs for same date)
        with out_path.open("a", encoding="utf-8") as fh:
            for json_line in lines:
                fh.write(json_line + "\n")

        total += len(lines)

    return total


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject VPS logs into local bronze datalake")
    parser.add_argument(
        "--live-root",
        type=Path,
        default=Path("pipeline/tests/fixtures/live"),
        help="Root of fetched VPS data (default: pipeline/tests/fixtures/live)",
    )
    parser.add_argument(
        "--datalake",
        type=Path,
        default=None,
        help="Bronze output dir (default: <live-root>/datalake/bronze)",
    )
    args = parser.parse_args()

    live_root: Path = args.live_root
    bronze_root: Path = args.datalake or (live_root / "datalake" / "bronze")

    if not live_root.exists():
        print(f"Error: {live_root} does not exist. Run scripts/fetch-vps-data.sh first.", file=sys.stderr)
        sys.exit(1)

    print(f"Live root:   {live_root}")
    print(f"Bronze dest: {bronze_root}")
    print()

    grand_total = 0
    datasets_found = 0

    for dataset, rel_paths in LOG_SOURCES.items():
        combined: dict[str, list[str]] = defaultdict(list)

        for rel_path in rel_paths:
            full_path = live_root / rel_path
            if not full_path.exists():
                continue

            print(f"  Reading {rel_path} ...")
            by_date = ingest_log(full_path, dataset)
            for date_str, lines in by_date.items():
                combined[date_str].extend(lines)

        if not combined:
            print(f"  [{dataset}] no log files found, skipping")
            continue

        datasets_found += 1
        total = write_bronze(combined, dataset, bronze_root)
        dates = sorted(combined.keys())
        print(f"  [{dataset}] {total:,} events across {len(dates)} days ({dates[0]} to {dates[-1]})")
        grand_total += total

    print()
    if datasets_found == 0:
        print("No data found. Check that fetch-vps-data.sh ran successfully.")
        sys.exit(1)

    print(f"Injected {grand_total:,} events from {datasets_found} datasets into {bronze_root}")
    print()
    print("Next steps:")
    print(f"  1. Run integration tests:  .venv/bin/pytest -m integration -v")
    print(f"  2. Or run the pipeline manually:")
    print(f"     .venv/bin/python -c \"")
    print(f"       from datetime import date")
    print(f"       from lantana.common.datalake import read_bronze_ndjson")
    print(f"       df = read_bronze_ndjson(date.fromisoformat('<DATE>'), bronze_root=Path('{bronze_root}'))")
    print(f"       print(df)\"")


if __name__ == "__main__":
    main()

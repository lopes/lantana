"""Daily error-log alerter — scans the structured errors file and pages on critical.

Severity model
--------------

The operator's foundational guarantee is that bronze data collected from
honeypots gets turned into silver + gold files. Anything that prevents file
creation is **critical** — the pipeline failed at its job, and the operator
needs to know now (not from a quiet dashboard tomorrow). Third-party
integrations (AbuseIPDB, VirusTotal, …) are optional decoration; they fail all
the time (rate limits, transient outages), so their errors are **warnings** —
visible in the daily embed but not page-worthy on their own.

Critical error types:
  - ``dataset_processing_failed`` — a dataset's silver write was skipped
    (defect #9 class)
  - ``transform_failed``          — ``lantana-transform`` crashed (defect #10
    class — wraps ``run_transform.main`` so the failure lands in the same
    errors file even though it happens outside ``run_enrichment``)

Warning error types:
  - ``auth_failed``    — provider key broken; pipeline still produces files,
    just that provider's columns are null
  - ``rate_limit``, ``not_found``, ``timeout``, ``network_error``,
    ``server_error``, ``http_4xx``, ``unknown`` — per-IOC degradation

Run shape
---------

Standalone cron at 05:00 UTC (post 01:00 enrich + 02:00 transform) reads the
NDJSON errors file, filters to the target date (yesterday by default), and
posts a Discord embed when ``critical_count`` or ``warning_count`` is non-zero.
Clean days produce nothing — operators infer "no message = no issues". An
idempotency marker (``.last_alerted``) prevents duplicate alerts on
``lantana-alert`` re-runs; pass ``--force`` to override during debugging.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import structlog

from lantana.common.config import load_reporting, load_secrets
from lantana.notify.discord import send_notification

logger = structlog.get_logger()

DEFAULT_ERRORS_PATH = Path("/var/lib/lantana/datalake/enrichment_errors.json")
DEFAULT_STATE_PATH = Path("/var/lib/lantana/datalake/.last_alerted")

CRITICAL_ERROR_TYPES: frozenset[str] = frozenset({
    "dataset_processing_failed",
    "transform_failed",
})

MESSAGE_TRUNCATE = 200
TOP_N_CRITICAL = 5
TOP_N_WARNING = 10


@dataclass
class ErrorBuckets:
    """Result of categorising the day's error rows."""

    critical: list[dict[str, Any]]
    warning: list[dict[str, Any]]

    @property
    def is_clean(self) -> bool:
        return not self.critical and not self.warning

    @property
    def has_critical(self) -> bool:
        return bool(self.critical)


def categorize_errors(rows: list[dict[str, Any]]) -> ErrorBuckets:
    """Split error rows into critical and warning buckets by error_type."""
    critical: list[dict[str, Any]] = []
    warning: list[dict[str, Any]] = []
    for row in rows:
        if row.get("error_type") in CRITICAL_ERROR_TYPES:
            critical.append(row)
        else:
            warning.append(row)
    return ErrorBuckets(critical=critical, warning=warning)


def load_errors_for_date(errors_path: Path, target_date: date) -> list[dict[str, Any]]:
    """Read the NDJSON errors file, return rows matching the target date.

    Malformed lines are logged at warning level and skipped — never crash
    the alerter on a corrupt row.
    """
    if not errors_path.exists():
        return []
    target = target_date.isoformat()
    rows: list[dict[str, Any]] = []
    with errors_path.open(encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError:
                logger.warning("alerter_malformed_row", line=stripped[:120])
                continue
            if entry.get("date") == target:
                rows.append(entry)
    return rows


def _truncate(value: str, limit: int = MESSAGE_TRUNCATE) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def build_embed_body(target_date: date, buckets: ErrorBuckets) -> str:
    """Format a Markdown body for the Discord embed.

    Critical errors get individual bullets (top 5 by occurrence). Warnings
    are aggregated by (provider, error_type) and sorted by total count.
    """
    lines: list[str] = [f"**Date:** `{target_date.isoformat()}`"]

    if buckets.critical:
        lines.append(f"\n🔴 **Critical: {len(buckets.critical)}**")
        sorted_critical = sorted(
            buckets.critical, key=lambda r: int(r.get("count", 1)), reverse=True
        )
        for row in sorted_critical[:TOP_N_CRITICAL]:
            provider = row.get("provider", "?")
            etype = row.get("error_type", "?")
            count = row.get("count", 1)
            msg = _truncate(str(row.get("message", "")))
            lines.append(f"• `{provider}` / `{etype}` (x{count}) — {msg}")

    if buckets.warning:
        total_warnings = sum(int(r.get("count", 1)) for r in buckets.warning)
        lines.append(f"\n🟡 **Warnings: {total_warnings}** (deduped)")
        buckets_map: dict[tuple[str, str], int] = {}
        for row in buckets.warning:
            key = (str(row.get("provider", "?")), str(row.get("error_type", "?")))
            buckets_map[key] = buckets_map.get(key, 0) + int(row.get("count", 1))
        for (provider, etype), count in sorted(
            buckets_map.items(), key=lambda kv: kv[1], reverse=True
        )[:TOP_N_WARNING]:
            lines.append(f"• `{provider}` / `{etype}` (x{count})")

    return "\n".join(lines)


def has_been_alerted(state_path: Path, target_date: date) -> bool:
    """Check whether the alerter has already fired for ``target_date``."""
    if not state_path.exists():
        return False
    try:
        contents = state_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return target_date.isoformat() in {line.strip() for line in contents.splitlines()}


def mark_alerted(state_path: Path, target_date: date) -> None:
    """Append the target date to the idempotency marker."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with state_path.open("a", encoding="utf-8") as f:
        f.write(target_date.isoformat() + "\n")


async def send_alert(
    webhook_url: str,
    operation_name: str,
    target_date: date,
    buckets: ErrorBuckets,
) -> None:
    """Build and post the Discord embed for a non-clean day."""
    level = "critical" if buckets.has_critical else "warning"
    title = f"Lantana {operation_name} — {target_date.isoformat()} ({level.upper()})"
    body = build_embed_body(target_date, buckets)
    await send_notification(
        webhook_url=webhook_url,
        level=level,
        title=title,
        message=body,
    )


async def run_alerter(
    target_date: date,
    errors_path: Path = DEFAULT_ERRORS_PATH,
    state_path: Path = DEFAULT_STATE_PATH,
    force: bool = False,
) -> None:
    """Read errors for ``target_date`` and alert via Discord when non-clean."""
    if not force and has_been_alerted(state_path, target_date):
        logger.info("alerter_skip_already_sent", date=target_date.isoformat())
        return

    rows = load_errors_for_date(errors_path, target_date)
    buckets = categorize_errors(rows)

    logger.info(
        "alerter_run",
        date=target_date.isoformat(),
        critical=len(buckets.critical),
        warning=len(buckets.warning),
    )

    if buckets.is_clean:
        # Clean day — do not page, do not mark (so a late-arriving error row
        # written between alerter runs is still picked up on a manual --force
        # or the next day's pass).
        return

    secrets = load_secrets()
    reporting = load_reporting()
    if not secrets.discord_webhook:
        logger.warning(
            "alerter_no_webhook",
            hint="set vault_webhook_discord to enable critical alerting",
        )
        return

    await send_alert(
        webhook_url=secrets.discord_webhook,
        operation_name=reporting.operation.name,
        target_date=target_date,
        buckets=buckets,
    )
    mark_alerted(state_path, target_date)


def main() -> None:
    """CLI entry point for ``lantana-alert``."""
    parser = argparse.ArgumentParser(
        prog="lantana-alert",
        description="Scan the daily errors log and post a Discord summary on non-clean days.",
    )
    parser.add_argument(
        "--date",
        type=date.fromisoformat,
        default=None,
        metavar="YYYY-MM-DD",
        help="Date to scan (UTC). Defaults to yesterday.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-alert even if the marker says we already did.",
    )
    args = parser.parse_args()
    target = args.date if args.date is not None else date.today() - timedelta(days=1)
    asyncio.run(run_alerter(target, force=args.force))

"""Discord webhook client for sending notifications and reports."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

if TYPE_CHECKING:
    from lantana.notify.alerts import ErrorBuckets

logger = structlog.get_logger()

# Discord embed colors by severity level
EMBED_COLORS: dict[str, int] = {
    "info": 0x2ECC71,  # Green
    "warning": 0xF39C12,  # Orange
    "critical": 0xE74C3C,  # Red
}


def max_severity(buckets: ErrorBuckets) -> str:
    """Return the embed level matching the highest severity tier present.

    Color rule (user-facing): green for clean or info-only days, yellow when
    warnings exist, red when any critical row is present. Info-tier rows
    (rate-limit exhaustion) are routine ops noise and don't escalate the
    color; they're surfaced in the brief attachment for traceability.
    """
    if buckets.has_critical:
        return "critical"
    if buckets.has_warning:
        return "warning"
    return "info"


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=30))
async def send_notification(
    webhook_url: str,
    level: str,
    title: str,
    message: str,
    attachment_path: str | None = None,
) -> None:
    """Send a notification to a Discord webhook.

    Args:
        webhook_url: Discord webhook URL.
        level: Severity level (info, warning, critical).
        title: Notification title.
        message: Notification body.
        attachment_path: Optional file path to attach.
    """
    color = EMBED_COLORS.get(level, EMBED_COLORS["info"])

    embed = {
        "title": title,
        "description": message,
        "color": color,
        "footer": {"text": f"Lantana | {level.upper()}"},
    }

    payload = {"embeds": [embed]}

    async with httpx.AsyncClient(timeout=30) as client:
        if attachment_path is not None:
            import json
            from pathlib import Path

            file_path = Path(attachment_path)
            with file_path.open("rb") as f:
                resp = await client.post(
                    webhook_url,
                    data={"payload_json": json.dumps(payload)},
                    files={"file": (file_path.name, f)},
                )
        else:
            resp = await client.post(webhook_url, json=payload)

        resp.raise_for_status()
        logger.info("discord_sent", level=level, title=title, status=resp.status_code)


def generate_and_send(argv: list[str] | None = None) -> None:
    """CLI entry point for lantana-report.

    Merged daily flow: loads yesterday's enrichment errors, classifies them
    into critical/warning/info tiers, reads gold tables, and posts a single
    Discord message whose embed color follows max severity. The full brief
    (markdown) is attached. Replaces the previous split between
    ``lantana-alert`` and ``lantana-report``.
    """
    import argparse
    import asyncio
    import os
    import tempfile
    from datetime import UTC, date, datetime, timedelta
    from pathlib import Path

    import polars as pl

    from lantana.common.config import load_reporting, load_secrets
    from lantana.common.datalake import SILVER_ROOT, read_gold_table, read_silver_partition
    from lantana.notify.alerts import (
        DEFAULT_ERRORS_PATH,
        categorize_errors,
        evaluate_liveness_alerts,
        load_errors_for_date,
    )
    from lantana.notify.report import generate_daily_brief, generate_embed_summary
    from lantana.notify.timing import collect_step_timings
    from lantana.prune import DEFAULT_LAKE_DIR, check_disk_usage

    parser = argparse.ArgumentParser(
        prog="lantana-report",
        description="Generate and send the daily Lantana intelligence brief to Discord.",
    )
    parser.add_argument(
        "--date",
        type=date.fromisoformat,
        default=None,
        metavar="YYYY-MM-DD",
        help="Date to report on (UTC). Defaults to yesterday.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate brief and embed locally without posting to Discord.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Optional path to write the rendered Markdown brief.",
    )
    parsed_args, _ = parser.parse_known_args(argv)
    target_date = (
        parsed_args.date
        if parsed_args.date is not None
        else datetime.now(UTC).date() - timedelta(days=1)
    )
    secrets = load_secrets()
    reporting = load_reporting()

    if not parsed_args.dry_run and parsed_args.output is None and not secrets.discord_webhook:
        logger.warning("no_discord_webhook", hint="Set discord_webhook in secrets.json")
        return

    errors_path = Path(os.environ.get("LANTANA_ENRICHMENT_ERRORS", str(DEFAULT_ERRORS_PATH)))
    error_rows = load_errors_for_date(errors_path, target_date)

    # Per-step duration from systemd. Report self-timing is intentionally
    # skipped (see notify/timing.py).
    timings = collect_step_timings(
        [
            "lantana-prune",
            "lantana-enrich",
            "lantana-transform",
        ]
    )

    disk_usage_pct: float | None = None
    try:
        if DEFAULT_LAKE_DIR.exists():
            disk_usage_pct = check_disk_usage(DEFAULT_LAKE_DIR)
    except OSError as exc:
        logger.warning("disk_usage_check_failed", error=repr(exc))

    summary = read_gold_table("daily_summary", target_date)
    reputation = read_gold_table("ip_reputation", target_date)
    progression = read_gold_table("behavioral_progression", target_date)
    clusters = read_gold_table("campaign_clusters", target_date)
    geographic = read_gold_table("geographic_summary", target_date)
    detection = read_gold_table("detection_findings", target_date)

    liveness_rows = evaluate_liveness_alerts(
        target_date=target_date,
        summary=summary,
        expected_datasets=reporting.operation.expected_datasets,
        silver_root=SILVER_ROOT,
        timings=timings,
        disk_usage_pct=disk_usage_pct,
    )
    buckets = categorize_errors([*error_rows, *liveness_rows])

    try:
        silver = read_silver_partition(target_date).collect()
    except (FileNotFoundError, pl.exceptions.PolarsError) as exc:
        logger.warning(
            "silver_read_failed",
            error_type=type(exc).__name__,
            error=repr(exc),
        )
        silver = pl.DataFrame()

    brief = generate_daily_brief(
        target_date,
        summary,
        reputation,
        progression,
        clusters,
        reporting.operation.name,
        geographic=geographic,
        detection=detection,
        buckets=buckets,
        timing=timings,
        silver=silver,
        tlp=reporting.sharing.tlp,
        disk_usage_pct=disk_usage_pct,
    )
    embed_text = generate_embed_summary(
        target_date,
        summary,
        progression,
        buckets=buckets,
        timing=timings,
        disk_usage_pct=disk_usage_pct,
    )
    level = max_severity(buckets)

    if parsed_args.output is not None:
        parsed_args.output.write_text(brief, encoding="utf-8")
        logger.info("report_written", path=str(parsed_args.output), level=level)

    if parsed_args.dry_run or not secrets.discord_webhook:
        logger.info("report_dry_run_complete", date=target_date.isoformat(), level=level)
        return

    # Write report to temp file for attachment
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".md",
        prefix=f"lantana-brief-{target_date.isoformat()}-",
        delete=False,
    ) as f:
        f.write(brief)
        report_path = Path(f.name)

    try:
        asyncio.run(
            send_notification(
                webhook_url=secrets.discord_webhook,
                level=level,
                title=f"Lantana Daily Brief — {target_date.isoformat()}",
                message=embed_text,
                attachment_path=str(report_path),
            )
        )
    finally:
        report_path.unlink(missing_ok=True)

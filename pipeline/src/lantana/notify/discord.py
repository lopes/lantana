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


def generate_and_send() -> None:
    """CLI entry point for lantana-report.

    Merged daily flow: loads yesterday's enrichment errors, classifies them
    into critical/warning/info tiers, reads gold tables, and posts a single
    Discord message whose embed color follows max severity. The full brief
    (markdown) is attached. Replaces the previous split between
    ``lantana-alert`` and ``lantana-report``.
    """
    import asyncio
    import tempfile
    from datetime import date, timedelta
    from pathlib import Path

    from lantana.common.config import load_reporting, load_secrets
    from lantana.common.datalake import read_gold_table
    from lantana.notify.alerts import DEFAULT_ERRORS_PATH, categorize_errors, load_errors_for_date
    from lantana.notify.report import generate_daily_brief, generate_embed_summary

    yesterday = date.today() - timedelta(days=1)
    secrets = load_secrets()
    reporting = load_reporting()

    if not secrets.discord_webhook:
        logger.warning("no_discord_webhook", hint="Set discord_webhook in secrets.json")
        return

    # Pipeline-health classification — single source of truth for the embed
    # color and the brief's Pipeline Health section.
    error_rows = load_errors_for_date(DEFAULT_ERRORS_PATH, yesterday)
    buckets = categorize_errors(error_rows)

    # Read gold tables. geographic_summary + detection_findings are
    # optional in generate_daily_brief (they gate the Geographic Origin
    # and Detection Highlights sections); the prior code omitted them
    # and those sections were silently dropped from every report.
    summary = read_gold_table("daily_summary", yesterday)
    reputation = read_gold_table("ip_reputation", yesterday)
    progression = read_gold_table("behavioral_progression", yesterday)
    clusters = read_gold_table("campaign_clusters", yesterday)
    geographic = read_gold_table("geographic_summary", yesterday)
    detection = read_gold_table("detection_findings", yesterday)

    # Generate report with health classification embedded.
    brief = generate_daily_brief(
        yesterday,
        summary,
        reputation,
        progression,
        clusters,
        reporting.operation.name,
        geographic=geographic,
        detection=detection,
        buckets=buckets,
    )
    embed_text = generate_embed_summary(yesterday, summary, progression, buckets=buckets)
    level = max_severity(buckets)

    # Write report to temp file for attachment
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".md",
        prefix=f"lantana-brief-{yesterday.isoformat()}-",
        delete=False,
    ) as f:
        f.write(brief)
        report_path = Path(f.name)

    try:
        asyncio.run(
            send_notification(
                webhook_url=secrets.discord_webhook,
                level=level,
                title=f"Lantana Daily Brief — {yesterday.isoformat()}",
                message=embed_text,
                attachment_path=str(report_path),
            )
        )
    finally:
        report_path.unlink(missing_ok=True)

"""Discord webhook client for sending notifications and reports."""

from __future__ import annotations

from pathlib import Path


async def send_notification(
    webhook_url: str,
    level: str,
    title: str,
    message: str,
    attachment_path: Path | None = None,
) -> None:
    """Send a notification to a Discord webhook.

    Args:
        webhook_url: Discord webhook URL.
        level: Severity level (info, warning, critical).
        title: Notification title.
        message: Notification body.
        attachment_path: Optional file to attach.
    """
    raise NotImplementedError("TODO")


def generate_and_send() -> None:
    """CLI entry point for lantana-report: generate daily report and send to Discord."""
    raise NotImplementedError("TODO")

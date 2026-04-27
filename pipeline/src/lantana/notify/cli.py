"""CLI entry point for lantana-notify."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

import structlog

from lantana.notify.discord import send_notification

logger = structlog.get_logger()


def _resolve_webhook_url(cli_url: str | None) -> str | None:
    """Resolve webhook URL from CLI arg, env var, or secrets.json (in order)."""
    if cli_url:
        return cli_url

    env_url = os.environ.get("LANTANA_DISCORD_WEBHOOK")
    if env_url:
        return env_url

    # Try loading from secrets.json
    try:
        from lantana.common.config import load_secrets

        secrets = load_secrets()
        if secrets.discord_webhook:
            return secrets.discord_webhook
    except Exception:
        pass

    return None


def main() -> None:
    """Parse CLI args and send a Discord notification."""
    parser = argparse.ArgumentParser(description="Send a Lantana notification to Discord")
    parser.add_argument("--level", required=True, choices=["info", "warning", "critical"])
    parser.add_argument("--title", required=True)
    parser.add_argument("--message", required=True)
    parser.add_argument("--attachment", default=None)
    parser.add_argument("--webhook-url", default=None)
    args = parser.parse_args()

    webhook_url = _resolve_webhook_url(args.webhook_url)
    if not webhook_url:
        logger.warning(
            "no_webhook_url",
            hint="Set --webhook-url, LANTANA_DISCORD_WEBHOOK, or secrets.json",
        )
        sys.exit(1)

    asyncio.run(send_notification(
        webhook_url=webhook_url,
        level=args.level,
        title=args.title,
        message=args.message,
        attachment_path=args.attachment,
    ))

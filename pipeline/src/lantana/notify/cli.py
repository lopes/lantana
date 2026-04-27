"""CLI entry point for lantana-notify."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from lantana.notify.discord import send_notification


def main() -> None:
    """Parse CLI args and send a Discord notification."""
    parser = argparse.ArgumentParser(description="Send a Lantana notification to Discord")
    parser.add_argument("--level", required=True, choices=["info", "warning", "critical"])
    parser.add_argument("--title", required=True)
    parser.add_argument("--message", required=True)
    parser.add_argument("--attachment", type=Path, default=None)
    args = parser.parse_args()

    raise NotImplementedError("TODO")

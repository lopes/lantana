"""Main enrichment orchestrator -- reads bronze, enriches IPs, writes silver."""

from __future__ import annotations

import asyncio
from datetime import date


async def run_enrichment(target_date: date) -> None:
    """Run the full enrichment pipeline for a given date."""
    raise NotImplementedError("TODO")


def main() -> None:
    """CLI entry point for lantana-enrich."""
    asyncio.run(run_enrichment(date.today()))

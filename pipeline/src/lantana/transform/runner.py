"""Gold aggregation runner -- reads silver, computes metrics, writes gold."""

from __future__ import annotations

from datetime import date


def run_transform(target_date: date) -> None:
    """Run the full transform pipeline for a given date."""
    raise NotImplementedError("TODO")


def main() -> None:
    """CLI entry point for lantana-transform."""
    run_transform(date.today())

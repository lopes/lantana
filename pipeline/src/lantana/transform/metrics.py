"""Gold metric computation functions."""

from __future__ import annotations

import polars as pl


def compute_daily_summary(silver: pl.LazyFrame) -> pl.DataFrame:
    """Compute daily summary statistics from silver-layer data."""
    raise NotImplementedError("TODO")


def compute_ip_reputation(silver: pl.LazyFrame) -> pl.DataFrame:
    """Compute per-IP reputation scores from enrichment data."""
    raise NotImplementedError("TODO")


def compute_behavioral_progression(silver: pl.LazyFrame) -> pl.DataFrame:
    """Compute attacker behavioral progression metrics."""
    raise NotImplementedError("TODO")


def compute_campaign_clusters(silver: pl.LazyFrame) -> pl.DataFrame:
    """Compute campaign clustering from correlated attack patterns."""
    raise NotImplementedError("TODO")

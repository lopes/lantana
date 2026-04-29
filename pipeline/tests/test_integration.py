"""Integration tests using real VPS data.

These tests read bronze NDJSON produced by scripts/inject-vps-data.py
and replay the full pipeline: normalize, redact, gold, report.
All tests skip when injected data is absent.

Setup:
  1. scripts/fetch-vps-data.sh          # download raw data from VPS
  2. .venv/bin/python scripts/inject-vps-data.py  # write bronze NDJSON
  3. .venv/bin/pytest -m integration -v  # run these tests

Run selectively:  .venv/bin/pytest -m integration -v
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import polars as pl
import pytest

from lantana.common.datalake import read_bronze_ndjson
from lantana.common.redact import RedactionConfig, redact_infrastructure_ips, validate_no_leaks
from lantana.models.normalize import normalize_cowrie, normalize_dataset
from lantana.notify.report import generate_daily_brief, generate_embed_summary
from lantana.transform.metrics import (
    compute_behavioral_progression,
    compute_campaign_clusters,
    compute_daily_summary,
    compute_ip_reputation,
)

LIVE_ROOT = Path(__file__).parent / "fixtures" / "live"
BRONZE_ROOT = LIVE_ROOT / "datalake" / "bronze"

# Enrichment columns that gold metrics reference but won't exist in
# un-enriched data.  Added as typed nulls before gold computation.
_ENRICHMENT_STUBS: dict[str, pl.Expr] = {
    "abuseipdb_confidence_score": pl.lit(None).cast(pl.Int64),
    "greynoise_classification": pl.lit(None).cast(pl.Utf8),
    "greynoise_noise": pl.lit(None).cast(pl.Boolean),
    "geo.country_code": pl.lit(None).cast(pl.Utf8),
    "geo.asn": pl.lit(None).cast(pl.Utf8),
    "geo.isp": pl.lit(None).cast(pl.Utf8),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _discover_dates() -> list[date]:
    """Find all date partitions available in the injected bronze data."""
    dates: set[date] = set()
    for date_dir in BRONZE_ROOT.glob("dataset=*/date=*/"):
        name = date_dir.name
        if name.startswith("date="):
            try:
                dates.add(date.fromisoformat(name[5:]))
            except ValueError:
                continue
    return sorted(dates)


def _discover_datasets() -> list[str]:
    """Find all dataset names available in the injected bronze data."""
    datasets: set[str] = set()
    for ds_dir in BRONZE_ROOT.glob("dataset=*/"):
        name = ds_dir.name
        if name.startswith("dataset="):
            datasets.add(name[8:])
    return sorted(datasets)


def _add_enrichment_stubs(df: pl.DataFrame) -> pl.DataFrame:
    """Add null enrichment columns that gold metrics expect."""
    cols = [expr.alias(name) for name, expr in _ENRICHMENT_STUBS.items() if name not in df.columns]
    if cols:
        df = df.with_columns(cols)
    return df


def _add_missing_silver_columns(df: pl.DataFrame) -> pl.DataFrame:
    """Add null columns that gold metrics may reference but some datasets lack."""
    optional: dict[str, pl.DataType] = {
        "session": pl.Utf8,
        "user_name": pl.Utf8,
        "unmapped_password": pl.Utf8,
        "actor_process_cmd_line": pl.Utf8,
        "finding_title": pl.Utf8,
        "finding_uid": pl.Utf8,
    }
    cols = [
        pl.lit(None).cast(dtype).alias(name)
        for name, dtype in optional.items()
        if name not in df.columns
    ]
    if cols:
        df = df.with_columns(cols)
    return df


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def live_dates() -> list[date]:
    dates = _discover_dates()
    if not dates:
        pytest.skip(
            "No injected bronze data. Run:\n"
            "  scripts/fetch-vps-data.sh\n"
            "  .venv/bin/python scripts/inject-vps-data.py"
        )
    return dates


@pytest.fixture()
def live_datasets() -> list[str]:
    datasets = _discover_datasets()
    if not datasets:
        pytest.skip("No injected bronze data")
    return datasets


@pytest.fixture()
def live_target_date(live_dates: list[date]) -> date:
    """Pick the most recent date with data."""
    return live_dates[-1]


@pytest.fixture()
def live_redact_config() -> RedactionConfig:
    """Redaction config using op_single inventory defaults."""
    return RedactionConfig(
        infrastructure_ips=["10.50.99.1", "10.50.99.10", "10.50.99.100"],
        infrastructure_cidrs=["10.50.99.0/24"],
        pseudonym_map={
            "10.50.99.1": "honeypot-wan",
            "10.50.99.10": "honeypot-collector",
            "10.50.99.100": "honeypot-sensor-01",
        },
    )


@pytest.fixture()
def live_silver(
    live_target_date: date,
    live_datasets: list[str],
    live_redact_config: RedactionConfig,
) -> pl.DataFrame:
    """Build a silver DataFrame from real data: read bronze, normalize, redact, stub enrichment."""
    parts: list[pl.DataFrame] = []

    for dataset in live_datasets:
        df = read_bronze_ndjson(live_target_date, dataset=dataset, bronze_root=BRONZE_ROOT)
        if df.is_empty():
            continue

        normalized = normalize_dataset(df, dataset)
        redacted = redact_infrastructure_ips(normalized, live_redact_config)
        with_stubs = _add_enrichment_stubs(redacted)
        with_cols = _add_missing_silver_columns(with_stubs)
        parts.append(with_cols)

    if not parts:
        pytest.skip(f"No events for {live_target_date}")

    return pl.concat(parts, how="diagonal_relaxed")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration()
class TestIntegration:
    def test_bronze_reads_all_datasets(
        self, live_datasets: list[str], live_target_date: date
    ) -> None:
        """read_bronze_ndjson returns non-empty DataFrames for each dataset."""
        for dataset in live_datasets:
            df = read_bronze_ndjson(live_target_date, dataset=dataset, bronze_root=BRONZE_ROOT)
            assert not df.is_empty(), f"{dataset} bronze is empty for {live_target_date}"

    def test_normalize_real_cowrie(self, live_target_date: date) -> None:
        """OCSF normalization succeeds on real Cowrie events."""
        df = read_bronze_ndjson(live_target_date, dataset="cowrie", bronze_root=BRONZE_ROOT)
        if df.is_empty():
            pytest.skip("No cowrie data for this date")

        result = normalize_cowrie(df)

        assert not result.is_empty()
        assert "class_uid" in result.columns
        assert "src_endpoint_ip" in result.columns
        assert "time" in result.columns
        # Raw columns consumed
        assert "src_ip" not in result.columns
        assert "eventid" not in result.columns
        # Real data should produce multiple OCSF classes
        class_uids = set(result.get_column("class_uid").unique().to_list())
        assert len(class_uids) >= 2, f"Expected 2+ OCSF classes, got {class_uids}"

    def test_normalize_all_datasets(self, live_datasets: list[str], live_target_date: date) -> None:
        """normalize_dataset() succeeds for every available dataset."""
        for dataset in live_datasets:
            df = read_bronze_ndjson(live_target_date, dataset=dataset, bronze_root=BRONZE_ROOT)
            if df.is_empty():
                continue
            result = normalize_dataset(df, dataset)
            assert "class_uid" in result.columns, f"{dataset} missing class_uid"

    def test_redact_real_events(
        self, live_target_date: date, live_redact_config: RedactionConfig
    ) -> None:
        """Redaction + leak validation passes on real events."""
        df = read_bronze_ndjson(live_target_date, dataset="cowrie", bronze_root=BRONZE_ROOT)
        if df.is_empty():
            pytest.skip("No cowrie data")

        normalized = normalize_cowrie(df)
        redacted = redact_infrastructure_ips(normalized, live_redact_config)
        validate_no_leaks(redacted, live_redact_config)

    def test_full_pipeline_to_gold(self, live_silver: pl.DataFrame) -> None:
        """Full bronze-to-gold replay produces non-trivial gold tables."""
        summary = compute_daily_summary(live_silver)
        assert not summary.is_empty()
        row = summary.row(0, named=True)
        assert row["total_events"] > 0
        assert row["unique_source_ips"] > 0

        reputation = compute_ip_reputation(live_silver)
        assert not reputation.is_empty()

        progression = compute_behavioral_progression(live_silver)
        assert not progression.is_empty()
        assert "stage_label" in progression.columns

        # May be empty if no shared credentials — just assert no crash
        compute_campaign_clusters(live_silver)

    def test_report_from_real_data(self, live_silver: pl.DataFrame) -> None:
        """Report generation produces valid Markdown from real data."""
        summary = compute_daily_summary(live_silver)
        reputation = compute_ip_reputation(live_silver)
        progression = compute_behavioral_progression(live_silver)
        clusters = compute_campaign_clusters(live_silver)

        target_date = date.today()
        brief = generate_daily_brief(
            target_date,
            summary,
            reputation,
            progression,
            clusters,
            operation_name="VPS Integration Test",
        )
        assert "# Daily Brief" in brief
        assert "## Key Metrics" in brief
        assert "Total Events" in brief

        embed = generate_embed_summary(target_date, summary, progression)
        assert len(embed) > 0
        assert len(embed) < 4096

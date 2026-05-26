"""Tests for Intel report generation from gold data."""

from __future__ import annotations

from datetime import UTC, date, datetime

import polars as pl

from lantana.notify.report import (
    _fmt_provider_risk,
    _fmt_risk_breakdown,
    generate_daily_brief,
    generate_embed_summary,
)
from lantana.notify.timing import StepTiming


def _ts(minute: int = 0) -> datetime:
    return datetime(2026, 4, 25, 10, minute, 0, tzinfo=UTC)


def _make_summary() -> pl.DataFrame:
    return pl.DataFrame({
        "total_events": [150],
        "unique_source_ips": [12],
        "unique_sessions": [8],
        "auth_attempts": [95],
        "auth_successes": [3],
        "auth_failures": [92],
        "commands_executed": [7],
        "findings_detected": [5],
        "network_events": [43],
        "top_usernames": [[
            {"value": "root", "count": 50},
            {"value": "admin", "count": 30},
            {"value": "test", "count": 10},
        ]],
        "top_passwords": [[
            {"value": "admin", "count": 40},
            {"value": "123456", "count": 25},
            {"value": "password", "count": 15},
        ]],
        "top_commands": [[
            {"value": "uname -a", "count": 8},
            {"value": "cat /etc/passwd", "count": 5},
        ]],
        "top_source_countries": [[
            {"value": "CN", "count": 20},
            {"value": "RU", "count": 10},
            {"value": "US", "count": 5},
        ]],
        "top_source_ips": [[
            {"value": "203.0.113.50", "count": 50},
            {"value": "198.51.100.22", "count": 80},
        ]],
    })


def _make_reputation() -> pl.DataFrame:
    """Reputation fixture covering Phase D.2's enrichment-coverage cases:

    * 203.0.113.50 — fully enriched across all four providers; high composite.
    * 198.51.100.22 — only AbuseIPDB populated; the other three are null.
    * 192.0.2.99 — no enrichment at all (all four providers null); shows the
      "behavioral only, halved" path.
    """
    return pl.DataFrame({
        "src_endpoint_ip": ["203.0.113.50", "198.51.100.22", "192.0.2.99"],
        "risk_score": [87.5, 42.3, 5.0],
        "enrichment_risk_score": [90.0, 73.0, None],
        "behavioral_risk_score": [85.0, 11.6, 10.0],
        "total_events": [50, 80, 20],
        "geo_country": ["CN", "RU", "US"],
        "auth_attempts": [10, 80, 0],
        "auth_successes": [2, 0, 0],
        "commands_executed": [5, 0, 0],
        "findings_triggered": [3, 0, 0],
        "datasets": [["cowrie", "suricata", "nftables"], ["cowrie"], ["nftables"]],
        # Per-provider risk_scores (the four-slot A/V/S/G surfacing).
        "abuseipdb_risk_score": [100.0, 73.0, None],
        "virustotal_risk_score": [75.0, None, None],
        "shodan_risk_score": [100.0, None, None],
        "greynoise_risk_score": [75.0, None, None],
    })


def _make_progression() -> pl.DataFrame:
    return pl.DataFrame({
        "src_endpoint_ip": ["203.0.113.50", "198.51.100.22", "192.0.2.99"],
        "max_stage": [4, 2, 1],
        "stage_label": ["interactive", "credential", "scan"],
        "is_automated": [False, True, False],
        "first_seen": [_ts(0), _ts(5), _ts(8)],
        "last_seen": [_ts(10), _ts(6), _ts(9)],
        "auth_attempts": [10, 80, 0],
        "auth_successes": [2, 0, 0],
        "commands_executed": [5, 0, 0],
    })


def _make_clusters() -> pl.DataFrame:
    return pl.DataFrame({
        "cluster_id": ["abc123"],
        "shared_username": ["root"],
        "shared_password": ["admin"],
        "ip_count": [2],
        "ips": [["203.0.113.50", "198.51.100.22"]],
        "total_events": [15],
        "first_seen": [_ts(0)],
        "last_seen": [_ts(6)],
    })


class TestGenerateDailyBrief:
    def test_contains_date_header(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "2026-04-25" in report
        assert "Test Op" in report

    def test_contains_metrics(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "150" in report  # total_events
        assert "12" in report   # unique IPs

    def test_contains_top_attackers(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "203.0.113.50" in report
        assert "87.5" in report  # risk score

    def test_contains_escalations(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "interactive" in report

    def test_contains_campaign_clusters(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "root" in report
        assert "admin" in report

    def test_contains_mermaid_chart(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "```mermaid" in report

    def test_handles_empty_data(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), pl.DataFrame(), pl.DataFrame(),
            pl.DataFrame(), pl.DataFrame(), "Test Op",
        )
        assert "No data" in report

    def test_returns_string(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert isinstance(report, str)
        assert len(report) > 100


class TestProviderRiskFormatter:
    """`A/V/S/G` per-provider risk_score quadruplet for the Top Attackers row.

    The four-slot fixed shape (one per provider) means an analyst can
    scan a column and see at a glance which provider was offline today
    (the `-` cells) without re-querying the gold table."""

    def test_all_providers_populated(self) -> None:
        assert _fmt_provider_risk({
            "abuseipdb_risk_score": 100.0,
            "virustotal_risk_score": 75.0,
            "shodan_risk_score": 100.0,
            "greynoise_risk_score": 75.0,
        }) == "100/75/100/75"

    def test_all_providers_null_renders_all_dashes(self) -> None:
        assert _fmt_provider_risk({}) == "-/-/-/-"

    def test_partial_population_mixes_numbers_and_dashes(self) -> None:
        assert _fmt_provider_risk({
            "abuseipdb_risk_score": 88.0,
            "virustotal_risk_score": None,
            "shodan_risk_score": None,
            "greynoise_risk_score": None,
        }) == "88/-/-/-"

    def test_floats_render_as_rounded_ints(self) -> None:
        """0..100 ints fit a four-slot table cell better than decimals."""
        assert _fmt_provider_risk({
            "abuseipdb_risk_score": 88.4,
            "virustotal_risk_score": 50.6,
            "shodan_risk_score": 25.0,
            "greynoise_risk_score": 10.0,
        }) == "88/51/25/10"


class TestRiskBreakdownFormatter:
    """`composite (enrichment+behavioral)/2` — the why-this-score cell."""

    def test_full_decomposition_rendered(self) -> None:
        out = _fmt_risk_breakdown({
            "risk_score": 87.5,
            "enrichment_risk_score": 90.0,
            "behavioral_risk_score": 85.0,
        })
        assert out == "87.5 (90+85)/2"

    def test_composite_only_when_sub_scores_missing(self) -> None:
        """Backward-compat for pre-Phase-D.2 gold partitions."""
        assert _fmt_risk_breakdown({"risk_score": 42.3}) == "42.3"

    def test_dash_when_composite_missing(self) -> None:
        assert _fmt_risk_breakdown({}) == "-"

    def test_em_dash_for_missing_subscore(self) -> None:
        """One side present, other absent → keep the layout but mark the gap."""
        out = _fmt_risk_breakdown({
            "risk_score": 50.0,
            "enrichment_risk_score": 100.0,
            "behavioral_risk_score": None,
        })
        assert out == "50.0 (100+—)/2"


class TestReportEnrichmentSurfacing:
    """Phase D.3 verification — the Top Attackers table surfaces each
    provider's score (the A/V/S/G column) AND the composite decomposition
    (the Risk column). An analyst reading the Discord brief can answer
    'why this score?' without leaving the report."""

    def test_top_attackers_table_has_provider_risk_column(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "A/V/S/G" in report
        # Fully-enriched fixture row renders its four scores.
        assert "100/75/100/75" in report
        # AbuseIPDB-only fixture row renders three dashes after the abuseipdb cell.
        assert "73/-/-/-" in report
        # Un-enriched fixture row renders all dashes.
        assert "-/-/-/-" in report

    def test_top_attackers_shows_risk_breakdown(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        # Composite (enrichment + behavioral) layout for the fully-enriched IP.
        assert "87.5 (90+85)/2" in report

    def test_table_includes_legend_explaining_columns(self) -> None:
        """A reader new to the report should be able to decode the columns
        without leaving the brief — the legend line is the discoverability
        contract."""
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "Risk legend:" in report
        assert "A/V/S/G" in report


class TestGenerateEmbedSummary:
    def test_returns_short_summary(self) -> None:
        summary = generate_embed_summary(
            date(2026, 4, 25), _make_summary(), _make_progression(),
        )
        assert isinstance(summary, str)
        assert "150" in summary  # total events
        # Must fit in Discord embed (< 4096 chars)
        assert len(summary) < 4096

    def test_handles_empty_data(self) -> None:
        summary = generate_embed_summary(
            date(2026, 4, 25), pl.DataFrame(), pl.DataFrame(),
        )
        assert "No data" in summary

    def test_clean_health_one_liner(self) -> None:
        """No errors → '✅ Pipeline clean' visible in the embed."""
        from lantana.notify.alerts import ErrorBuckets
        summary = generate_embed_summary(
            date(2026, 4, 25), _make_summary(), _make_progression(),
            buckets=ErrorBuckets(critical=[], warning=[]),
        )
        assert "Pipeline clean" in summary

    def test_critical_health_one_liner(self) -> None:
        """Critical row → '🔴 N critical' visible in the embed."""
        from lantana.notify.alerts import ErrorBuckets
        summary = generate_embed_summary(
            date(2026, 4, 25), _make_summary(), _make_progression(),
            buckets=ErrorBuckets(
                critical=[{"provider": "pipeline", "error_type": "transform_failed", "count": 1}],
                warning=[],
            ),
        )
        assert "critical" in summary.lower()

    def test_info_only_health_one_liner(self) -> None:
        """Info-only day still shows the info count, even though it stays green."""
        from lantana.notify.alerts import ErrorBuckets
        summary = generate_embed_summary(
            date(2026, 4, 25), _make_summary(), _make_progression(),
            buckets=ErrorBuckets(
                critical=[],
                warning=[],
                info=[{"provider": "abuseipdb", "error_type": "rate_limit", "count": 100}],
            ),
        )
        assert "100" in summary
        assert "info" in summary.lower()


class TestPipelineHealthSection:
    def test_clean_renders_no_issues(self) -> None:
        """Clean day: the brief still has a Pipeline Health section with a tick."""
        from lantana.notify.alerts import ErrorBuckets
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
            buckets=ErrorBuckets(critical=[], warning=[]),
        )
        assert "## Pipeline Health" in report
        assert "No issues" in report

    def test_critical_row_renders_in_table(self) -> None:
        from lantana.notify.alerts import ErrorBuckets
        buckets = ErrorBuckets(
            critical=[{
                "provider": "pipeline",
                "error_type": "dataset_processing_failed",
                "count": 1,
                "message": "nft schema mismatch",
            }],
            warning=[],
        )
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
            buckets=buckets,
        )
        assert "## Pipeline Health" in report
        assert "Critical" in report
        assert "dataset_processing_failed" in report
        assert "nft schema mismatch" in report

    def test_three_tier_renders_all_sections(self) -> None:
        from lantana.notify.alerts import ErrorBuckets
        buckets = ErrorBuckets(
            critical=[{
                "provider": "pipeline", "error_type": "transform_failed",
                "count": 1, "message": "boom",
            }],
            warning=[{"provider": "shodan", "error_type": "timeout", "count": 3}],
            info=[{"provider": "abuseipdb", "error_type": "rate_limit", "count": 200}],
        )
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
            buckets=buckets,
        )
        assert "Critical" in report
        assert "Warning" in report
        assert "Info" in report
        assert "rate_limit" in report
        assert "timeout" in report

    def test_section_omitted_when_buckets_none(self) -> None:
        """Backwards-compat: when buckets isn't passed, the section is silent."""
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "Pipeline Health" not in report


def _st(unit: str, dur: float | None, result: str = "success") -> StepTiming:
    """Compact StepTiming builder for tests — keeps fixture lines under 100 chars."""
    return StepTiming(unit=unit, duration_seconds=dur, result=result, finished_at=None)


class TestPipelineTimingSection:
    def test_renders_when_timing_passed(self) -> None:
        timings = [_st("lantana-prune", 24.0), _st("lantana-enrich", 1110.0)]
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
            timing=timings,
        )
        assert "## Pipeline Timing" in report
        assert "prune" in report
        assert "18.5" in report  # enrich minutes

    def test_section_omitted_when_timing_none(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "Pipeline Timing" not in report

    def test_empty_timing_list_omits_section(self) -> None:
        """Same rule as data-presence: empty input → silent skip."""
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
            timing=[],
        )
        assert "Pipeline Timing" not in report


class TestTopNExpansion:
    """Sections capped at top-10 (TOP_N constant) instead of pre-Phase-4's 5/3."""

    def _summary_with_15_usernames(self) -> pl.DataFrame:
        """daily_summary with 15 distinct usernames so the cap is observable."""
        users = [{"value": f"user{i:02d}", "count": 100 - i} for i in range(15)]
        passwords = [{"value": f"pwd{i:02d}", "count": 50 - i} for i in range(15)]
        return _make_summary().with_columns(
            pl.Series("top_usernames", [users]),
            pl.Series("top_passwords", [passwords]),
        )

    def test_top_usernames_capped_at_ten(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), self._summary_with_15_usernames(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        # First 10 must appear; ranks 11+ must not.
        for i in range(10):
            assert f"user{i:02d}" in report
        for i in (10, 11, 12, 13, 14):
            assert f"user{i:02d}" not in report

    def test_top_usernames_rendered_with_rank_table(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), self._summary_with_15_usernames(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        # New rank/item/count header (replaces the pre-Phase-4 inline list).
        assert "| Rank | Username | Count |" in report

    def test_top_attackers_table_has_rank_column(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "| Rank | IP | Risk | Country | Events | Stage | A/V/S/G |" in report

    def test_campaign_clusters_table_has_rank_column(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "| Rank | Credentials | IP Count |" in report
        # IPs no longer crammed into a table column — they live in a
        # rank-numbered list below the table for scannability.
        assert "**IPs by rank:**" in report
        assert "1. 203.0.113.50, 198.51.100.22" in report

    def test_notable_escalations_table_has_rank_column(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "| Rank | IP | Stage | Auth | Commands | Automated |" in report


class TestMalwareSectionVTContext:
    """Malware Captured table joins VT family/type/detections from silver
    onto the gold top_download_hashes list."""

    def _summary_with_hashes(self) -> pl.DataFrame:
        return _make_summary().with_columns(
            pl.Series("downloads_captured", [2]),
            pl.Series("top_download_hashes", [[
                {"value": "a" * 64, "count": 7},
                {"value": "b" * 64, "count": 3},
            ]]),
        )

    def _silver_with_vt(self) -> pl.DataFrame:
        return pl.DataFrame({
            "file_hash_sha256": ["a" * 64, "b" * 64],
            "vt_file_family": ["mirai", ""],
            "vt_file_type": ["elf", "shell"],
            "vt_file_malicious_count": [42, 0],
            "vt_file_risk_score": [100.0, 0.0],
            "file_url": [
                "http://192.0.2.5/loader.sh",
                "http://198.51.100.7/files/payload.bin",
            ],
        })

    def test_malware_table_includes_vt_columns(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), self._summary_with_hashes(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
            silver=self._silver_with_vt(),
        )
        assert "## Malware Captured" in report
        # New header shape: SHA256 + Family + Type + Detections + Risk + URL + Count.
        assert "| Rank | SHA256 | Family | Type | VT Detections | VT Risk | URL | Count |" in report
        # The first hash row carries its VT context.
        assert "mirai" in report
        assert "elf" in report
        assert "42" in report  # detections count for first hash

    def test_malware_table_unknown_hash_shows_question_marks(self) -> None:
        """A top-N hash with no matching silver row falls back to '?' cells."""
        summary = self._summary_with_hashes()
        # Silver covers only 'a'*64; 'b'*64 has no metadata row.
        silver = self._silver_with_vt().filter(pl.col("file_hash_sha256") == "a" * 64)
        report = generate_daily_brief(
            date(2026, 4, 25), summary, _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
            silver=silver,
        )
        # The unenriched row must render with '?' family/type — not crash.
        assert "?" in report

    def test_malware_table_without_silver_still_renders(self) -> None:
        """No silver passed (e.g. cowrie partition absent for the date)."""
        report = generate_daily_brief(
            date(2026, 4, 25), self._summary_with_hashes(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        # Table header is rendered; every metadata column collapses to '?'.
        assert "## Malware Captured" in report
        assert "| Rank | SHA256 | Family | Type" in report

    def test_malware_section_omitted_when_no_downloads(self) -> None:
        """Honeywall-only operation (no cowrie) → downloads_captured=0 → no section."""
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        # _make_summary has no downloads_captured key — section absent.
        assert "## Malware Captured" not in report


class TestIocExportPointer:
    """Phase 0 moves IOC export to the dashboard's STIX Export page.
    The brief stays a reading document and only carries a pointer line."""

    def test_pointer_line_present(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        assert "STIX Export" in report
        assert "dashboard" in report

    def test_no_inline_ioc_sections(self) -> None:
        """No `<details>` blocks, no `## IP Addresses` H2, no `## File Hashes`
        — the long tail is now reachable only via the dashboard."""
        silver = pl.DataFrame({
            "src_endpoint_ip": ["203.0.113.50", "198.51.100.22"],
            "file_hash_sha256": ["a" * 64, "b" * 64],
            "file_url": ["http://example.com/x.sh", "http://example.net/y.bin"],
        })
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
            silver=silver,
        )
        assert "## IP Addresses" not in report
        assert "## File Hashes" not in report
        assert "## Download URLs" not in report
        assert "## Full IOC Inventory" not in report
        assert "<details" not in report


class TestEmbedTimingOneLiner:
    def test_timing_appended_when_provided(self) -> None:
        summary = generate_embed_summary(
            date(2026, 4, 25), _make_summary(), _make_progression(),
            timing=[_st("lantana-enrich", 1110.0)],
        )
        assert "enrich" in summary
        assert "18.5m" in summary

    def test_timing_omitted_when_all_unknown(self) -> None:
        """All-unknown timing (e.g. no systemctl) → no timing line in embed."""
        summary = generate_embed_summary(
            date(2026, 4, 25), _make_summary(), _make_progression(),
            timing=[_st("lantana-enrich", None, result="unknown")],
        )
        # The clock emoji is the timing line's prefix — absent means line was skipped.
        assert "⏱" not in summary

"""Tests for Intel report generation from gold data."""

from __future__ import annotations

from datetime import UTC, date, datetime

import polars as pl

from lantana.notify.report import (
    _fmt_abuseipdb,
    _fmt_shodan,
    _fmt_vt,
    generate_daily_brief,
    generate_embed_summary,
)


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
        "top_usernames": [["root", "admin", "test"]],
        "top_passwords": [["admin", "123456", "password"]],
        "top_commands": [["uname -a", "cat /etc/passwd"]],
        "top_source_countries": [["CN", "RU", "US"]],
        "top_source_ips": [["203.0.113.50", "198.51.100.22"]],
    })


def _make_reputation() -> pl.DataFrame:
    """Reputation fixture covering all three enrichment populations:

    * 203.0.113.50 — fully enriched (AbuseIPDB + VT + Shodan w/ vulns)
    * 198.51.100.22 — AbuseIPDB only (e.g. GN+VT+Shodan skipped or 404)
    * 192.0.2.99 — no enrichment at all (e.g. all providers exhausted)
    """
    return pl.DataFrame({
        "src_endpoint_ip": ["203.0.113.50", "198.51.100.22", "192.0.2.99"],
        "risk_score": [87.5, 42.3, 5.0],
        "total_events": [50, 80, 20],
        "geo_country": ["CN", "RU", "US"],
        "auth_attempts": [10, 80, 0],
        "auth_successes": [2, 0, 0],
        "commands_executed": [5, 0, 0],
        "findings_triggered": [3, 0, 0],
        "datasets": [["cowrie", "suricata", "nftables"], ["cowrie"], ["nftables"]],
        "abuseipdb_score": [100, 73, None],
        "abuseipdb_reports": [685, 12, None],
        "vt_malicious": [13, None, None],
        "shodan_ports": ["22,80,443", None, None],
        "shodan_vulns": ["CVE-2023-1234", None, None],
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


class TestEnrichmentFormatters:
    """Per-provider cell formatters for the Top Attackers table.

    Reports must surface the underlying enrichment signals (AbuseIPDB
    confidence, VT malicious count, Shodan ports + vulns) — the gold
    risk_score blends them and obscures which provider drove the score.
    """

    def test_abuseipdb_fully_populated(self) -> None:
        assert _fmt_abuseipdb({"abuseipdb_score": 100, "abuseipdb_reports": 685}) == "100/685"

    def test_abuseipdb_missing_renders_dash(self) -> None:
        assert _fmt_abuseipdb({}) == "-"
        assert _fmt_abuseipdb({"abuseipdb_score": None, "abuseipdb_reports": None}) == "-"

    def test_abuseipdb_partial_populated_treats_missing_as_zero(self) -> None:
        """Partial population (score but no reports, or vice versa) shouldn't drop the cell."""
        assert _fmt_abuseipdb({"abuseipdb_score": 50, "abuseipdb_reports": None}) == "50/0"
        assert _fmt_abuseipdb({"abuseipdb_score": None, "abuseipdb_reports": 42}) == "0/42"

    def test_vt_populated(self) -> None:
        assert _fmt_vt({"vt_malicious": 13}) == "13"

    def test_vt_zero_is_shown_not_dashed(self) -> None:
        """vt_malicious=0 is a meaningful signal (IP is known to VT, just clean) — show it."""
        assert _fmt_vt({"vt_malicious": 0}) == "0"

    def test_vt_missing_renders_dash(self) -> None:
        assert _fmt_vt({}) == "-"
        assert _fmt_vt({"vt_malicious": None}) == "-"

    def test_shodan_ports_only(self) -> None:
        assert _fmt_shodan({"shodan_ports": "22,80,443", "shodan_vulns": None}) == "3p"

    def test_shodan_ports_plus_cve(self) -> None:
        assert _fmt_shodan(
            {"shodan_ports": "22,80,443", "shodan_vulns": "CVE-2023-1234,CVE-2024-5678"},
        ) == "3p+CVE"

    def test_shodan_no_ports_no_vulns(self) -> None:
        """Empty Shodan response (200 but no scan data) still distinct from totally-missing."""
        assert _fmt_shodan({"shodan_ports": "", "shodan_vulns": None}) == "-"

    def test_shodan_missing_renders_dash(self) -> None:
        assert _fmt_shodan({}) == "-"


class TestReportEnrichmentSurfacing:
    """Bug from 2026-05-22: report consumed gold but never surfaced raw
    AbuseIPDB / VT / Shodan signals; operator observation 'I don't recall
    seeing Shodan data before' was correct. Verify the columns now appear."""

    def test_top_attackers_table_has_enrichment_columns(self) -> None:
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        # Header row must include the three new columns.
        assert "AbuseIPDB" in report
        assert "VT" in report
        assert "Shodan" in report
        # The fully-enriched fixture IP renders with its concrete values.
        assert "100/685" in report   # AbuseIPDB score/reports
        assert "| 13 |" in report    # VT malicious count cell
        assert "3p+CVE" in report    # Shodan ports + CVE marker

    def test_missing_enrichment_renders_dash_not_zero(self) -> None:
        """The unenriched fixture row (192.0.2.99) must show `-`, not misleading `0`."""
        report = generate_daily_brief(
            date(2026, 4, 25), _make_summary(), _make_reputation(),
            _make_progression(), _make_clusters(), "Test Op",
        )
        # Find the line for 192.0.2.99 and confirm all three cells are dashed.
        unenriched_line = next(
            line for line in report.splitlines() if "192.0.2.99" in line
        )
        # Three trailing dashes for the three enrichment columns.
        assert unenriched_line.count("| - ") >= 3


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

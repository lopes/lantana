"""Tests for Intel report generation from gold data."""

from __future__ import annotations

from datetime import UTC, date, datetime

import polars as pl

from lantana.notify.report import generate_daily_brief, generate_embed_summary


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

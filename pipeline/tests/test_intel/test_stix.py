"""Tests for STIX 2.1 bundle generation from gold data."""

from __future__ import annotations

from datetime import UTC, date, datetime

import polars as pl
import stix2

from lantana.common.config import (
    OperationConfig,
    OperatorConfig,
    RedactConfig,
    ReportingConfig,
    SharingConfig,
)
from lantana.intel.stix import generate_bundle


def _ts(minute: int = 0) -> datetime:
    return datetime(2026, 4, 25, 10, minute, 0, tzinfo=UTC)


def _reporting() -> ReportingConfig:
    return ReportingConfig(
        operator=OperatorConfig(
            name="Test Operator", handle="test_op",
            contact="https://test.example.com", pgp_fingerprint="AABB",
        ),
        sharing=SharingConfig(
            tlp="GREEN", community="Test Community",
            discord_channel="test-intel",
        ),
        operation=OperationConfig(
            name="Test Operation", description="Test honeypot",
            sector="Technology", region="US", start_date="2026-01-01",
        ),
        redact=RedactConfig(
            infrastructure_ips=["10.50.99.100"],
            infrastructure_cidrs=["10.50.99.0/24"],
            pseudonym_map={"10.50.99.100": "honeypot-sensor-01"},
        ),
    )


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
        "first_seen": [_ts(0), _ts(5), _ts(8)],
        "last_seen": [_ts(10), _ts(6), _ts(9)],
    })


def _make_progression() -> pl.DataFrame:
    return pl.DataFrame({
        "src_endpoint_ip": ["203.0.113.50", "198.51.100.22", "192.0.2.99"],
        "max_stage": [4, 2, 1],
        "stage_label": ["interactive", "credential", "scan"],
        "is_automated": [False, True, False],
        "first_seen": [_ts(0), _ts(5), _ts(8)],
        "last_seen": [_ts(10), _ts(6), _ts(9)],
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


class TestGenerateBundle:
    def test_returns_valid_bundle(self) -> None:
        """generate_bundle returns a STIX Bundle."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        assert isinstance(bundle, stix2.Bundle)
        assert len(bundle.objects) > 0

    def test_contains_identity(self) -> None:
        """Bundle contains an Identity for the operator."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        identities = [o for o in bundle.objects if o.type == "identity"]
        assert len(identities) == 1
        assert identities[0].name == "Test Operator"

    def test_contains_indicators_for_risky_ips(self) -> None:
        """Bundle has Indicator objects for IPs above risk threshold."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        # 203.0.113.50 (87.5) and 198.51.100.22 (42.3) are above default threshold
        indicator_names = [i.name for i in indicators]
        assert "203.0.113.50" in indicator_names
        assert "198.51.100.22" in indicator_names
        # 192.0.2.99 (5.0) is below threshold
        assert "192.0.2.99" not in indicator_names

    def test_indicator_has_pattern(self) -> None:
        """Indicators have valid STIX patterns."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        for ind in indicators:
            assert "ipv4-addr:value" in ind.pattern

    def test_contains_campaign_from_clusters(self) -> None:
        """Bundle has Campaign objects from credential clusters."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        campaigns = [o for o in bundle.objects if o.type == "campaign"]
        assert len(campaigns) >= 1
        assert "root:admin" in campaigns[0].name

    def test_contains_relationships(self) -> None:
        """Bundle has Relationship objects linking indicators to campaigns."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        relationships = [o for o in bundle.objects if o.type == "relationship"]
        assert len(relationships) > 0

    def test_contains_report(self) -> None:
        """Bundle contains a Report wrapping all objects."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        reports = [o for o in bundle.objects if o.type == "report"]
        assert len(reports) == 1
        assert "2026-04-25" in reports[0].name

    def test_no_infrastructure_ips(self) -> None:
        """OPSEC: no infrastructure IPs appear anywhere in the bundle."""
        reporting = _reporting()
        bundle = generate_bundle(
            date(2026, 4, 25), reporting,
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        bundle_str = bundle.serialize()
        for ip in reporting.redact.infrastructure_ips:
            assert ip not in bundle_str, f"Infrastructure IP {ip} leaked into STIX bundle"

    def test_has_tlp_marking(self) -> None:
        """Indicators reference TLP marking from config."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            _make_reputation(), _make_progression(), _make_clusters(),
        )
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        assert len(indicators) > 0
        # All indicators should have object_marking_refs
        for ind in indicators:
            assert hasattr(ind, "object_marking_refs")
            assert len(ind.object_marking_refs) > 0

    def test_empty_data_returns_minimal_bundle(self) -> None:
        """Empty gold data still produces a valid bundle with identity."""
        bundle = generate_bundle(
            date(2026, 4, 25), _reporting(),
            pl.DataFrame(), pl.DataFrame(), pl.DataFrame(),
        )
        assert isinstance(bundle, stix2.Bundle)
        identities = [o for o in bundle.objects if o.type == "identity"]
        assert len(identities) == 1

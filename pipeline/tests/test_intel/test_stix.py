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
            name="Test Operator",
            handle="test_op",
            contact="https://test.example.com",
            pgp_fingerprint="AABB",
        ),
        sharing=SharingConfig(
            tlp="GREEN",
            community="Test Community",
            discord_channel="test-intel",
        ),
        operation=OperationConfig(
            name="Test Operation",
            description="Test honeypot",
            sector="Technology",
            region="US",
            start_date="2026-01-01",
        ),
        redact=RedactConfig(
            infrastructure_ips=["10.50.99.100"],
            infrastructure_cidrs=["10.50.99.0/24"],
            pseudonym_map={"10.50.99.100": "honeypot-sensor-01"},
        ),
    )


def _make_reputation() -> pl.DataFrame:
    return pl.DataFrame(
        {
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
        }
    )


def _make_progression() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "src_endpoint_ip": ["203.0.113.50", "198.51.100.22", "192.0.2.99"],
            "max_stage": [4, 2, 1],
            "stage_label": ["interactive", "credential", "scan"],
            "is_automated": [False, True, False],
            "first_seen": [_ts(0), _ts(5), _ts(8)],
            "last_seen": [_ts(10), _ts(6), _ts(9)],
        }
    )


def _make_clusters() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "cluster_id": ["abc123"],
            "shared_username": ["root"],
            "shared_password": ["admin"],
            "ip_count": [2],
            "ips": [["203.0.113.50", "198.51.100.22"]],
            "total_events": [15],
            "first_seen": [_ts(0)],
            "last_seen": [_ts(6)],
        }
    )


class TestGenerateBundle:
    def test_returns_valid_bundle(self) -> None:
        """generate_bundle returns a STIX Bundle."""
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
        )
        assert isinstance(bundle, stix2.Bundle)
        assert len(bundle.objects) > 0

    def test_contains_identity(self) -> None:
        """Bundle contains an Identity for the operator."""
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
        )
        identities = [o for o in bundle.objects if o.type == "identity"]
        assert len(identities) == 1
        assert identities[0].name == "Test Operator"

    def test_contains_indicators_for_risky_ips(self) -> None:
        """Bundle has Indicator objects for IPs above risk threshold."""
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
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
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
        )
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        for ind in indicators:
            assert "ipv4-addr:value" in ind.pattern

    def test_contains_campaign_from_clusters(self) -> None:
        """Bundle has Campaign objects from credential clusters."""
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
        )
        campaigns = [o for o in bundle.objects if o.type == "campaign"]
        assert len(campaigns) >= 1
        assert "root:admin" in campaigns[0].name

    def test_contains_relationships(self) -> None:
        """Bundle has Relationship objects linking indicators to campaigns."""
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
        )
        relationships = [o for o in bundle.objects if o.type == "relationship"]
        assert len(relationships) > 0

    def test_contains_report(self) -> None:
        """Bundle contains a Report wrapping all objects."""
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
        )
        reports = [o for o in bundle.objects if o.type == "report"]
        assert len(reports) == 1
        assert "2026-04-25" in reports[0].name

    def test_no_infrastructure_ips(self) -> None:
        """OPSEC: no infrastructure IPs appear anywhere in the bundle."""
        reporting = _reporting()
        bundle = generate_bundle(
            date(2026, 4, 25),
            reporting,
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
        )
        bundle_str = bundle.serialize()
        for ip in reporting.redact.infrastructure_ips:
            assert ip not in bundle_str, f"Infrastructure IP {ip} leaked into STIX bundle"

    def test_has_tlp_marking(self) -> None:
        """Indicators reference TLP marking from config."""
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
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
            date(2026, 4, 25),
            _reporting(),
            pl.DataFrame(),
            pl.DataFrame(),
            pl.DataFrame(),
        )
        assert isinstance(bundle, stix2.Bundle)
        identities = [o for o in bundle.objects if o.type == "identity"]
        assert len(identities) == 1

    def test_ipv6_indicator_pattern_and_tlp_clear(self) -> None:
        """IPv6 addresses emit [ipv6-addr:value = ...] patterns and CLEAR maps to TLP_WHITE."""
        reporting = _reporting()
        reporting.sharing.tlp = "CLEAR"
        rep = _make_reputation().with_columns(
            pl.Series("src_endpoint_ip", ["2001:db8::50", "198.51.100.22", "192.0.2.99"])
        )
        bundle = generate_bundle(
            date(2026, 4, 25),
            reporting,
            rep,
            _make_progression(),
            _make_clusters(),
        )
        indicators = [o for o in bundle.objects if o.type == "indicator"]
        v6_ind = next(i for i in indicators if i.name == "2001:db8::50")
        assert v6_ind.pattern == "[ipv6-addr:value = '2001:db8::50']"
        assert stix2.TLP_WHITE.id in v6_ind.object_marking_refs

    def test_malware_hash_indicator_linked_via_indicates_relationship(self) -> None:
        """File-hash Indicator SDOs connect to Malware SDOs via an 'indicates' Relationship."""
        sha = "f" * 64
        summary = pl.DataFrame(
            {
                "downloads_captured": [1],
                "top_download_hashes": [[{"value": sha, "count": 1}]],
            }
        )
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
            summary=summary,
        )
        malwares = [o for o in bundle.objects if o.type == "malware"]
        hash_inds = [
            o for o in bundle.objects if o.type == "indicator" and o.name == f"file-{sha[:12]}"
        ]
        rels = [
            o
            for o in bundle.objects
            if o.type == "relationship"
            and o.source_ref == hash_inds[0].id
            and o.target_ref == malwares[0].id
        ]
        assert len(malwares) == 1
        assert len(hash_inds) == 1
        assert len(rels) == 1
        assert rels[0].relationship_type == "indicates"
        assert len(rels[0].object_marking_refs) > 0

    def test_infrastructure_ip_leak_raises_value_error(self) -> None:
        """generate_bundle raises ValueError if an infrastructure IP leaks into the bundle."""
        import pytest

        reporting = _reporting()
        leaking_rep = _make_reputation().with_columns(
            pl.Series("src_endpoint_ip", ["10.50.99.100", "198.51.100.22", "192.0.2.99"])
        )
        with pytest.raises(ValueError, match="Infrastructure IP leak"):
            generate_bundle(
                date(2026, 4, 25),
                reporting,
                leaking_rep,
                _make_progression(),
                _make_clusters(),
            )


class TestStixV15DurablePivot:
    """v1.5 STIX 2.1 pivot: durable extracted_iocs, 7d inbound valid_until, behavioral gating,
    zero bogus HTTP patterns, zero benign-scanner Threat Actors, and CIDR/hostname leak checks."""

    def test_durable_extracted_iocs_emit_all_five_types_and_vhash_gti_actors(self) -> None:
        from lantana.transform.metrics import EXTRACTED_IOCS_SCHEMA

        extracted = pl.DataFrame(
            [
                {
                    "ioc_type": "malware_hash",
                    "ioc_value": "a" * 64,
                    "vhash": "014056655d155515",
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 3,
                    "unique_src_ips": 2,
                    "vt_status": "found",
                    "vt_malicious": 35,
                    "gti_verdict": "VERDICT_MALICIOUS",
                    "gti_score": 90,
                    "malware_family": "mirai",
                    "actor_associations": "UNC9999",
                    "verification_status": "verified",
                    "verification_reason": "captured_artifact",
                },
                {
                    "ioc_type": "c2_ip",
                    "ioc_value": "198.51.100.88",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 1,
                    "unique_src_ips": 1,
                    "vt_status": "found",
                    "vt_malicious": 5,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "verified",
                    "verification_reason": "vt_malicious",
                },
                {
                    "ioc_type": "stager_url",
                    "ioc_value": "http://drop.example.org/stage.sh",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 2,
                    "unique_src_ips": 1,
                    "vt_status": "found",
                    "vt_malicious": 2,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "verified",
                    "verification_reason": "vt_malicious",
                },
                {
                    "ioc_type": "stager_domain",
                    "ioc_value": "drop.example.org",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 2,
                    "unique_src_ips": 1,
                    "vt_status": "found",
                    "vt_malicious": 4,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "verified",
                    "verification_reason": "vt_malicious",
                },
                {
                    "ioc_type": "ssh_key",
                    "ioc_value": "ssh-ed25519 SHA256:syntheticFingerprintValue12345",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 1,
                    "unique_src_ips": 1,
                    "vt_status": None,
                    "vt_malicious": None,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "verified",
                    "verification_reason": "captured_artifact",
                },
            ],
            schema=EXTRACTED_IOCS_SCHEMA,
        )
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            _make_reputation(),
            _make_progression(),
            _make_clusters(),
            extracted_iocs=extracted,
        )
        patterns = [o.pattern for o in bundle.objects if o.type == "indicator"]
        assert any("file:hashes.'SHA-256'" in p for p in patterns)
        assert any("ipv4-addr:value = '198.51.100.88'" in p for p in patterns)
        assert any("url:value = 'http://drop.example.org/stage.sh'" in p for p in patterns)
        assert any("domain-name:value = 'drop.example.org'" in p for p in patterns)
        assert any("x-lantana-ssh-key:fingerprint" in p for p in patterns)

        hash_ind = next(
            o for o in bundle.objects if o.type == "indicator" and o.name == f"file-{'a' * 12}"
        )
        assert "vhash:014056655d155515" in hash_ind.labels
        actors = [o for o in bundle.objects if o.type == "threat-actor"]
        assert len(actors) == 1
        assert actors[0].name == "UNC9999"

    def test_inbound_indicators_have_7d_valid_until_and_exclude_scanners_riot_and_benign(
        self,
    ) -> None:
        from datetime import timedelta

        rep = pl.DataFrame(
            {
                "src_endpoint_ip": [
                    "203.0.113.50",  # interactive attacker -> INCLUDE
                    "203.0.113.51",  # pure scanner (behavioral=0) -> EXCLUDE
                    "203.0.113.52",  # RIOT -> EXCLUDE
                    "203.0.113.53",  # GreyNoise benign (Censys) -> EXCLUDE
                ],
                "risk_score": [85.0, 50.0, 60.0, 55.0],
                "behavioral_risk_score": [75.0, 0.0, 50.0, 50.0],
                "enrichment_risk_score": [95.0, 100.0, 0.0, 0.0],
                "greynoise_riot": [False, False, True, False],
                "greynoise_class": ["malicious", "malicious", "malicious", "benign"],
                "greynoise_name": ["Mirai", "Scanner", "Cloudflare", "Censys"],
                "total_events": [20, 5, 5, 5],
                "auth_attempts": [5, 0, 1, 1],
                "auth_successes": [1, 0, 1, 1],
                "commands_executed": [3, 0, 1, 1],
                "findings_triggered": [0, 0, 0, 0],
                "first_seen": [_ts(0)] * 4,
                "last_seen": [_ts(5)] * 4,
            }
        )
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            rep,
            _make_progression(),
            pl.DataFrame(),
        )
        inds = [o for o in bundle.objects if o.type == "indicator"]
        assert [i.name for i in inds] == ["203.0.113.50"]
        assert inds[0].valid_until == datetime(2026, 4, 25, tzinfo=UTC) + timedelta(days=7)
        assert "Mirai" in inds[0].labels
        assert "Censys" not in bundle.serialize()

    def test_detection_findings_do_not_emit_bogus_http_pattern(self) -> None:
        detection = pl.DataFrame(
            {
                "finding_title": ["ET SCAN Potential SSH Scan"],
                "finding_uid": ["2001219"],
                "unique_ips": [25],
                "event_count": [100],
                "category": ["Attempted Information Leak"],
                "first_seen": [_ts(0)],
            }
        )
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            pl.DataFrame(),
            pl.DataFrame(),
            pl.DataFrame(),
            detection=detection,
        )
        assert "http-request-ext" not in bundle.serialize()
        assert [o for o in bundle.objects if o.type == "indicator"] == []

    def test_assert_no_infra_leaks_catches_cidr_variant_and_hostname(self) -> None:
        import pytest

        reporting = _reporting()
        reporting.redact.infrastructure_hostnames = ["vps-secret-node.example.net"]

        # Unlisted member inside 10.50.99.0/24 CIDR
        cidr_rep = _make_reputation().with_columns(
            pl.Series("src_endpoint_ip", ["10.50.99.222", "198.51.100.22", "192.0.2.99"])
        )
        with pytest.raises(ValueError, match="Infrastructure IP leak") as exc_cidr:
            generate_bundle(
                date(2026, 4, 25), reporting, cidr_rep, _make_progression(), _make_clusters()
            )
        assert "10.50.99.222" not in str(exc_cidr.value)

        # Hostname leaked inside campaign cluster username
        host_clusters = _make_clusters().with_columns(
            pl.Series("shared_username", ["vps-secret-node.example.net"])
        )
        with pytest.raises(ValueError, match="Infrastructure hostname leak") as exc_host:
            generate_bundle(
                date(2026, 4, 25), reporting, _make_reputation(), _make_progression(), host_clusters
            )
        assert "vps-secret-node.example.net" not in str(exc_host.value)

    def test_naive_datetime_first_seen_does_not_raise_typeerror(self) -> None:
        """Tz-naive first_seen values (production mixed-dataset Parquet) normalize to UTC."""
        naive_ts = datetime(2026, 4, 25, 14, 0, 1)  # intentionally tz-naive
        rep = _make_reputation().with_columns(pl.lit(naive_ts).alias("first_seen"))
        clusters = _make_clusters().with_columns(pl.lit(naive_ts).alias("first_seen"))
        extracted = pl.DataFrame(
            {
                "ioc_type": ["c2_ip", "malware_hash"],
                "ioc_value": ["203.0.113.88", "a" * 64],
                "vhash": [None, None],
                "first_seen": [naive_ts, naive_ts],
                "last_seen": [naive_ts, naive_ts],
                "event_count": [1, 1],
                "unique_src_ips": [1, 1],
                "vt_status": ["found", None],
                "vt_malicious": [5, None],
                "gti_verdict": [None, None],
                "gti_score": [None, None],
                "malware_family": [None, None],
                "actor_associations": [None, None],
            }
        )
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            rep,
            _make_progression(),
            clusters,
            extracted_iocs=extracted,
        )
        inds = [o for o in bundle.objects if o.type == "indicator"]
        assert len(inds) == 4
        assert all(ind.valid_until > ind.valid_from for ind in inds)


class TestStixAntiPoisoning:
    """Anti-feed-poisoning gating for outbound IOCs in STIX 2.1 bundles."""

    def test_blocks_poisoned_benign_infra_and_unverified_outbound_by_default(self) -> None:
        from lantana.transform.metrics import EXTRACTED_IOCS_SCHEMA

        extracted = pl.DataFrame(
            [
                # Benign DNS resolver -> MUST NOT export even if VT/status were poisoned
                {
                    "ioc_type": "c2_ip",
                    "ioc_value": "1.1.1.1",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 5,
                    "unique_src_ips": 3,
                    "vt_status": "found",
                    "vt_malicious": 10,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "suppressed",
                    "verification_reason": "benign_resolver_ip",
                },
                # Shared hosting apex domain -> MUST NEVER export
                {
                    "ioc_type": "stager_domain",
                    "ioc_value": "raw.githubusercontent.com",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 2,
                    "unique_src_ips": 1,
                    "vt_status": "found",
                    "vt_malicious": 12,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "suppressed",
                    "verification_reason": "shared_hosting_domain",
                },
                # Corroborated path-specific URL on shared hosting -> MUST export
                {
                    "ioc_type": "stager_url",
                    "ioc_value": "https://raw.githubusercontent.com/attacker/repo/main/drop.sh",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 2,
                    "unique_src_ips": 1,
                    "vt_status": "found",
                    "vt_malicious": 4,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "verified",
                    "verification_reason": "vt_malicious",
                },
                # Unverified attacker-typed bank URL -> omitted by default
                {
                    "ioc_type": "stager_url",
                    "ioc_value": "https://legitimate-bank.example/x",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 1,
                    "unique_src_ips": 1,
                    "vt_status": "not_found",
                    "vt_malicious": None,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "unverified",
                    "verification_reason": "uncorroborated",
                },
                # Unverified domain -> omitted by default
                {
                    "ioc_type": "stager_domain",
                    "ioc_value": "legitimate-bank.example",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 1,
                    "unique_src_ips": 1,
                    "vt_status": "not_found",
                    "vt_malicious": None,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "unverified",
                    "verification_reason": "uncorroborated",
                },
            ],
            schema=EXTRACTED_IOCS_SCHEMA,
        )
        bundle = generate_bundle(
            date(2026, 4, 25),
            _reporting(),
            pl.DataFrame(),
            pl.DataFrame(),
            pl.DataFrame(),
            extracted_iocs=extracted,
        )
        inds = [o for o in bundle.objects if o.type == "indicator"]
        assert len(inds) == 1
        assert (
            inds[0].pattern
            == "[url:value = 'https://raw.githubusercontent.com/attacker/repo/main/drop.sh']"
        )
        assert inds[0].confidence == 80
        assert "unverified" not in inds[0].labels
        serialized = bundle.serialize()
        assert "1.1.1.1" not in serialized
        assert "legitimate-bank.example" not in serialized
        assert "domain-name:value = 'raw.githubusercontent.com'" not in serialized

    def test_opt_in_unverified_outbound_tags_label_lower_confidence_and_7d_ttl(self) -> None:
        from datetime import timedelta

        from lantana.common.config import StixExportConfig
        from lantana.transform.metrics import EXTRACTED_IOCS_SCHEMA

        reporting = _reporting()
        reporting.stix = StixExportConfig(
            include_unverified_outbound=True,
            unverified_confidence=20,
        )
        extracted = pl.DataFrame(
            [
                {
                    "ioc_type": "stager_url",
                    "ioc_value": "http://fresh-drop.example.org/payload.sh",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 1,
                    "unique_src_ips": 1,
                    "vt_status": None,
                    "vt_malicious": None,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "unverified",
                    "verification_reason": "uncorroborated",
                },
                {
                    "ioc_type": "stager_url",
                    "ioc_value": "https://raw.githubusercontent.com/org/repo/main/README.md",
                    "vhash": None,
                    "first_seen": _ts(1),
                    "last_seen": _ts(2),
                    "event_count": 1,
                    "unique_src_ips": 1,
                    "vt_status": None,
                    "vt_malicious": None,
                    "gti_verdict": None,
                    "gti_score": None,
                    "malware_family": None,
                    "actor_associations": None,
                    "verification_status": "suppressed",
                    "verification_reason": "shared_hosting_unverified_url",
                },
            ],
            schema=EXTRACTED_IOCS_SCHEMA,
        )
        bundle = generate_bundle(
            date(2026, 4, 25),
            reporting,
            pl.DataFrame(),
            pl.DataFrame(),
            pl.DataFrame(),
            extracted_iocs=extracted,
        )
        inds = [o for o in bundle.objects if o.type == "indicator"]
        assert len(inds) == 1
        ind = inds[0]
        assert ind.pattern == "[url:value = 'http://fresh-drop.example.org/payload.sh']"
        assert "unverified" in ind.labels
        assert ind.confidence == 20
        assert ind.valid_until == datetime(2026, 4, 25, tzinfo=UTC) + timedelta(days=7)

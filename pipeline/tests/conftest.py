"""Shared test fixtures for the Lantana pipeline test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from lantana.common.config import (
    OperationConfig,
    OperatorConfig,
    RedactConfig,
    ReportingConfig,
    SharingConfig,
)


@pytest.fixture()
def sample_bronze_cowrie_ndjson() -> str:
    """Return 3 sample NDJSON lines representing bronze Cowrie events."""
    return (
        '{"timestamp":"2026-04-25T10:00:00","eventid":"cowrie.login.success",'
        '"src_ip":"203.0.113.50","src_port":54321,"dst_ip":"10.50.99.100",'
        '"dst_port":2222,"session":"abc123","protocol":"ssh",'
        '"username":"root","password":"admin","input":"","message":"login attempt",'
        '"sensor":"sensor-01"}\n'
        '{"timestamp":"2026-04-25T10:01:00","eventid":"cowrie.command.input",'
        '"src_ip":"203.0.113.50","src_port":54321,"dst_ip":"10.50.99.100",'
        '"dst_port":2222,"session":"abc123","protocol":"ssh",'
        '"username":"root","password":"","input":"uname -a","message":"CMD: uname -a",'
        '"sensor":"sensor-01"}\n'
        '{"timestamp":"2026-04-25T10:02:00","eventid":"cowrie.login.failed",'
        '"src_ip":"198.51.100.22","src_port":12345,"dst_ip":"10.50.99.100",'
        '"dst_port":2222,"session":"def456","protocol":"ssh",'
        '"username":"admin","password":"password123","input":"","message":"login attempt",'
        '"sensor":"sensor-01"}\n'
    )


@pytest.fixture()
def mock_reporting_config() -> ReportingConfig:
    """Return a ReportingConfig instance populated with test values."""
    return ReportingConfig(
        operator=OperatorConfig(
            name="Test Operator",
            handle="test_handle",
            contact="https://test.example.com",
            pgp_fingerprint="AABBCCDD",
        ),
        sharing=SharingConfig(
            tlp="GREEN",
            community="Test Community",
            discord_channel="test-intel",
        ),
        operation=OperationConfig(
            name="Test Operation",
            description="Test honeypot sensor",
            sector="Technology",
            region="US",
            start_date="2026-01-01",
        ),
        redact=RedactConfig(
            infrastructure_ips=["10.50.99.1", "10.50.99.10", "10.50.99.100"],
            infrastructure_cidrs=["10.50.99.0/24"],
            pseudonym_map={
                "10.50.99.1": "honeypot-wan",
                "10.50.99.10": "honeypot-collector",
                "10.50.99.100": "honeypot-sensor-01",
            },
        ),
    )


@pytest.fixture()
def sample_bronze_suricata_ndjson() -> str:
    """Return sample NDJSON lines representing bronze Suricata events."""
    return (
        '{"timestamp":"2026-04-25T10:00:00","event_type":"alert",'
        '"src_ip":"203.0.113.50","src_port":54321,"dest_ip":"10.50.99.100",'
        '"dest_port":80,"proto":"TCP","alert_signature_id":2001219,'
        '"alert_signature":"ET SCAN Potential SSH Scan",'
        '"alert_category":"Attempted Information Leak","alert_severity":2,'
        '"alert_action":"allowed","flow_id":1234567890}\n'
        '{"timestamp":"2026-04-25T10:01:00","event_type":"alert",'
        '"src_ip":"198.51.100.22","src_port":12345,"dest_ip":"10.50.99.100",'
        '"dest_port":443,"proto":"TCP","alert_signature_id":2024897,'
        '"alert_signature":"ET EXPLOIT Possible CVE-2021-44228",'
        '"alert_category":"Attempted Administrator Privilege Gain","alert_severity":1,'
        '"alert_action":"allowed","flow_id":1234567891}\n'
        '{"timestamp":"2026-04-25T10:02:00","event_type":"flow",'
        '"src_ip":"203.0.113.50","src_port":54321,"dest_ip":"10.50.99.100",'
        '"dest_port":80,"proto":"TCP","alert_signature_id":null,'
        '"alert_signature":null,"alert_category":null,"alert_severity":null,'
        '"alert_action":null,"flow_id":1234567890}\n'
    )


@pytest.fixture()
def sample_bronze_nftables_ndjson() -> str:
    """Return sample NDJSON lines representing bronze nftables events."""
    return (
        '{"timestamp":"2026-04-25T10:00:00","action":"drop",'
        '"chain":"input","src_ip":"203.0.113.50","src_port":54321,'
        '"dst_ip":"10.50.99.100","dst_port":23,"protocol":"tcp",'
        '"interface_in":"eth0","interface_out":"","length":60}\n'
        '{"timestamp":"2026-04-25T10:01:00","action":"accept",'
        '"chain":"input","src_ip":"198.51.100.22","src_port":12345,'
        '"dst_ip":"10.50.99.100","dst_port":22,"protocol":"tcp",'
        '"interface_in":"eth0","interface_out":"","length":52}\n'
    )


@pytest.fixture()
def tmp_datalake(tmp_path: Path) -> Path:
    """Create a temporary datalake directory structure for testing."""
    for layer in ("bronze", "silver", "gold"):
        (tmp_path / layer).mkdir()
    return tmp_path

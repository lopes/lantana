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
def tmp_datalake(tmp_path: Path) -> Path:
    """Create a temporary datalake directory structure for testing."""
    for layer in ("bronze", "silver", "gold"):
        (tmp_path / layer).mkdir()
    return tmp_path

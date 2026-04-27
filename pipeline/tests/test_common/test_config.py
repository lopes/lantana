"""Tests for lantana.common.config."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lantana.common.config import ReportingConfig, SecretsConfig, load_reporting, load_secrets


@pytest.fixture()
def secrets_file(tmp_path: Path) -> Path:
    data = {
        "virustotal": "vt-key-123",
        "shodan": "shodan-key-456",
        "abuseipdb": "abuse-key-789",
        "greynoise": "gn-key-012",
        "phishstats": "ps-key-345",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture()
def reporting_file(tmp_path: Path) -> Path:
    data = {
        "operator": {
            "name": "Test",
            "handle": "test_handle",
            "contact": "https://test.com",
            "pgp_fingerprint": "",
        },
        "sharing": {"tlp": "GREEN", "community": "Test", "discord_channel": "test"},
        "operation": {
            "name": "TestOp",
            "description": "Test",
            "sector": "Tech",
            "region": "US",
            "start_date": "2026-01-01",
        },
        "redact": {
            "infrastructure_ips": ["10.50.99.100"],
            "infrastructure_cidrs": ["10.50.99.0/24"],
            "pseudonym_map": {"10.50.99.100": "honeypot-sensor-01"},
        },
    }
    path = tmp_path / "reporting.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_secrets(secrets_file: Path) -> None:
    """Secrets file parses correctly with all fields."""
    config = load_secrets(secrets_file)
    assert isinstance(config, SecretsConfig)
    assert config.virustotal == "vt-key-123"
    assert config.abuseipdb == "abuse-key-789"
    assert config.discord_webhook == ""  # defaults to empty when not in file


def test_load_secrets_with_discord_webhook(tmp_path: Path) -> None:
    """Secrets file with discord_webhook parses correctly."""
    data = {
        "virustotal": "vt", "shodan": "sh", "abuseipdb": "ab",
        "greynoise": "gn", "phishstats": "ps",
        "discord_webhook": "https://discord.com/api/webhooks/123/abc",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.discord_webhook == "https://discord.com/api/webhooks/123/abc"


def test_load_secrets_missing_key(tmp_path: Path) -> None:
    """Missing API key raises validation error."""
    path = tmp_path / "bad.json"
    path.write_text('{"virustotal": "x"}', encoding="utf-8")
    with pytest.raises(Exception):
        load_secrets(path)


def test_load_reporting(reporting_file: Path) -> None:
    """Reporting file parses correctly with nested structure."""
    config = load_reporting(reporting_file)
    assert isinstance(config, ReportingConfig)
    assert config.operator.handle == "test_handle"
    assert config.sharing.tlp == "GREEN"
    assert config.operation.name == "TestOp"
    assert "10.50.99.100" in config.redact.infrastructure_ips
    assert config.redact.pseudonym_map["10.50.99.100"] == "honeypot-sensor-01"

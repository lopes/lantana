"""Tests for lantana.common.config."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lantana.common.config import (
    ReportingConfig,
    SecretsConfig,
    load_reporting,
    load_secrets,
    load_secrets_tolerant,
)


@pytest.fixture()
def secrets_file(tmp_path: Path) -> Path:
    """Canonical secrets.json — vault-style keys, mirrors the Ansible vault."""
    data = {
        "vault_apikey_virustotal": "vt-key-123",
        "vault_apikey_shodan":     "shodan-key-456",
        "vault_apikey_abuseipdb":  "abuse-key-789",
        "vault_apikey_greynoise":  "gn-key-012",
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
    """Secrets file with discord webhook parses correctly."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan":     "sh",
        "vault_apikey_abuseipdb":  "ab",
        "vault_apikey_greynoise":  "gn",
        "vault_webhook_discord":   "https://discord.com/api/webhooks/123/abc",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.discord_webhook == "https://discord.com/api/webhooks/123/abc"


def test_load_secrets_missing_key(tmp_path: Path) -> None:
    """Missing required API key raises validation error."""
    path = tmp_path / "bad.json"
    path.write_text('{"vault_apikey_virustotal": "x"}', encoding="utf-8")
    with pytest.raises(Exception):
        load_secrets(path)


def test_load_secrets_greynoise_optional(tmp_path: Path) -> None:
    """greynoise is optional and defaults to None when omitted."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan":     "sh",
        "vault_apikey_abuseipdb":  "ab",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.greynoise is None


def test_load_secrets_greynoise_null_means_disabled(tmp_path: Path) -> None:
    """Explicit JSON null disables the provider."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan":     "sh",
        "vault_apikey_abuseipdb":  "ab",
        "vault_apikey_greynoise":  None,
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.greynoise is None


def test_load_secrets_empty_string_means_anonymous(tmp_path: Path) -> None:
    """Empty string keeps the provider enabled in unauthenticated mode."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan":     "sh",
        "vault_apikey_abuseipdb":  "ab",
        "vault_apikey_greynoise":  "",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.greynoise == ""


def test_load_secrets_drops_removed_provider_keys(tmp_path: Path) -> None:
    """Vault keys for removed providers (PhishStats) are silently stripped.

    Operator vault files written when PhishStats existed must still parse.
    """
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan":     "sh",
        "vault_apikey_abuseipdb":  "ab",
        "vault_apikey_phishstats": "leftover-key",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    # The PhishStats key was dropped, the rest parsed fine.
    assert config.virustotal == "vt"
    assert not hasattr(config, "phishstats")


def test_load_secrets_accepts_short_field_names(tmp_path: Path) -> None:
    """populate_by_name=True keeps the short-key form usable (existing fixtures)."""
    data = {
        "virustotal": "vt",
        "shodan":     "sh",
        "abuseipdb":  "ab",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.virustotal == "vt"
    assert config.shodan == "sh"
    assert config.abuseipdb == "ab"


def test_load_secrets_maxmind_optional(tmp_path: Path) -> None:
    """vault_apikey_maxmind is optional and populates SecretsConfig.maxmind."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan":     "sh",
        "vault_apikey_abuseipdb":  "ab",
        "vault_apikey_maxmind":    "mm-license-key",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.maxmind == "mm-license-key"


def test_load_secrets_maxmind_defaults_none(tmp_path: Path) -> None:
    """Omitted maxmind line means the field is None."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan":     "sh",
        "vault_apikey_abuseipdb":  "ab",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.maxmind is None


def test_load_secrets_tolerant_translates_legacy_keys(tmp_path: Path) -> None:
    """Pre-2026-05 vault key names are auto-translated."""
    data = {
        "vault_virustotal_api_key":  "vt",
        "vault_shodan_api_key":      "sh",
        "vault_abuseipdb_api_key":   "ab",
        "vault_greynoise_api_key":   "gn",
        "vault_maxmind_license_key": "mm",
        "vault_discord_webhook_url": "https://discord.com/api/webhooks/x/y",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config, translated = load_secrets_tolerant(path)
    assert translated is True
    assert config.virustotal == "vt"
    assert config.maxmind == "mm"
    assert config.discord_webhook == "https://discord.com/api/webhooks/x/y"


def test_load_secrets_tolerant_passes_canonical_through(tmp_path: Path) -> None:
    """Files already in the canonical form skip translation."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan":     "sh",
        "vault_apikey_abuseipdb":  "ab",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config, translated = load_secrets_tolerant(path)
    assert translated is False
    assert config.virustotal == "vt"


def test_load_reporting(reporting_file: Path) -> None:
    """Reporting file parses correctly with nested structure."""
    config = load_reporting(reporting_file)
    assert isinstance(config, ReportingConfig)
    assert config.operator.handle == "test_handle"
    assert config.sharing.tlp == "GREEN"
    assert config.operation.name == "TestOp"
    assert "10.50.99.100" in config.redact.infrastructure_ips
    assert config.redact.pseudonym_map["10.50.99.100"] == "honeypot-sensor-01"

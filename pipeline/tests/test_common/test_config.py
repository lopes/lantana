"""Tests for lantana.common.config."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from lantana.common.config import (
    ReportingConfig,
    SecretsConfig,
    load_reporting,
    load_secrets,
    load_secrets_tolerant,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture()
def secrets_file(tmp_path: Path) -> Path:
    """Canonical secrets.json — vault-style keys, mirrors the Ansible vault."""
    data = {
        "vault_apikey_virustotal": "vt-key-123",
        "vault_apikey_shodan": "shodan-key-456",
        "vault_apikey_abuseipdb": "abuse-key-789",
        "vault_apikey_greynoise": "gn-key-012",
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
        "vault_apikey_shodan": "sh",
        "vault_apikey_abuseipdb": "ab",
        "vault_apikey_greynoise": "gn",
        "vault_webhook_discord": "https://discord.com/api/webhooks/123/abc",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.discord_webhook == "https://discord.com/api/webhooks/123/abc"


def test_load_secrets_all_provider_keys_optional(tmp_path: Path) -> None:
    """All enrichment provider API keys are optional (zero-key mode works)."""
    path = tmp_path / "empty.json"
    path.write_text("{}", encoding="utf-8")
    config = load_secrets(path)
    assert config.virustotal is None
    assert config.shodan is None
    assert config.abuseipdb is None
    assert config.greynoise is None
    assert config.gti is None
    assert config.gti_enabled is False
    assert config.maxmind is None
    assert config.discord_webhook == ""


def test_load_secrets_gti_opt_in(tmp_path: Path) -> None:
    """Optional GTI key and toggle parse cleanly."""
    path = tmp_path / "gti.json"
    path.write_text(
        json.dumps({"vault_apikey_gti": "SYNTHETIC_TEST_GTI_KEY_000000", "gti_enabled": True}),
        encoding="utf-8",
    )
    config = load_secrets(path)
    assert config.gti == "SYNTHETIC_TEST_GTI_KEY_000000"
    assert config.gti_enabled is True


def test_load_secrets_invalid_type_raises_validation_error(tmp_path: Path) -> None:
    """Malformed field types still fail Pydantic validation."""
    path = tmp_path / "bad.json"
    path.write_text('{"gti_enabled": "not-a-bool"}', encoding="utf-8")
    with pytest.raises(ValidationError):
        load_secrets(path)


def test_load_secrets_greynoise_optional(tmp_path: Path) -> None:
    """greynoise is optional and defaults to None when omitted."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan": "sh",
        "vault_apikey_abuseipdb": "ab",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.greynoise is None


def test_load_secrets_greynoise_null_means_disabled(tmp_path: Path) -> None:
    """Explicit JSON null disables the provider."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan": "sh",
        "vault_apikey_abuseipdb": "ab",
        "vault_apikey_greynoise": None,
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.greynoise is None


def test_load_secrets_empty_string_means_anonymous(tmp_path: Path) -> None:
    """Empty string keeps the provider enabled in unauthenticated mode."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan": "sh",
        "vault_apikey_abuseipdb": "ab",
        "vault_apikey_greynoise": "",
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
        "vault_apikey_shodan": "sh",
        "vault_apikey_abuseipdb": "ab",
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
        "shodan": "sh",
        "abuseipdb": "ab",
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
        "vault_apikey_shodan": "sh",
        "vault_apikey_abuseipdb": "ab",
        "vault_apikey_maxmind": "mm-license-key",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.maxmind == "mm-license-key"


def test_load_secrets_maxmind_defaults_none(tmp_path: Path) -> None:
    """Omitted maxmind line means the field is None."""
    data = {
        "vault_apikey_virustotal": "vt",
        "vault_apikey_shodan": "sh",
        "vault_apikey_abuseipdb": "ab",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config = load_secrets(path)
    assert config.maxmind is None


def test_load_secrets_tolerant_translates_legacy_keys(tmp_path: Path) -> None:
    """Pre-2026-05 vault key names are auto-translated."""
    data = {
        "vault_virustotal_api_key": "vt",
        "vault_shodan_api_key": "sh",
        "vault_abuseipdb_api_key": "ab",
        "vault_greynoise_api_key": "gn",
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
        "vault_apikey_shodan": "sh",
        "vault_apikey_abuseipdb": "ab",
    }
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    config, translated = load_secrets_tolerant(path)
    assert translated is False
    assert config.virustotal == "vt"


def test_load_reporting(reporting_file: Path) -> None:
    """Reporting file parses correctly with nested structure and default stix policy."""
    config = load_reporting(reporting_file)
    assert isinstance(config, ReportingConfig)
    assert config.operator.handle == "test_handle"
    assert config.sharing.tlp == "GREEN"
    assert config.operation.name == "TestOp"
    assert "10.50.99.100" in config.redact.infrastructure_ips
    assert config.redact.pseudonym_map["10.50.99.100"] == "honeypot-sensor-01"
    assert config.stix.include_unverified_outbound is False
    assert config.stix.unverified_confidence == 25
    assert config.stix.allowlist_domains == []
    assert config.stix.allowlist_ips == []


def test_load_reporting_with_stix_policy_overrides(reporting_file: Path) -> None:
    """Optional stix export policy block parses custom allowlists and opt-in toggle."""
    raw = json.loads(reporting_file.read_text(encoding="utf-8"))
    raw["stix"] = {
        "include_unverified_outbound": True,
        "unverified_confidence": 20,
        "allowlist_domains": ["partner.example.org"],
        "allowlist_ips": ["198.51.100.0/24"],
    }
    reporting_file.write_text(json.dumps(raw), encoding="utf-8")
    config = load_reporting(reporting_file)
    assert config.stix.include_unverified_outbound is True
    assert config.stix.unverified_confidence == 20
    assert config.stix.allowlist_domains == ["partner.example.org"]
    assert config.stix.allowlist_ips == ["198.51.100.0/24"]


def test_load_reporting_invalid_stix_confidence_raises(reporting_file: Path) -> None:
    """Out-of-range unverified_confidence fails Pydantic validation."""
    raw = json.loads(reporting_file.read_text(encoding="utf-8"))
    raw["stix"] = {"unverified_confidence": 150}
    reporting_file.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_reporting(reporting_file)


def test_load_reporting_null_stix_block_coerces_to_defaults(reporting_file: Path) -> None:
    """Empty YAML `stix:` (serialized as JSON null) gracefully coerces to StixExportConfig."""
    raw = json.loads(reporting_file.read_text(encoding="utf-8"))
    raw["stix"] = None
    reporting_file.write_text(json.dumps(raw), encoding="utf-8")
    config = load_reporting(reporting_file)
    assert config.stix.include_unverified_outbound is False
    assert config.stix.allowlist_domains == []


def test_load_reporting_invalid_stix_allowlist_entries_fail_fast(reporting_file: Path) -> None:
    """Malformed operator allowlist IPs/CIDRs and domains raise ValidationError instead of
    silently failing open."""
    raw = json.loads(reporting_file.read_text(encoding="utf-8"))
    raw["stix"] = {"allowlist_ips": ["198.51.100.999"]}
    reporting_file.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_reporting(reporting_file)

    raw["stix"] = {"allowlist_domains": ["https://bad-url-not-a-domain.example/x"]}
    reporting_file.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_reporting(reporting_file)

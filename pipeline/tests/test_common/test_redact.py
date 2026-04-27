"""Tests for OPSEC redaction -- the most safety-critical module."""

from __future__ import annotations

import pytest
import polars as pl

from lantana.common.redact import RedactionConfig, redact_infrastructure_ips, validate_no_leaks


@pytest.fixture()
def redaction_config() -> RedactionConfig:
    return RedactionConfig(
        infrastructure_ips=[
            "172.31.99.129",
            "10.50.99.100",
            "10.50.99.10",
            "fd99:10:50:99::100",
        ],
        infrastructure_cidrs=[
            "10.50.99.0/24",
            "fd99:10:50:99::/64",
        ],
        pseudonym_map={
            "172.31.99.129": "honeypot-wan",
            "10.50.99.100": "honeypot-sensor-01",
            "10.50.99.10": "honeypot-collector-01",
            "fd99:10:50:99::100": "honeypot-sensor-01",
        },
    )


def test_redact_replaces_dst_ip(redaction_config: RedactionConfig) -> None:
    """Destination IPs matching infrastructure must be pseudonymized."""
    df = pl.DataFrame({
        "src_ip": ["203.0.113.50", "198.51.100.22"],
        "dst_ip": ["172.31.99.129", "172.31.99.129"],
        "event": ["login", "scan"],
    })
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.get_column("dst_ip").to_list() == ["honeypot-wan", "honeypot-wan"]


def test_redact_preserves_attacker_ips(redaction_config: RedactionConfig) -> None:
    """Source IPs (attacker) must never be modified."""
    df = pl.DataFrame({
        "src_ip": ["203.0.113.50"],
        "dst_ip": ["10.50.99.100"],
    })
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.get_column("src_ip").to_list() == ["203.0.113.50"]
    assert result.get_column("dst_ip").to_list() == ["honeypot-sensor-01"]


def test_redact_handles_missing_dst_columns(redaction_config: RedactionConfig) -> None:
    """DataFrames without destination columns pass through unchanged."""
    df = pl.DataFrame({
        "src_ip": ["203.0.113.50"],
        "event": ["scan"],
    })
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.shape == df.shape


def test_redact_handles_empty_dataframe(redaction_config: RedactionConfig) -> None:
    """Empty DataFrames pass through without error."""
    df = pl.DataFrame()
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.is_empty()


def test_validate_no_leaks_passes_clean_data(redaction_config: RedactionConfig) -> None:
    """Clean data with no infrastructure IPs passes validation."""
    df = pl.DataFrame({
        "src_ip": ["203.0.113.50"],
        "dst_ip": ["honeypot-wan"],
        "event": ["scan"],
    })
    assert validate_no_leaks(df, redaction_config) is True


def test_validate_no_leaks_catches_direct_ip(redaction_config: RedactionConfig) -> None:
    """Validation catches a direct infrastructure IP match."""
    df = pl.DataFrame({
        "src_ip": ["203.0.113.50"],
        "dst_ip": ["172.31.99.129"],
    })
    with pytest.raises(ValueError, match="Infrastructure IP leak"):
        validate_no_leaks(df, redaction_config)


def test_validate_no_leaks_catches_cidr_match(redaction_config: RedactionConfig) -> None:
    """Validation catches IPs within infrastructure CIDRs."""
    df = pl.DataFrame({
        "some_field": ["10.50.99.55"],
    })
    with pytest.raises(ValueError, match="Infrastructure IP leak"):
        validate_no_leaks(df, redaction_config)


def test_validate_no_leaks_ignores_non_ip_strings(redaction_config: RedactionConfig) -> None:
    """Non-IP strings in columns don't trigger false positives."""
    df = pl.DataFrame({
        "event": ["cowrie.login.success"],
        "command": ["uname -a"],
        "username": ["root"],
    })
    assert validate_no_leaks(df, redaction_config) is True

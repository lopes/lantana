"""Tests for OPSEC redaction — the most safety-critical module."""

from __future__ import annotations

import polars as pl
import pytest

from lantana.common.redact import (
    RedactionConfig,
    drop_infrastructure_source_rows,
    redact_infrastructure_ips,
    validate_no_leaks,
)


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
    df = pl.DataFrame(
        {
            "src_ip": ["203.0.113.50", "198.51.100.22"],
            "dst_ip": ["172.31.99.129", "172.31.99.129"],
            "event": ["login", "scan"],
        }
    )
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.get_column("dst_ip").to_list() == ["honeypot-wan", "honeypot-wan"]


def test_redact_preserves_attacker_ips(redaction_config: RedactionConfig) -> None:
    """Source IPs (attacker) must never be modified."""
    df = pl.DataFrame(
        {
            "src_ip": ["203.0.113.50"],
            "dst_ip": ["10.50.99.100"],
        }
    )
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.get_column("src_ip").to_list() == ["203.0.113.50"]
    assert result.get_column("dst_ip").to_list() == ["honeypot-sensor-01"]


def test_redact_handles_missing_dst_columns(redaction_config: RedactionConfig) -> None:
    """DataFrames without destination columns pass through unchanged."""
    df = pl.DataFrame(
        {
            "src_ip": ["203.0.113.50"],
            "event": ["scan"],
        }
    )
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.shape == df.shape


def test_redact_handles_empty_dataframe(redaction_config: RedactionConfig) -> None:
    """Empty DataFrames pass through without error."""
    df = pl.DataFrame()
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.is_empty()


def test_validate_no_leaks_passes_clean_data(redaction_config: RedactionConfig) -> None:
    """Clean data with no infrastructure IPs passes validation."""
    df = pl.DataFrame(
        {
            "src_ip": ["203.0.113.50"],
            "dst_ip": ["honeypot-wan"],
            "event": ["scan"],
        }
    )
    assert validate_no_leaks(df, redaction_config) is True


def test_validate_no_leaks_catches_direct_ip(redaction_config: RedactionConfig) -> None:
    """Validation catches a direct infrastructure IP match."""
    df = pl.DataFrame(
        {
            "src_ip": ["203.0.113.50"],
            "dst_ip": ["172.31.99.129"],
        }
    )
    with pytest.raises(ValueError, match="Infrastructure IP leak"):
        validate_no_leaks(df, redaction_config)


def test_validate_no_leaks_catches_cidr_match(redaction_config: RedactionConfig) -> None:
    """Validation catches IPs within infrastructure CIDRs in IP-typed columns."""
    df = pl.DataFrame(
        {
            "src_ip": ["10.50.99.55"],
        }
    )
    with pytest.raises(ValueError, match="Infrastructure IP leak"):
        validate_no_leaks(df, redaction_config)


def test_validate_no_leaks_ignores_non_ip_strings(redaction_config: RedactionConfig) -> None:
    """Non-IP strings in columns don't trigger false positives."""
    df = pl.DataFrame(
        {
            "event": ["cowrie.login.success"],
            "command": ["uname -a"],
            "username": ["root"],
        }
    )
    assert validate_no_leaks(df, redaction_config) is True


def test_validate_no_leaks_skips_attacker_content_columns(
    redaction_config: RedactionConfig,
) -> None:
    """Attacker-supplied content (passwords, commands) is NOT validated here.

    Cowrie silver for 2026-05-20 was lost when an attacker bruteforced SSH
    using the honeypot's own WAN IP as the password attempt — the value
    landed in ``unmapped_password`` and the previous validator scanned every
    string column, raising ValueError and dropping the whole batch.

    The new contract: redact_infrastructure_ips pseudonymizes content
    columns upstream, validate_no_leaks scopes its check to IP-typed columns
    only. Both invariants together preserve the OPSEC promise without
    false-positiving on attacker noise.
    """
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["203.0.113.50"],
            "dst_endpoint_ip": ["honeypot-wan"],
            "unmapped_password": ["172.31.99.129"],  # attacker's password attempt
            "actor_process_cmd_line": ["nc 10.50.99.55 4444"],
            "message": ["nft drop SRC=203.0.113.50 DST=172.31.99.129"],
        }
    )
    assert validate_no_leaks(df, redaction_config) is True


def test_redact_replaces_wan_in_password(redaction_config: RedactionConfig) -> None:
    """Attacker uses the WAN IP itself as a password attempt — must pseudonymize.

    Real defect #9 from op_alpha 2026-05-20. The value gets exact-matched
    and rewritten to the operator-facing pseudonym; gold's top_passwords can
    safely publish that string.
    """
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["203.0.113.50"],
            "user_name": ["root"],
            "unmapped_password": ["172.31.99.129"],
        }
    )
    result = redact_infrastructure_ips(df, redaction_config)
    assert result.get_column("unmapped_password").to_list() == ["honeypot-wan"]


def test_redact_replaces_wan_substring_in_message(
    redaction_config: RedactionConfig,
) -> None:
    """nftables preserves the raw kernel log in `message` (including DST=<wan>).

    Substring replacement scrubs the embedded address. The OPSEC promise is
    that no operation address survives into shareable output — exact-match
    isn't sufficient for free-text fields.
    """
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["203.0.113.50"],
            "message": ["[LANTANA_INPUT_DROP] SRC=203.0.113.50 DST=172.31.99.129 PROTO=TCP"],
        }
    )
    result = redact_infrastructure_ips(df, redaction_config)
    msg = result.get_column("message").to_list()[0]
    assert "172.31.99.129" not in msg
    assert "honeypot-wan" in msg


# --- drop_infrastructure_source_rows ---


def test_drop_source_rows_filters_wan_origin(redaction_config: RedactionConfig) -> None:
    """Suricata events where src_endpoint_ip is the honeypot WAN are dropped."""
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["203.0.113.50", "172.31.99.129", "198.51.100.22"],
            "dst_endpoint_ip": ["172.31.99.129", "203.0.113.50", "172.31.99.129"],
            "event": ["scan", "outbound-response", "scan"],
        }
    )
    result = drop_infrastructure_source_rows(df, redaction_config)
    assert result.height == 2
    assert "172.31.99.129" not in result.get_column("src_endpoint_ip").to_list()


def test_drop_source_rows_handles_src_ip_pre_normalize(
    redaction_config: RedactionConfig,
) -> None:
    """Works on bronze-shaped `src_ip` column too (before normalize rename)."""
    df = pl.DataFrame(
        {
            "src_ip": ["203.0.113.50", "172.31.99.129"],
            "event": ["scan", "outbound-response"],
        }
    )
    result = drop_infrastructure_source_rows(df, redaction_config)
    assert result.height == 1
    assert result.get_column("src_ip").to_list() == ["203.0.113.50"]


def test_drop_source_rows_noop_when_no_source_column(
    redaction_config: RedactionConfig,
) -> None:
    """DataFrames without a recognised source column pass through unchanged."""
    df = pl.DataFrame({"event": ["scan", "scan"], "command": ["uname", "ls"]})
    result = drop_infrastructure_source_rows(df, redaction_config)
    assert result.height == 2


def test_drop_source_rows_noop_when_no_infra_match(
    redaction_config: RedactionConfig,
) -> None:
    """Pure attacker traffic is not affected."""
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["203.0.113.50", "198.51.100.22"],
            "event": ["scan", "login"],
        }
    )
    result = drop_infrastructure_source_rows(df, redaction_config)
    assert result.height == 2
    assert result.equals(df)


def test_drop_source_rows_handles_ipv6_infrastructure(
    redaction_config: RedactionConfig,
) -> None:
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["fd99:10:50:99::100", "2001:db8:1::beef"],
            "event": ["outbound-response", "scan"],
        }
    )
    result = drop_infrastructure_source_rows(df, redaction_config)
    assert result.height == 1
    assert result.get_column("src_endpoint_ip").to_list() == ["2001:db8:1::beef"]


def test_drop_source_rows_drops_expanded_ipv6_in_cidr(
    redaction_config: RedactionConfig,
) -> None:
    """Expanded-form IPv6 in infrastructure_cidrs must be dropped.

    The Linux kernel writes IPv6 in fully-expanded form
    (fd99:0010:0050:0099:0000:0000:0000:0100). That string is not in
    infrastructure_ips (which stores the compressed form fd99:10:50:99::100),
    so exact-match alone misses it. CIDR membership via ipaddress.ip_address()
    handles the format mismatch.

    Defect from op_alpha 2026-06-08: Dionaea output responses slipped through
    because the kernel logged the sensor's ULA address in expanded form.
    """
    df = pl.DataFrame(
        {
            "src_endpoint_ip": [
                "fd99:0010:0050:0099:0000:0000:0000:0100",
                "2001:db8:1::beef",
            ],
            "event": ["outbound-response", "scan"],
        }
    )
    result = drop_infrastructure_source_rows(df, redaction_config)
    assert result.height == 1
    assert result.get_column("src_endpoint_ip").to_list() == ["2001:db8:1::beef"]


def test_drop_source_rows_empty_dataframe(redaction_config: RedactionConfig) -> None:
    df = pl.DataFrame(
        schema={"src_endpoint_ip": pl.Utf8, "event": pl.Utf8},
    )
    result = drop_infrastructure_source_rows(df, redaction_config)
    assert result.height == 0

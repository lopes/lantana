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


def test_substring_redact_longest_prefix_first_and_destfile() -> None:
    """Longer IP prefix (10.50.99.100) is replaced before shorter prefix (10.50.99.1),
    and destfile / file_name columns are scrubbed."""
    cfg = RedactionConfig(
        infrastructure_ips=["10.50.99.1", "10.50.99.100"],
        infrastructure_cidrs=["10.50.99.0/24"],
        pseudonym_map={
            "10.50.99.1": "honeywall-gw",
            "10.50.99.100": "sensor-node",
        },
    )
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["203.0.113.50"],
            "message": ["connect from 10.50.99.100 via gateway 10.50.99.1"],
            "destfile": ["/tmp/10.50.99.100.bin"],
            "file_name": ["upload_10.50.99.100.elf"],
        }
    )
    result = redact_infrastructure_ips(df, cfg)
    row = result.row(0, named=True)
    assert row["message"] == "connect from sensor-node via gateway honeywall-gw"
    assert "honeywall-gw00" not in row["message"]
    assert row["destfile"] == "/tmp/sensor-node.bin"
    assert row["file_name"] == "upload_sensor-node.elf"


def test_redact_expanded_ipv6_and_unmapped_cidr_passes_validate_no_leaks(
    redaction_config: RedactionConfig,
) -> None:
    """Expanded IPv6 and unmapped subnet IPs in dst_endpoint_ip are redacted cleanly."""
    from lantana.common.redact import validate_no_leaks

    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["203.0.113.50", "198.51.100.22"],
            "dst_endpoint_ip": [
                "fd99:0010:0050:0099:0000:0000:0000:0100",
                "10.50.99.250",
            ],
        }
    )
    redacted = redact_infrastructure_ips(df, redaction_config)
    assert validate_no_leaks(redacted, redaction_config) is True
    dst_vals = redacted.get_column("dst_endpoint_ip").to_list()
    assert dst_vals[1] == "redacted-infra"
    assert "fd99:0010:0050:0099:0000:0000:0000:0100" not in dst_vals


def test_redact_non_dotted_wan_variants_and_hostnames_and_suricata_payloads() -> None:
    """Non-dotted IPv4/PTR variants, expanded IPv6, and VPS hostnames are scrubbed across all
    attacker-content columns including Suricata payload/http-body fields."""
    cfg = RedactionConfig(
        infrastructure_ips=["203.0.113.97", "2001:db8:205:200::8382"],
        infrastructure_cidrs=["10.50.99.0/24"],
        pseudonym_map={
            "203.0.113.97": "honeypot-wan",
            "2001:db8:205:200::8382": "honeypot-wan-v6",
        },
        infrastructure_hostnames=["vps-test-01.example.net", "sn-test-01"],
    )
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["198.51.100.10"],
            "actor_process_cmd_line": [
                "echo 203_0_113_97 203-0-113-97 97.113.0.203 97.ip-203-0-113 "
                "VPS-TEST-01.EXAMPLE.NET"
            ],
            "payload-printable": [
                "GET / HTTP/1.1\r\nHost: 97.ip-203-0-113.example.org\r\n"
                "X-Node: sn-test-01 2001:0db8:0205:0200:0000:0000:0000:8382"
            ],
            "http-body-printable": ["target=203-0-113-97"],
        }
    )
    out = redact_infrastructure_ips(df, cfg).row(0, named=True)
    for col in ("actor_process_cmd_line", "payload-printable", "http-body-printable"):
        val = out[col]
        for forbidden in (
            "203.0.113.97",
            "203_0_113_97",
            "203-0-113-97",
            "97.113.0.203",
            "97.ip-203-0-113",
            "vps-test-01.example.net",
            "VPS-TEST-01.EXAMPLE.NET",
            "sn-test-01",
            "2001:0db8:0205:0200:0000:0000:0000:8382",
        ):
            assert forbidden not in val, f"{forbidden} leaked in {col}: {val}"
    assert "honeypot-wan" in out["actor_process_cmd_line"]
    assert "honeypot-host" in out["actor_process_cmd_line"]
    assert "honeypot-wan-v6" in out["payload-printable"]


def test_expanded_wan_ipv6_without_cidr_caught_in_drop_and_validate() -> None:
    """Expanded WAN IPv6 (no CIDR) is dropped and caught by validate_no_leaks."""
    cfg = RedactionConfig(
        infrastructure_ips=["2001:db8:205:200::8382"],
        infrastructure_cidrs=[],
        pseudonym_map={"2001:db8:205:200::8382": "honeypot-wan-v6"},
    )
    expanded = "2001:0db8:0205:0200:0000:0000:0000:8382"
    df = pl.DataFrame(
        {
            "src_endpoint_ip": [expanded, "2001:db8:1::beef"],
            "dst_endpoint_ip": ["honeypot-wan-v6", expanded],
        }
    )
    dropped = drop_infrastructure_source_rows(df, cfg)
    assert dropped.height == 1
    assert dropped.get_column("src_endpoint_ip").to_list() == ["2001:db8:1::beef"]

    with pytest.raises(ValueError, match="Infrastructure IP leak") as exc_info:
        validate_no_leaks(dropped, cfg)
    # OPSEC: exception text must NEVER contain the raw leaked IP address
    assert expanded not in str(exc_info.value)
    assert "2001:db8:205:200::8382" not in str(exc_info.value)
    assert "sha256=" in str(exc_info.value)


def test_validate_no_leaks_never_embeds_raw_ipv4_or_cidr_in_error(
    redaction_config: RedactionConfig,
) -> None:
    """OPSEC: raw leaked IPs and CIDRs never appear in ValueError (prevents Discord leak chain)."""
    df_direct = pl.DataFrame({"dst_endpoint_ip": ["172.31.99.129"]})
    with pytest.raises(ValueError, match="Infrastructure IP leak") as exc1:
        validate_no_leaks(df_direct, redaction_config)
    assert "172.31.99.129" not in str(exc1.value)

    df_cidr = pl.DataFrame({"src_endpoint_ip": ["10.50.99.42"]})
    with pytest.raises(ValueError, match="Infrastructure IP leak") as exc2:
        validate_no_leaks(df_cidr, redaction_config)
    assert "10.50.99.42" not in str(exc2.value)
    assert "10.50.99.0/24" not in str(exc2.value)


def test_redact_config_alias_unified() -> None:
    """common.config.RedactConfig and common.redact.RedactionConfig are the same class."""
    from lantana.common.config import RedactConfig

    assert RedactConfig is RedactionConfig


def test_redact_dionaea_http_preview_and_host_headers() -> None:
    """OPSEC: WAN IP / variants inside Dionaea HTTP preview, host, and URI are scrubbed."""
    cfg = RedactionConfig(
        infrastructure_ips=["203.0.113.97"],
        infrastructure_cidrs=["10.50.99.0/24"],
        pseudonym_map={"203.0.113.97": "honeypot-wan"},
        infrastructure_hostnames=["vps-test-01.example.net"],
    )
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["198.51.100.10"],
            "http_host": ["203.0.113.97:80"],
            "http_uri": ["/probe?target=vps-test-01.example.net"],
            "http_body_preview": ['{"target":"203-0-113-97","host":"vps-test-01.example.net"}'],
        }
    )
    out = redact_infrastructure_ips(df, cfg).row(0, named=True)
    for col in ("http_host", "http_uri", "http_body_preview"):
        assert "203.0.113.97" not in out[col]
        assert "203-0-113-97" not in out[col]
        assert "vps-test-01.example.net" not in out[col]


def test_redact_uppercase_ipv6_and_ipv4_mapped_ipv6_and_dionaea_columns() -> None:
    """OPSEC: uppercase IPv6, ::ffff:-mapped IPv4, and Dionaea fields are fully scrubbed."""
    cfg = RedactionConfig(
        infrastructure_ips=["203.0.113.97", "2001:db8:abcd::1"],
        infrastructure_cidrs=["10.50.99.0/24"],
        pseudonym_map={
            "203.0.113.97": "honeypot-wan",
            "2001:db8:abcd::1": "honeypot-wan-v6",
        },
        infrastructure_hostnames=["vps-hidden.example.net"],
    )
    df = pl.DataFrame(
        {
            "src_endpoint_ip": ["::ffff:203.0.113.97", "198.51.100.22"],
            "dst_endpoint_ip": ["honeypot-wan", "::FFFF:203.0.113.97"],
            "actor_process_cmd_line": ["ok", "curl http://[2001:DB8:ABCD::1]/x"],
            "http_content_type": ["text/plain", "application/json; host=203.0.113.97"],
            "src_hostname": ["a", "vps-hidden.example.net"],
            "sql_command": ["SELECT 1", "EXEC xp_cmdshell 'ping ::ffff:203.0.113.97'"],
        }
    )
    dropped = drop_infrastructure_source_rows(df, cfg)
    assert dropped.height == 1
    redacted = redact_infrastructure_ips(dropped, cfg)
    assert validate_no_leaks(redacted, cfg) is True
    row = redacted.row(0, named=True)
    assert row["dst_endpoint_ip"] == "honeypot-wan"
    assert "2001:DB8:ABCD::1" not in row["actor_process_cmd_line"]
    assert "honeypot-wan-v6" in row["actor_process_cmd_line"]
    assert "203.0.113.97" not in row["http_content_type"]
    assert "vps-hidden.example.net" not in row["src_hostname"]
    assert "203.0.113.97" not in row["sql_command"]

    # validate_no_leaks catches unredacted ::ffff: WAN IP in IP columns
    leak_df = pl.DataFrame({"dst_endpoint_ip": ["::ffff:203.0.113.97"]})
    with pytest.raises(ValueError, match="Infrastructure IP leak"):
        validate_no_leaks(leak_df, cfg)

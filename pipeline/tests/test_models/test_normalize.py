"""Tests for OCSF normalization — bronze DataFrame to OCSF columns."""

from __future__ import annotations

import json

import polars as pl
import pytest

from lantana.models.normalize import (
    normalize_cowrie,
    normalize_dataset,
    normalize_dionaea,
    normalize_nftables,
    normalize_suricata,
)
from lantana.models.ocsf import (
    CLASS_AUTHENTICATION,
    CLASS_DETECTION_FINDING,
    CLASS_FILE_ACTIVITY,
    CLASS_NETWORK_ACTIVITY,
    CLASS_PROCESS_ACTIVITY,
    OCSF_VERSION,
    PRODUCT_NAME,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ndjson_to_df(ndjson: str) -> pl.DataFrame:
    """Parse NDJSON string into a Polars DataFrame."""
    records = [json.loads(line) for line in ndjson.strip().splitlines()]
    return pl.DataFrame(records)


# ---------------------------------------------------------------------------
# Cowrie normalization
# ---------------------------------------------------------------------------


class TestNormalizeCowrie:
    def test_login_success_maps_to_authentication(self, sample_bronze_cowrie_ndjson: str) -> None:
        """cowrie.login.success -> class_uid=3002, status_id=1."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        login_success = result.filter(pl.col("message") == "login attempt").filter(
            pl.col("status_id") == 1
        )
        assert login_success.height == 1
        row = login_success.row(0, named=True)
        assert row["class_uid"] == CLASS_AUTHENTICATION
        assert row["category_uid"] == 3
        assert row["user_name"] == "root"
        assert row["auth_protocol"] == "ssh"
        assert row["is_cleartext"] is True

    def test_login_failed_maps_to_authentication_failure(
        self, sample_bronze_cowrie_ndjson: str
    ) -> None:
        """cowrie.login.failed -> class_uid=3002, status_id=2."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        login_failed = result.filter(pl.col("status_id") == 2)
        assert login_failed.height == 1
        row = login_failed.row(0, named=True)
        assert row["class_uid"] == CLASS_AUTHENTICATION
        assert row["user_name"] == "admin"

    def test_command_input_maps_to_process_activity(self, sample_bronze_cowrie_ndjson: str) -> None:
        """cowrie.command.input -> class_uid=1007, cmd_line from input."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        commands = result.filter(pl.col("class_uid") == CLASS_PROCESS_ACTIVITY)
        assert commands.height == 1
        row = commands.row(0, named=True)
        assert row["actor_process_cmd_line"] == "uname -a"

    def test_column_renames(self, sample_bronze_cowrie_ndjson: str) -> None:
        """Bronze columns renamed to OCSF equivalents."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        assert "src_endpoint_ip" in result.columns
        assert "dst_endpoint_ip" in result.columns
        assert "src_endpoint_port" in result.columns
        assert "dst_endpoint_port" in result.columns
        assert "time" in result.columns
        # Original names should not remain
        assert "src_ip" not in result.columns
        assert "dst_ip" not in result.columns
        assert "timestamp" not in result.columns

    def test_metadata_columns(self, sample_bronze_cowrie_ndjson: str) -> None:
        """Every row has OCSF metadata columns."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        assert result.get_column("metadata_version").unique().to_list() == [OCSF_VERSION]
        assert result.get_column("metadata_product_name").unique().to_list() == [PRODUCT_NAME]

    def test_session_preserved(self, sample_bronze_cowrie_ndjson: str) -> None:
        """Session column is preserved for behavioral analysis."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        assert "session" in result.columns

    def test_password_preserved_for_login_events(self, sample_bronze_cowrie_ndjson: str) -> None:
        """Password mapped to unmapped_password for credential intel."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        assert "unmapped_password" in result.columns
        # Raw password column is dropped
        assert "password" not in result.columns
        # Login events have the password value
        login_rows = result.filter(pl.col("class_uid") == CLASS_AUTHENTICATION)
        passwords = login_rows.get_column("unmapped_password").to_list()
        assert "admin" in passwords
        assert "password123" in passwords

    def test_protocol_preserved_for_non_login(self, sample_bronze_cowrie_ndjson: str) -> None:
        """Protocol mapped to connection_info_protocol_name for non-login events."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        assert "connection_info_protocol_name" in result.columns
        # Raw protocol column is dropped
        assert "protocol" not in result.columns
        # Command events get the protocol name
        cmd_rows = result.filter(pl.col("class_uid") == CLASS_PROCESS_ACTIVITY)
        assert cmd_rows.get_column("connection_info_protocol_name").to_list() == ["ssh"]

    def test_file_download_maps_to_file_activity(self, sample_bronze_cowrie_ndjson: str) -> None:
        """cowrie.session.file_download -> class_uid=1001, severity=HIGH."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        downloads = result.filter(pl.col("class_uid") == CLASS_FILE_ACTIVITY)
        assert downloads.height == 1
        row = downloads.row(0, named=True)
        assert row["category_uid"] == 1  # CATEGORY_SYSTEM
        assert row["severity_id"] == 4  # HIGH

    def test_download_hash_preserved(self, sample_bronze_cowrie_ndjson: str) -> None:
        """SHA256 hash mapped to file_hash_sha256; raw shasum column dropped."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        assert "file_hash_sha256" in result.columns
        assert "shasum" not in result.columns
        downloads = result.filter(pl.col("class_uid") == CLASS_FILE_ACTIVITY)
        sha = downloads.get_column("file_hash_sha256").to_list()[0]
        assert sha.startswith("e3b0c44298fc1c")

    def test_download_url_preserved(self, sample_bronze_cowrie_ndjson: str) -> None:
        """Download URL mapped to file_url; raw url/outfile columns dropped."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        assert "file_url" in result.columns
        assert "file_path" in result.columns
        assert "url" not in result.columns
        assert "outfile" not in result.columns
        downloads = result.filter(pl.col("class_uid") == CLASS_FILE_ACTIVITY)
        assert "malware.example.com" in downloads.get_column("file_url").to_list()[0]
        assert downloads.get_column("file_path").to_list()[0] == "/tmp/payload.sh"

    def test_conditional_columns_absent_does_not_crash(self) -> None:
        """Bronze without command/login/file_download rows lacks ``input``, ``username``,
        ``password``, ``protocol``, ``shasum``, ``url``, ``outfile`` — normalize must
        tolerate every absence and emit typed-null OCSF columns. Regression for
        2026-06-10 critical: quiet day with zero ``cowrie.command.*`` events crashed
        the cowrie normaliser on unguarded ``pl.col("input")``.
        """
        df = pl.DataFrame(
            {
                "timestamp": ["2026-06-10T12:00:00Z", "2026-06-10T12:00:01Z"],
                "eventid": ["cowrie.session.connect", "cowrie.session.closed"],
                "src_ip": ["198.51.100.5", "198.51.100.5"],
                "dst_ip": ["203.0.113.10", "203.0.113.10"],
                "src_port": [54321, 54321],
                "dst_port": [22, 22],
                "session": ["abc123", "abc123"],
                "message": ["New connection", "Connection lost"],
                "sensor": ["sn-01", "sn-01"],
            }
        )
        result = normalize_cowrie(df)
        assert result.height == 2
        for col in (
            "actor_process_cmd_line",
            "user_name",
            "unmapped_password",
            "auth_protocol",
            "connection_info_protocol_name",
            "file_hash_sha256",
            "file_url",
            "file_path",
        ):
            assert col in result.columns, f"missing OCSF column: {col}"
            assert result.get_column(col).null_count() == result.height, (
                f"{col} should be all-null when bronze lacks the source field"
            )


# ---------------------------------------------------------------------------
# Suricata normalization
# ---------------------------------------------------------------------------


class TestNormalizeSuricata:
    def test_alert_maps_to_detection_finding(self, sample_bronze_suricata_ndjson: str) -> None:
        """Suricata alerts -> class_uid=2004."""
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_suricata(df)
        alerts = result.filter(pl.col("class_uid") == CLASS_DETECTION_FINDING)
        assert alerts.height == 2
        row = alerts.row(0, named=True)
        assert row["finding_title"] == "ET SCAN Potential SSH Scan"
        assert row["finding_uid"] == "2001219"
        assert row["analytic_name"] == "Suricata"

    def test_non_alert_maps_to_network_activity(self, sample_bronze_suricata_ndjson: str) -> None:
        """Suricata flow events -> class_uid=4001."""
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_suricata(df)
        flows = result.filter(pl.col("class_uid") == CLASS_NETWORK_ACTIVITY)
        assert flows.height == 1

    def test_column_renames(self, sample_bronze_suricata_ndjson: str) -> None:
        """Suricata columns renamed to OCSF equivalents."""
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_suricata(df)
        assert "src_endpoint_ip" in result.columns
        assert "dst_endpoint_ip" in result.columns
        assert "src_ip" not in result.columns
        assert "dest_ip" not in result.columns

    def test_severity_mapping(self, sample_bronze_suricata_ndjson: str) -> None:
        """Suricata alert_severity maps to OCSF severity_id."""
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_suricata(df)
        alerts = result.filter(pl.col("class_uid") == CLASS_DETECTION_FINDING)
        severities = alerts.get_column("severity_id").to_list()
        # alert_severity 1 (high in Suricata) -> severity_id 4, severity 2 -> 3
        assert 4 in severities
        assert 3 in severities

    def test_proto_preserved_as_protocol_name(self, sample_bronze_suricata_ndjson: str) -> None:
        """Suricata proto renamed to connection_info_protocol_name."""
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_suricata(df)
        assert "connection_info_protocol_name" in result.columns
        assert "proto" not in result.columns
        protocols = result.get_column("connection_info_protocol_name").to_list()
        assert all(p == "TCP" for p in protocols)

    def test_alert_category_and_action_preserved(self, sample_bronze_suricata_ndjson: str) -> None:
        """Alert category and action preserved as finding_category/finding_action."""
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_suricata(df)
        assert "finding_category" in result.columns
        assert "finding_action" in result.columns
        # Raw columns dropped
        assert "alert_category" not in result.columns
        assert "alert_action" not in result.columns
        # Alert rows have values
        alerts = result.filter(pl.col("class_uid") == CLASS_DETECTION_FINDING)
        assert "Attempted Information Leak" in alerts.get_column("finding_category").to_list()

    def test_nested_alert_struct_is_flattened(self) -> None:
        """Production Suricata bronze ships ``alert`` as a nested struct.

        Test fixtures pre-flatten the fields, so the runner crashed in
        production with ColumnNotFoundError until _flatten_suricata_alert_struct
        was added. This test pins that behaviour.
        """
        nested = pl.DataFrame(
            {
                "event_type": ["alert", "flow"],
                "src_ip": ["203.0.113.50", "203.0.113.51"],
                "dest_ip": ["10.50.99.100", "10.50.99.100"],
                "proto": ["TCP", "TCP"],
                "alert": [
                    {
                        "severity": 2,
                        "signature": "ET SCAN Potential SSH Scan",
                        "signature_id": 2001219,
                        "category": "Attempted Information Leak",
                        "action": "allowed",
                    },
                    None,
                ],
            }
        )
        result = normalize_suricata(nested)
        alerts = result.filter(pl.col("class_uid") == CLASS_DETECTION_FINDING)
        assert alerts.height == 1
        assert alerts.get_column("finding_title").to_list() == ["ET SCAN Potential SSH Scan"]
        assert alerts.get_column("finding_uid").to_list() == ["2001219"]
        assert alerts.get_column("finding_category").to_list() == ["Attempted Information Leak"]

    def test_missing_alert_column_filled_with_nulls(self) -> None:
        """No `alert` column AND no flat alert_* columns — pure flow data.

        Older or differently-configured Suricata sources may not emit
        alert events at all; the normaliser must still complete and just
        leave the detection columns null on every row.
        """
        flow_only = pl.DataFrame(
            {
                "event_type": ["flow", "flow"],
                "src_ip": ["203.0.113.50", "198.51.100.22"],
                "dest_ip": ["10.50.99.100", "10.50.99.100"],
                "proto": ["TCP", "TCP"],
            }
        )
        result = normalize_suricata(flow_only)
        # All rows classified as network activity (no alerts present)
        assert (result.get_column("class_uid") != CLASS_DETECTION_FINDING).all()
        # finding_title is null for every row
        assert result.get_column("finding_title").null_count() == result.height

    def test_json_encoded_alert_string_is_flattened(self) -> None:
        """``read_bronze_ndjson`` JSON-stringifies dict columns so polars schema
        inference stays stable across heterogeneous rows. The alert flatten
        helper must decode the string back into a Struct before extracting
        subfields, otherwise every silver alert row drops its detection
        metadata even when Suricata populated it.
        """
        stringified = pl.DataFrame(
            {
                "event_type": ["alert"],
                "src_ip": ["203.0.113.50"],
                "dest_ip": ["10.50.99.100"],
                "proto": ["TCP"],
                "alert": [
                    '{"severity": 1, "signature": "ET EXPLOIT Possible CVE-2021-44228",'
                    ' "signature_id": 2024897, "category": "Attempted Administrator'
                    ' Privilege Gain", "action": "allowed"}'
                ],
            }
        )
        result = normalize_suricata(stringified)
        alerts = result.filter(pl.col("class_uid") == CLASS_DETECTION_FINDING)
        assert alerts.height == 1
        assert alerts.get_column("finding_title").to_list() == [
            "ET EXPLOIT Possible CVE-2021-44228"
        ]
        assert alerts.get_column("finding_uid").to_list() == ["2024897"]
        assert alerts.get_column("finding_category").to_list() == [
            "Attempted Administrator Privilege Gain"
        ]


class TestGeoStructFlattening:
    """Vector ships `geo` as a nested struct; transform/metrics expects flat
    `geo.country_code` / `geo.asn` / etc. The dispatch wrapper bridges them.
    """

    def test_nested_geo_struct_is_flattened(self) -> None:
        nested = pl.DataFrame(
            {
                "eventid": ["cowrie.session.connect"],
                "src_ip": ["203.0.113.50"],
                "dst_ip": ["10.50.99.100"],
                "session": ["abc"],
                "protocol": ["ssh"],
                "username": [""],
                "password": [""],
                "input": [""],
                "message": ["new connection"],
                "timestamp": ["2026-05-19T20:48:48Z"],
                "geo": [
                    {
                        "asn": 12345,
                        "isp": "Example ISP",
                        "country_code": "BR",
                        "region_code": "SP",
                        "city": "São Paulo",
                        "latitude": -23.5,
                        "longitude": -46.6,
                        "timezone": "America/Sao_Paulo",
                    }
                ],
            }
        )
        result = normalize_dataset(nested, "cowrie")
        assert "geo" not in result.columns
        for field in (
            "country_code",
            "region_code",
            "city",
            "latitude",
            "longitude",
            "timezone",
            "asn",
            "isp",
        ):
            assert f"geo.{field}" in result.columns
        assert result.get_column("geo.country_code").to_list() == ["BR"]
        assert result.get_column("geo.asn").to_list() == [12345]

    def test_missing_geo_column_fills_nulls(self) -> None:
        """Bronze without any geo enrichment still produces the flat columns
        (typed null) so downstream code can rely on the schema.
        """
        no_geo = pl.DataFrame(
            {
                "eventid": ["cowrie.session.connect"],
                "src_ip": ["203.0.113.50"],
                "dst_ip": ["10.50.99.100"],
                "session": ["abc"],
                "protocol": ["ssh"],
                "username": [""],
                "password": [""],
                "input": [""],
                "message": ["connect"],
                "timestamp": ["2026-05-19T20:48:48Z"],
            }
        )
        result = normalize_dataset(no_geo, "cowrie")
        for field in ("country_code", "asn", "isp"):
            assert f"geo.{field}" in result.columns
            assert result.get_column(f"geo.{field}").null_count() == result.height

    def test_json_encoded_geo_string_is_flattened(self) -> None:
        """``read_bronze_ndjson`` JSON-stringifies nested structs to keep schema
        inference stable across mixed-type rows. The flatten helper must decode
        the string back into a Struct before extracting subfields — otherwise
        every silver row gets null geo even when Vector populated the data.
        """
        stringified = pl.DataFrame(
            {
                "eventid": ["cowrie.session.connect"],
                "src_ip": ["203.0.113.50"],
                "dst_ip": ["10.50.99.100"],
                "session": ["abc"],
                "protocol": ["ssh"],
                "username": [""],
                "password": [""],
                "input": [""],
                "message": ["new connection"],
                "timestamp": ["2026-05-19T20:48:48Z"],
                "geo": [
                    '{"country_code": "BR", "region_code": "SP", "city": "Sao Paulo",'
                    ' "latitude": -23.5, "longitude": -46.6,'
                    ' "timezone": "America/Sao_Paulo", "asn": 12345, "isp": "Example"}'
                ],
            }
        )
        result = normalize_dataset(stringified, "cowrie")
        assert "geo" not in result.columns
        assert result.get_column("geo.country_code").to_list() == ["BR"]
        assert result.get_column("geo.asn").to_list() == [12345]
        assert result.get_column("geo.isp").to_list() == ["Example"]


class TestNormalizeNftablesDefensive:
    def test_unparsed_bronze_returns_empty(self) -> None:
        """When Vector hasn't parsed nftables logs into structured fields,
        bronze only carries metadata + raw `message`. Normaliser returns
        empty rather than crashing on missing columns.
        """
        unparsed = pl.DataFrame(
            {
                "dataset": ["nftables"],
                "host": ["sn-01"],
                "message": ["[chain] IN=eth0 OUT= SRC=203.0.113.50 ..."],
                "timestamp": ["2026-05-19T20:48:00Z"],
            }
        )
        result = normalize_nftables(unparsed)
        assert result.is_empty()

    def test_missing_one_required_field_returns_empty(self) -> None:
        """Even partial parsing (e.g. has action but not chain) is rejected."""
        partial = pl.DataFrame(
            {
                "action": ["drop"],
                "protocol": ["tcp"],
                "src_ip": ["203.0.113.50"],
                "dst_ip": ["10.50.99.100"],
                # chain missing
            }
        )
        result = normalize_nftables(partial)
        assert result.is_empty()


# ---------------------------------------------------------------------------
# Nftables normalization
# ---------------------------------------------------------------------------


class TestNormalizeNftables:
    def test_all_rows_are_network_activity(self, sample_bronze_nftables_ndjson: str) -> None:
        """All nftables events -> class_uid=4001."""
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_nftables(df)
        assert (result.get_column("class_uid") == CLASS_NETWORK_ACTIVITY).all()

    def test_column_renames(self, sample_bronze_nftables_ndjson: str) -> None:
        """Nftables columns renamed to OCSF equivalents."""
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_nftables(df)
        assert "src_endpoint_ip" in result.columns
        assert "dst_endpoint_ip" in result.columns
        assert "src_endpoint_port" in result.columns
        assert "dst_endpoint_port" in result.columns
        assert "src_ip" not in result.columns
        assert "dst_ip" not in result.columns

    def test_action_maps_to_activity_id(self, sample_bronze_nftables_ndjson: str) -> None:
        """Nftables action maps to OCSF activity_id."""
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_nftables(df)
        # drop -> activity_id 5 (Refuse), accept -> activity_id 1 (Open)
        drop_row = result.filter(pl.col("activity_id") == 5)
        assert drop_row.height == 1
        accept_row = result.filter(pl.col("activity_id") == 1)
        assert accept_row.height == 1

    def test_protocol_mapped_to_name_and_number(self, sample_bronze_nftables_ndjson: str) -> None:
        """Protocol preserved as name and mapped to IANA number."""
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_nftables(df)
        assert "connection_info_protocol_name" in result.columns
        assert "connection_info_protocol_num" in result.columns
        assert "protocol" not in result.columns
        assert all(n == "tcp" for n in result.get_column("connection_info_protocol_name").to_list())
        assert all(n == 6 for n in result.get_column("connection_info_protocol_num").to_list())

    def test_length_mapped_to_traffic_bytes(self, sample_bronze_nftables_ndjson: str) -> None:
        """Packet length mapped to traffic_bytes_in."""
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_nftables(df)
        assert "traffic_bytes_in" in result.columns
        assert "length" not in result.columns
        assert result.get_column("traffic_bytes_in").to_list() == [60, 52]

    def test_interfaces_preserved(self, sample_bronze_nftables_ndjson: str) -> None:
        """Interface columns preserved for network analysis."""
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_nftables(df)
        assert "interface_in" in result.columns
        assert "interface_out" in result.columns


# ---------------------------------------------------------------------------
# Dionaea normalization
# ---------------------------------------------------------------------------


class TestNormalizeDionaea:
    def test_connection_maps_to_network_activity(self, sample_bronze_dionaea_ndjson: str) -> None:
        """Plain connection (no credentials/commands) -> class_uid=4001."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        smb_row = result.filter(pl.col("connection_info_protocol_name") == "smbd")
        assert smb_row.height == 1
        row = smb_row.row(0, named=True)
        assert row["class_uid"] == CLASS_NETWORK_ACTIVITY
        assert row["category_uid"] == 4

    def test_credential_maps_to_authentication(self, sample_bronze_dionaea_ndjson: str) -> None:
        """Event with credential_username -> class_uid=3002."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        auth_rows = result.filter(pl.col("class_uid") == CLASS_AUTHENTICATION)
        assert auth_rows.height == 1
        row = auth_rows.row(0, named=True)
        assert row["user_name"] == "root"
        assert row["unmapped_password"] == "admin"
        assert row["category_uid"] == 3

    def test_ftp_command_maps_to_process_activity(self, sample_bronze_dionaea_ndjson: str) -> None:
        """Event with ftp_command -> class_uid=1007."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        cmd_rows = result.filter(pl.col("class_uid") == CLASS_PROCESS_ACTIVITY)
        assert cmd_rows.height == 1
        row = cmd_rows.row(0, named=True)
        assert row["actor_process_cmd_line"] == "USER anonymous"

    def test_column_renames(self, sample_bronze_dionaea_ndjson: str) -> None:
        """Bronze columns renamed to OCSF equivalents."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        assert "src_endpoint_ip" in result.columns
        assert "dst_endpoint_ip" in result.columns
        assert "src_endpoint_port" in result.columns
        assert "dst_endpoint_port" in result.columns
        assert "time" in result.columns
        # Original names should not remain
        assert "src_ip" not in result.columns
        assert "dst_ip" not in result.columns
        assert "timestamp" not in result.columns

    def test_metadata_columns(self, sample_bronze_dionaea_ndjson: str) -> None:
        """Every row has OCSF metadata columns."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        assert result.get_column("metadata_version").unique().to_list() == [OCSF_VERSION]
        assert result.get_column("metadata_product_name").unique().to_list() == [PRODUCT_NAME]

    def test_protocol_preserved(self, sample_bronze_dionaea_ndjson: str) -> None:
        """connection_protocol preserved as connection_info_protocol_name."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        assert "connection_info_protocol_name" in result.columns
        assert "connection_protocol" not in result.columns
        protocols = result.get_column("connection_info_protocol_name").to_list()
        assert "smbd" in protocols
        assert "mysqld" in protocols
        assert "ftpd" in protocols

    def test_transport_preserved(self, sample_bronze_dionaea_ndjson: str) -> None:
        """connection_transport preserved for network analysis."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        assert "connection_transport" in result.columns

    def test_password_preserved_for_credential_events(
        self, sample_bronze_dionaea_ndjson: str
    ) -> None:
        """credential_password mapped to unmapped_password for credential intel."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        assert "unmapped_password" in result.columns
        assert "credential_password" not in result.columns
        auth_rows = result.filter(pl.col("class_uid") == CLASS_AUTHENTICATION)
        passwords = auth_rows.get_column("unmapped_password").to_list()
        assert "admin" in passwords

    def test_severity_by_event_type(self, sample_bronze_dionaea_ndjson: str) -> None:
        """Credentials=MEDIUM, commands=MEDIUM, connections=LOW."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        # Connection event (SMB): LOW=2
        smb = result.filter(pl.col("class_uid") == CLASS_NETWORK_ACTIVITY)
        assert smb.get_column("severity_id").to_list() == [2]
        # Credential event (MySQL): MEDIUM=3
        auth = result.filter(pl.col("class_uid") == CLASS_AUTHENTICATION)
        assert auth.get_column("severity_id").to_list() == [3]
        # Command event (FTP): MEDIUM=3
        cmd = result.filter(pl.col("class_uid") == CLASS_PROCESS_ACTIVITY)
        assert cmd.get_column("severity_id").to_list() == [3]


# ---------------------------------------------------------------------------
# Dataset dispatcher
# ---------------------------------------------------------------------------


class TestNormalizeDataset:
    def test_dispatches_cowrie(self, sample_bronze_cowrie_ndjson: str) -> None:
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_dataset(df, "cowrie")
        assert "class_uid" in result.columns

    def test_dispatches_suricata(self, sample_bronze_suricata_ndjson: str) -> None:
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_dataset(df, "suricata")
        assert "class_uid" in result.columns

    def test_dispatches_nftables(self, sample_bronze_nftables_ndjson: str) -> None:
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_dataset(df, "nftables")
        assert "class_uid" in result.columns

    def test_dispatches_dionaea(self, sample_bronze_dionaea_ndjson: str) -> None:
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dataset(df, "dionaea")
        assert "class_uid" in result.columns

    def test_unknown_dataset_raises(self) -> None:
        df = pl.DataFrame({"x": [1]})
        with pytest.raises(ValueError, match="Unknown dataset"):
            normalize_dataset(df, "unknown")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_dataframe_passes_through(self) -> None:
        """Empty DataFrame returns empty DataFrame."""
        df = pl.DataFrame()
        result = normalize_cowrie(df)
        assert result.is_empty()

    def test_enrichment_columns_preserved(self, sample_bronze_cowrie_ndjson: str) -> None:
        """API enrichment columns are preserved through normalization."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        df = df.with_columns(
            pl.lit(85).alias("abuseipdb_confidence_score"),
            pl.lit("US").alias("geo.country_code"),
        )
        result = normalize_cowrie(df)
        assert "abuseipdb_confidence_score" in result.columns
        assert "geo.country_code" in result.columns

    def test_partition_columns_preserved(self, sample_bronze_cowrie_ndjson: str) -> None:
        """Partition columns (dataset, server, operation) are preserved."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        df = df.with_columns(
            pl.lit("cowrie").alias("dataset"),
            pl.lit("sensor-01").alias("server"),
            pl.lit("op_single").alias("operation"),
        )
        result = normalize_cowrie(df)
        assert "dataset" in result.columns
        assert "server" in result.columns
        assert "operation" in result.columns

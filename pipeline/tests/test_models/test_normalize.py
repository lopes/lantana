"""Tests for OCSF normalization -- bronze DataFrame to OCSF columns."""

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
    def test_login_success_maps_to_authentication(
        self, sample_bronze_cowrie_ndjson: str
    ) -> None:
        """cowrie.login.success -> class_uid=3002, status_id=1."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        login_success = result.filter(
            pl.col("message") == "login attempt"
        ).filter(pl.col("status_id") == 1)
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

    def test_command_input_maps_to_process_activity(
        self, sample_bronze_cowrie_ndjson: str
    ) -> None:
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

    def test_password_preserved_for_login_events(
        self, sample_bronze_cowrie_ndjson: str
    ) -> None:
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

    def test_protocol_preserved_for_non_login(
        self, sample_bronze_cowrie_ndjson: str
    ) -> None:
        """Protocol mapped to connection_info_protocol_name for non-login events."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        result = normalize_cowrie(df)
        assert "connection_info_protocol_name" in result.columns
        # Raw protocol column is dropped
        assert "protocol" not in result.columns
        # Command events get the protocol name
        cmd_rows = result.filter(pl.col("class_uid") == CLASS_PROCESS_ACTIVITY)
        assert cmd_rows.get_column("connection_info_protocol_name").to_list() == ["ssh"]


# ---------------------------------------------------------------------------
# Suricata normalization
# ---------------------------------------------------------------------------


class TestNormalizeSuricata:
    def test_alert_maps_to_detection_finding(
        self, sample_bronze_suricata_ndjson: str
    ) -> None:
        """Suricata alerts -> class_uid=2004."""
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_suricata(df)
        alerts = result.filter(pl.col("class_uid") == CLASS_DETECTION_FINDING)
        assert alerts.height == 2
        row = alerts.row(0, named=True)
        assert row["finding_title"] == "ET SCAN Potential SSH Scan"
        assert row["finding_uid"] == "2001219"
        assert row["analytic_name"] == "Suricata"

    def test_non_alert_maps_to_network_activity(
        self, sample_bronze_suricata_ndjson: str
    ) -> None:
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

    def test_proto_preserved_as_protocol_name(
        self, sample_bronze_suricata_ndjson: str
    ) -> None:
        """Suricata proto renamed to connection_info_protocol_name."""
        df = _ndjson_to_df(sample_bronze_suricata_ndjson)
        result = normalize_suricata(df)
        assert "connection_info_protocol_name" in result.columns
        assert "proto" not in result.columns
        protocols = result.get_column("connection_info_protocol_name").to_list()
        assert all(p == "TCP" for p in protocols)

    def test_alert_category_and_action_preserved(
        self, sample_bronze_suricata_ndjson: str
    ) -> None:
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


# ---------------------------------------------------------------------------
# Nftables normalization
# ---------------------------------------------------------------------------


class TestNormalizeNftables:
    def test_all_rows_are_network_activity(
        self, sample_bronze_nftables_ndjson: str
    ) -> None:
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

    def test_action_maps_to_activity_id(
        self, sample_bronze_nftables_ndjson: str
    ) -> None:
        """Nftables action maps to OCSF activity_id."""
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_nftables(df)
        # drop -> activity_id 5 (Refuse), accept -> activity_id 1 (Open)
        drop_row = result.filter(pl.col("activity_id") == 5)
        assert drop_row.height == 1
        accept_row = result.filter(pl.col("activity_id") == 1)
        assert accept_row.height == 1

    def test_protocol_mapped_to_name_and_number(
        self, sample_bronze_nftables_ndjson: str
    ) -> None:
        """Protocol preserved as name and mapped to IANA number."""
        df = _ndjson_to_df(sample_bronze_nftables_ndjson)
        result = normalize_nftables(df)
        assert "connection_info_protocol_name" in result.columns
        assert "connection_info_protocol_num" in result.columns
        assert "protocol" not in result.columns
        assert all(n == "tcp" for n in result.get_column("connection_info_protocol_name").to_list())
        assert all(n == 6 for n in result.get_column("connection_info_protocol_num").to_list())

    def test_length_mapped_to_traffic_bytes(
        self, sample_bronze_nftables_ndjson: str
    ) -> None:
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
    def test_connection_maps_to_network_activity(
        self, sample_bronze_dionaea_ndjson: str
    ) -> None:
        """Plain connection (no credentials/commands) -> class_uid=4001."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        smb_row = result.filter(pl.col("connection_info_protocol_name") == "smbd")
        assert smb_row.height == 1
        row = smb_row.row(0, named=True)
        assert row["class_uid"] == CLASS_NETWORK_ACTIVITY
        assert row["category_uid"] == 4

    def test_credential_maps_to_authentication(
        self, sample_bronze_dionaea_ndjson: str
    ) -> None:
        """Event with credential_username -> class_uid=3002."""
        df = _ndjson_to_df(sample_bronze_dionaea_ndjson)
        result = normalize_dionaea(df)
        auth_rows = result.filter(pl.col("class_uid") == CLASS_AUTHENTICATION)
        assert auth_rows.height == 1
        row = auth_rows.row(0, named=True)
        assert row["user_name"] == "root"
        assert row["unmapped_password"] == "admin"
        assert row["category_uid"] == 3

    def test_ftp_command_maps_to_process_activity(
        self, sample_bronze_dionaea_ndjson: str
    ) -> None:
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

    def test_enrichment_columns_preserved(
        self, sample_bronze_cowrie_ndjson: str
    ) -> None:
        """API enrichment columns are preserved through normalization."""
        df = _ndjson_to_df(sample_bronze_cowrie_ndjson)
        df = df.with_columns(
            pl.lit(85).alias("abuseipdb_confidence_score"),
            pl.lit("US").alias("geo.country_code"),
        )
        result = normalize_cowrie(df)
        assert "abuseipdb_confidence_score" in result.columns
        assert "geo.country_code" in result.columns

    def test_partition_columns_preserved(
        self, sample_bronze_cowrie_ndjson: str
    ) -> None:
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

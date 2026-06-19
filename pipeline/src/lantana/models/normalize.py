"""OCSF normalization — transform bronze DataFrames to OCSF-columned DataFrames.

Pure DataFrame transforms with no IO. Each function maps a dataset's
bronze columns to OCSF equivalents, adds OCSF metadata columns, and
preserves enrichment/partition/geo columns untouched.

Field mapping tables below document every bronze field and its fate:
  - "rename"     = column renamed to OCSF equivalent
  - "map"        = value transformed into an OCSF field
  - "conditional" = mapped only for certain event types, null otherwise
  - "preserve"   = kept as-is (no OCSF equivalent, but useful for intel/correlation)
  - "generate"   = new OCSF column computed from raw data
"""

from __future__ import annotations

import polars as pl

from lantana.models.ocsf import (
    CATEGORY_FINDINGS,
    CATEGORY_IAM,
    CATEGORY_NETWORK,
    CATEGORY_SYSTEM,
    CLASS_AUTHENTICATION,
    CLASS_DETECTION_FINDING,
    CLASS_FILE_ACTIVITY,
    CLASS_NETWORK_ACTIVITY,
    CLASS_PROCESS_ACTIVITY,
    OCSF_VERSION,
    PRODUCT_NAME,
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_UNKNOWN,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    STATUS_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Explicit field mapping tables (raw bronze -> OCSF silver)
#
# Format: raw_field -> (ocsf_field, action, notes)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# File-intent classification
#
# Cowrie's file_download/file_upload events fire for *any* byte transfer
# attackers initiate — not just malware. The vast majority on op_alpha are
# attacker SSH-pubkey drops into ``~/.ssh/authorized_keys`` (persistence)
# or zero-byte / single-char probe writes (probe). Without a tag, gold's
# ``top_download_hashes`` ranks those above real ELF samples — the
# Discord brief reads "120x a8460f44… (SSH pubkey)" as if it were the
# top malware family of the day.
#
# Classification is destfile- and hash-driven so it works without any
# disk-side IO and stays inside the bronze→silver normaliser:
#   * persistence  — destfile points at well-known persistence targets
#                    (`~/.ssh/*`, shell rc/history files, sudoers)
#   * probe        — shasum matches a known-noise sha256 (empty file,
#                    "1\n", etc.) regardless of destfile
#   * malware      — default for any other file_download / file_upload
#                    event (SFTP-uploaded ELF samples land here)
#   * NULL         — non-file events
#
# Why a hash-set rather than a size threshold: normalize.py is a pure
# data transform with no filesystem access (silver writes happen on the
# collector, which in multi-node mode can't stat sensor-side downloads).
# Hash-based probe detection is exact, doesn't depend on the file still
# being on disk, and survives multi-node deployment.
_PERSISTENCE_DESTFILE_REGEX = (
    r"/\.ssh/|/\.bash_history$|/\.bashrc$|/\.bash_profile$|/\.zshrc$|/\.profile$|/sudoers"
)

# sha256 of common attacker probe payloads. Extend conservatively — every
# hash here is a permanent declaration that this content is "not malware",
# so only well-understood noise patterns should land in this set.
_PROBE_SHA256: frozenset[str] = frozenset(
    {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty file
        "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",  # "1\n"
    }
)


COWRIE_FIELD_MAP: dict[str, tuple[str, str, str]] = {
    # --- Renamed (1:1 column rename) ---
    "timestamp": ("time", "rename", "Event timestamp"),
    "src_ip": ("src_endpoint_ip", "rename", "Attacker source IP"),
    "dst_ip": ("dst_endpoint_ip", "rename", "Honeypot destination IP"),
    "src_port": ("src_endpoint_port", "rename", "Attacker source port"),
    "dst_port": ("dst_endpoint_port", "rename", "Honeypot destination port"),
    # --- Conditional (depends on eventid) ---
    "eventid": ("class_uid", "map", "Dispatches to OCSF class; consumed"),
    "username": ("user_name", "conditional", "Login events only; null for others"),
    "password": ("unmapped_password", "conditional", "Login only; credential intel"),
    "input": ("actor_process_cmd_line", "conditional", "Command events only; null for others"),
    "protocol": (
        "auth_protocol / connection_info_protocol_name",
        "conditional",
        "Login: auth_protocol. Others: connection_info_protocol_name",
    ),
    # --- Preserved (no OCSF equivalent) ---
    "session": ("session", "preserve", "Session ID for behavioral progression"),
    "message": ("message", "preserve", "Human-readable event description"),
    "sensor": ("sensor", "preserve", "Source sensor hostname"),
    # --- Generated OCSF metadata ---
    #   class_uid, category_uid, severity_id, activity_id, type_uid,
    #   status_id, metadata_version, metadata_product_name, is_cleartext
}

SURICATA_FIELD_MAP: dict[str, tuple[str, str, str]] = {
    # --- Renamed ---
    "timestamp": ("time", "rename", "Event timestamp"),
    "src_ip": ("src_endpoint_ip", "rename", "Attacker source IP"),
    "dest_ip": ("dst_endpoint_ip", "rename", "Suricata uses dest_ip"),
    "src_port": ("src_endpoint_port", "rename", "Source port"),
    "dest_port": ("dst_endpoint_port", "rename", "Destination port"),
    # --- Mapped ---
    "event_type": ("class_uid", "map", "Dispatches to OCSF class; consumed"),
    "alert_signature": ("finding_title + message", "map", "Alert: finding_title"),
    "alert_signature_id": ("finding_uid", "conditional", "Alert events only; cast to string"),
    "alert_severity": ("severity_id", "map", "Suricata 1=high->4, 2=med->3, 3=low->2"),
    # --- Preserved ---
    "proto": ("connection_info_protocol_name", "rename", "L4 protocol name"),
    "alert_category": ("finding_category", "conditional", "Alert classification"),
    "alert_action": ("finding_action", "conditional", "Allowed/blocked; disposition context"),
    "flow_id": ("flow_id", "preserve", "Flow tracking ID for session correlation"),
}

NFTABLES_FIELD_MAP: dict[str, tuple[str, str, str]] = {
    # --- Renamed ---
    "timestamp": ("time", "rename", "Event timestamp"),
    "src_ip": ("src_endpoint_ip", "rename", "Source IP"),
    "dst_ip": ("dst_endpoint_ip", "rename", "Destination IP"),
    "src_port": ("src_endpoint_port", "rename", "Source port"),
    "dst_port": ("dst_endpoint_port", "rename", "Destination port"),
    # --- Mapped ---
    "action": ("activity_id + message", "map", "accept->1(Open), drop/reject->5(Refuse)"),
    "chain": ("message", "map", "Combined with action into message; consumed"),
    "protocol": (
        "connection_info_protocol_num + connection_info_protocol_name",
        "map",
        "Name preserved, also mapped to IANA number",
    ),
    # --- Preserved ---
    "interface_in": ("interface_in", "preserve", "Ingress interface"),
    "interface_out": ("interface_out", "preserve", "Egress interface"),
    "length": ("traffic_bytes_in", "rename", "Packet length -> traffic bytes"),
}

# Common fields added by Vector (preserved as-is through normalization):
#   dataset, server, operation,
#   geo.country_code, geo.region_code, geo.city, geo.latitude, geo.longitude,
#   geo.timezone, geo.asn, geo.isp
#
# API enrichment fields (preserved as-is):
#   abuseipdb_*, greynoise_*, shodan_*, virustotal_*


def normalize_cowrie(df: pl.DataFrame) -> pl.DataFrame:
    """Normalize bronze Cowrie events to OCSF columns.

    Event dispatch:
    - cowrie.login.*                -> Authentication (3002)
    - cowrie.command.*              -> Process Activity (1007)
    - cowrie.session.file_download  -> File Activity (1001), activity_id=2 (Read)
    - cowrie.session.file_upload    -> File Activity (1001), activity_id=1 (Create)
    - other                         -> Network Activity (4001)
    """
    if df.is_empty():
        return df

    eventid_col = pl.col("eventid")

    is_login = eventid_col.str.starts_with("cowrie.login")
    is_command = eventid_col.str.starts_with("cowrie.command")
    is_file_download = eventid_col == "cowrie.session.file_download"
    is_file_upload = eventid_col == "cowrie.session.file_upload"
    is_file_event = is_file_download | is_file_upload
    is_login_success = eventid_col == "cowrie.login.success"

    # OCSF metadata columns + conditional field mappings
    result = df.with_columns(
        # class_uid dispatch
        pl.when(is_login)
        .then(pl.lit(CLASS_AUTHENTICATION))
        .when(is_command)
        .then(pl.lit(CLASS_PROCESS_ACTIVITY))
        .when(is_file_event)
        .then(pl.lit(CLASS_FILE_ACTIVITY))
        .otherwise(pl.lit(CLASS_NETWORK_ACTIVITY))
        .alias("class_uid"),
        # category_uid
        pl.when(is_login)
        .then(pl.lit(CATEGORY_IAM))
        .when(is_command | is_file_event)
        .then(pl.lit(CATEGORY_SYSTEM))
        .otherwise(pl.lit(CATEGORY_NETWORK))
        .alias("category_uid"),
        # severity_id: file events = HIGH (malware delivery / attacker implant)
        pl.when(is_file_event)
        .then(pl.lit(SEVERITY_HIGH))
        .when(is_login_success)
        .then(pl.lit(SEVERITY_MEDIUM))
        .when(is_command)
        .then(pl.lit(SEVERITY_MEDIUM))
        .otherwise(pl.lit(SEVERITY_LOW))
        .alias("severity_id"),
        # activity_id: 1=Create for upload, 2=Read for download, 1=Logon/Launch for auth/cmd
        pl.when(is_login)
        .then(pl.lit(1))
        .when(is_command)
        .then(pl.lit(1))
        .when(is_file_upload)
        .then(pl.lit(1))
        .when(is_file_download)
        .then(pl.lit(2))
        .otherwise(pl.lit(0))
        .alias("activity_id"),
        # status_id: success/failure for login, unknown for others
        pl.when(is_login_success)
        .then(pl.lit(STATUS_SUCCESS))
        .when(is_login & ~is_login_success)
        .then(pl.lit(STATUS_FAILURE))
        .otherwise(pl.lit(STATUS_UNKNOWN))
        .alias("status_id"),
        # Metadata
        pl.lit(OCSF_VERSION).alias("metadata_version"),
        pl.lit(PRODUCT_NAME).alias("metadata_product_name"),
        # Auth-specific: user_name
        pl.when(is_login)
        .then(pl.col("username") if "username" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("user_name"),
        # Auth-specific: unmapped_password (intel for credential analysis)
        pl.when(is_login)
        .then(pl.col("password") if "password" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("unmapped_password"),
        # Auth-specific: auth_protocol (login events)
        pl.when(is_login)
        .then(pl.col("protocol") if "protocol" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("auth_protocol"),
        # Protocol name for non-login events
        pl.when(~is_login)
        .then(pl.col("protocol") if "protocol" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("connection_info_protocol_name"),
        # is_cleartext (honeypots always see plaintext credentials)
        pl.when(is_login).then(pl.lit(True)).otherwise(pl.lit(None)).alias("is_cleartext"),
        # Process-specific: actor_process_cmd_line
        pl.when(is_command)
        .then(pl.col("input") if "input" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("actor_process_cmd_line"),
        # File-specific: file_hash_sha256 (from shasum, both download and upload)
        pl.when(is_file_event)
        .then(pl.col("shasum") if "shasum" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("file_hash_sha256"),
        # File-specific: file_url (downloads only; uploads have no source URL)
        pl.when(is_file_download)
        .then(pl.col("url") if "url" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("file_url"),
        # File-specific: file_path (outfile path where Cowrie saved the file)
        pl.when(is_file_event)
        .then(pl.col("outfile") if "outfile" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("file_path"),
        # File-specific: file_name (attacker's original filename for SFTP uploads)
        pl.when(is_file_upload)
        .then(pl.col("filename") if "filename" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("file_name"),
        # File-intent: persistence / probe / malware (see header comment).
        # Ordering matters — probe-hash overrides destfile because some
        # attackers `wget` empty-file probes into auth paths to check
        # write permission (e.g. ``> ~/.ssh/authorized_keys``), and that
        # is probe activity not a persistence attempt.
        pl.when(~is_file_event)
        .then(pl.lit(None, dtype=pl.Utf8))
        .when(
            pl.col("shasum").is_in(list(_PROBE_SHA256))
            if "shasum" in df.columns
            else pl.lit(False)
        )
        .then(pl.lit("probe"))
        .when(
            pl.col("destfile").str.contains(_PERSISTENCE_DESTFILE_REGEX)
            if "destfile" in df.columns
            else pl.lit(False)
        )
        .then(pl.lit("persistence"))
        .otherwise(pl.lit("malware"))
        .cast(pl.Utf8)
        .alias("file_intent"),
    )

    # type_uid = class_uid * 100 + activity_id
    result = result.with_columns(
        (pl.col("class_uid") * 100 + pl.col("activity_id")).alias("type_uid"),
    )

    # Rename shared columns (1:1 renames)
    rename_map: dict[str, str] = {
        "src_ip": "src_endpoint_ip",
        "dst_ip": "dst_endpoint_ip",
        "src_port": "src_endpoint_port",
        "dst_port": "dst_endpoint_port",
        "timestamp": "time",
    }
    rename_map = {k: v for k, v in rename_map.items() if k in result.columns}
    result = result.rename(rename_map)

    # Drop raw columns that have been mapped to OCSF equivalents
    drop_cols = [
        c
        for c in (
            "eventid",
            "username",
            "password",
            "input",
            "protocol",
            "shasum",
            "url",
            "outfile",
            "filename",
        )
        if c in result.columns
    ]
    if drop_cols:
        result = result.drop(drop_cols)

    return result


_ALERT_FLAT_TARGETS: tuple[tuple[str, str, pl.DataType], ...] = (
    ("severity", "alert_severity", pl.Int64()),
    ("signature", "alert_signature", pl.Utf8()),
    ("signature_id", "alert_signature_id", pl.Int64()),
    ("category", "alert_category", pl.Utf8()),
    ("action", "alert_action", pl.Utf8()),
)


def _flatten_suricata_alert_struct(df: pl.DataFrame) -> pl.DataFrame:
    """Ensure flat ``alert_*`` columns exist regardless of bronze shape.

    Production Suricata bronze (via Vector's eve.json) ships alert metadata
    nested under an ``alert`` struct. ``read_bronze_ndjson`` JSON-stringifies
    every dict-valued field to keep schema inference stable across rows, so
    by the time silver normalisation runs the column may be a ``Struct``
    (direct construction, unit tests), a ``Utf8`` containing JSON (the
    production path through the bronze reader), or absent entirely (a future
    bronze stream that doesn't carry alert metadata). All three are tolerated
    here so the normaliser below can always reference ``alert_severity`` etc.
    directly.
    """
    alert_dtype = df.schema.get("alert") if "alert" in df.columns else None

    if alert_dtype == pl.Utf8():
        decode_schema = pl.Struct(
            [pl.Field(sub, dtype) for sub, _flat, dtype in _ALERT_FLAT_TARGETS]
        )
        df = df.with_columns(pl.col("alert").str.json_decode(decode_schema).alias("alert"))
        alert_dtype = df.schema.get("alert")

    struct_field_names: set[str] = set()
    if isinstance(alert_dtype, pl.Struct):
        struct_field_names = {field.name for field in alert_dtype.fields}

    new_columns: list[pl.Expr] = []
    for sub, flat_name, dtype in _ALERT_FLAT_TARGETS:
        if flat_name in df.columns:
            continue
        if sub in struct_field_names:
            new_columns.append(pl.col("alert").struct.field(sub).alias(flat_name))
        else:
            new_columns.append(pl.lit(None, dtype=dtype).alias(flat_name))

    if new_columns:
        df = df.with_columns(new_columns)
    if "alert" in df.columns and isinstance(df.schema.get("alert"), pl.Struct):
        df = df.drop("alert")
    return df


def normalize_suricata(df: pl.DataFrame) -> pl.DataFrame:
    """Normalize bronze Suricata events to OCSF columns.

    Event dispatch:
    - alert events -> Detection Finding (2004)
    - other        -> Network Activity (4001)
    """
    if df.is_empty():
        return df

    df = _flatten_suricata_alert_struct(df)

    is_alert = pl.col("event_type") == "alert"

    # Map Suricata severity (1=high, 2=medium, 3=low) to OCSF severity_id
    severity_expr = (
        pl.when(pl.col("alert_severity") == 1)
        .then(pl.lit(SEVERITY_HIGH))
        .when(pl.col("alert_severity") == 2)
        .then(pl.lit(SEVERITY_MEDIUM))
        .when(pl.col("alert_severity") == 3)
        .then(pl.lit(SEVERITY_LOW))
        .otherwise(pl.lit(SEVERITY_UNKNOWN))
    )

    result = df.with_columns(
        # class_uid dispatch
        pl.when(is_alert)
        .then(pl.lit(CLASS_DETECTION_FINDING))
        .otherwise(pl.lit(CLASS_NETWORK_ACTIVITY))
        .alias("class_uid"),
        # category_uid
        pl.when(is_alert)
        .then(pl.lit(CATEGORY_FINDINGS))
        .otherwise(pl.lit(CATEGORY_NETWORK))
        .alias("category_uid"),
        # severity_id
        pl.when(is_alert)
        .then(severity_expr)
        .otherwise(pl.lit(SEVERITY_INFORMATIONAL))
        .alias("severity_id"),
        # activity_id: 1=Create for findings, 6=Traffic for network
        pl.when(is_alert).then(pl.lit(1)).otherwise(pl.lit(6)).alias("activity_id"),
        # status_id
        pl.lit(STATUS_UNKNOWN).alias("status_id"),
        # Metadata
        pl.lit(OCSF_VERSION).alias("metadata_version"),
        pl.lit(PRODUCT_NAME).alias("metadata_product_name"),
        # Detection-specific: finding_title
        pl.when(is_alert)
        .then(pl.col("alert_signature"))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("finding_title"),
        # Detection-specific: finding_uid
        pl.when(is_alert)
        .then(pl.col("alert_signature_id").cast(pl.Utf8))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("finding_uid"),
        # Detection-specific: analytic_name
        pl.when(is_alert)
        .then(pl.lit("Suricata"))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("analytic_name"),
        # Detection-specific: finding_category (from alert_category)
        pl.when(is_alert)
        .then(pl.col("alert_category"))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("finding_category"),
        # Detection-specific: finding_action (from alert_action)
        pl.when(is_alert)
        .then(pl.col("alert_action"))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("finding_action"),
    )

    # type_uid
    result = result.with_columns(
        (pl.col("class_uid") * 100 + pl.col("activity_id")).alias("type_uid"),
    )

    # message from alert_signature or event_type
    result = result.with_columns(
        pl.when(is_alert)
        .then(pl.col("alert_signature"))
        .otherwise(pl.col("event_type"))
        .cast(pl.Utf8)
        .alias("message"),
    )

    # Rename shared columns (suricata uses dest_ip/dest_port)
    rename_map: dict[str, str] = {
        "src_ip": "src_endpoint_ip",
        "dest_ip": "dst_endpoint_ip",
        "src_port": "src_endpoint_port",
        "dest_port": "dst_endpoint_port",
        "timestamp": "time",
        "proto": "connection_info_protocol_name",
    }
    rename_map = {k: v for k, v in rename_map.items() if k in result.columns}
    result = result.rename(rename_map)

    # Drop raw columns consumed into OCSF fields
    drop_cols = [
        c
        for c in (
            "event_type",
            "alert_signature",
            "alert_signature_id",
            "alert_category",
            "alert_severity",
            "alert_action",
        )
        if c in result.columns
    ]
    if drop_cols:
        result = result.drop(drop_cols)

    return result


_NFTABLES_REQUIRED_FIELDS = ("action", "protocol", "chain")


def normalize_nftables(df: pl.DataFrame) -> pl.DataFrame:
    """Normalize bronze nftables events to OCSF Network Activity columns.

    All nftables events map to Network Activity (4001).

    Production bronze must contain the parsed nftables fields produced by
    Vector's nftables pipeline (`action`, `protocol`, `chain`, plus the
    shared `src_ip` / `dst_ip` etc.). When upstream parsing is broken,
    events ship as raw `message` strings with only Vector metadata
    columns — nothing meaningful to OCSF-normalize. In that case we
    return an empty DataFrame so the runner skips the silver write
    cleanly rather than crashing on a missing column.
    """
    if df.is_empty():
        return df

    missing = [field for field in _NFTABLES_REQUIRED_FIELDS if field not in df.columns]
    if missing:
        return df.clear()

    # Map action to activity_id
    action_expr = (
        pl.when(pl.col("action") == "accept")
        .then(pl.lit(1))  # Open
        .when(pl.col("action") == "drop")
        .then(pl.lit(5))  # Refuse
        .when(pl.col("action") == "reject")
        .then(pl.lit(5))  # Refuse
        .otherwise(pl.lit(0))
    )

    # Map protocol name to IANA number
    proto_num_expr = (
        pl.when(pl.col("protocol") == "tcp")
        .then(pl.lit(6))
        .when(pl.col("protocol") == "udp")
        .then(pl.lit(17))
        .when(pl.col("protocol") == "icmp")
        .then(pl.lit(1))
        .otherwise(pl.lit(0))
    )

    # Severity: drop=medium (blocked attack), accept=informational
    severity_expr = (
        pl.when(pl.col("action") == "drop")
        .then(pl.lit(SEVERITY_MEDIUM))
        .when(pl.col("action") == "reject")
        .then(pl.lit(SEVERITY_MEDIUM))
        .otherwise(pl.lit(SEVERITY_INFORMATIONAL))
    )

    result = df.with_columns(
        pl.lit(CLASS_NETWORK_ACTIVITY).alias("class_uid"),
        pl.lit(CATEGORY_NETWORK).alias("category_uid"),
        severity_expr.alias("severity_id"),
        action_expr.alias("activity_id"),
        pl.lit(STATUS_UNKNOWN).alias("status_id"),
        pl.lit(OCSF_VERSION).alias("metadata_version"),
        pl.lit(PRODUCT_NAME).alias("metadata_product_name"),
        proto_num_expr.alias("connection_info_protocol_num"),
        pl.col("protocol").alias("connection_info_protocol_name"),
        pl.lit(1).alias("connection_info_direction_id"),  # Inbound
    )

    # type_uid and message
    result = result.with_columns(
        (pl.col("class_uid") * 100 + pl.col("activity_id")).alias("type_uid"),
        (pl.col("action") + " " + pl.col("chain")).alias("message"),
    )

    # Rename: length -> traffic_bytes_in
    result = result.with_columns(
        pl.col("length").alias("traffic_bytes_in"),
    )

    # Rename shared columns
    rename_map: dict[str, str] = {
        "src_ip": "src_endpoint_ip",
        "dst_ip": "dst_endpoint_ip",
        "src_port": "src_endpoint_port",
        "dst_port": "dst_endpoint_port",
        "timestamp": "time",
    }
    rename_map = {k: v for k, v in rename_map.items() if k in result.columns}
    result = result.rename(rename_map)

    # Drop raw columns consumed into OCSF fields
    drop_cols = [c for c in ("action", "chain", "protocol", "length") if c in result.columns]
    if drop_cols:
        result = result.drop(drop_cols)

    return result


DIONAEA_FIELD_MAP: dict[str, tuple[str, str, str]] = {
    # --- Renamed ---
    "timestamp": ("time", "rename", "Event timestamp"),
    "src_ip": ("src_endpoint_ip", "rename", "Attacker source IP"),
    "dst_ip": ("dst_endpoint_ip", "rename", "Honeypot destination IP"),
    "src_port": ("src_endpoint_port", "rename", "Attacker source port"),
    "dst_port": ("dst_endpoint_port", "rename", "Honeypot destination port"),
    # --- Mapped ---
    "connection_protocol": ("connection_info_protocol_name", "rename", "Service protocol name"),
    # --- Conditional ---
    "credential_username": ("user_name", "conditional", "Login events; null otherwise"),
    "credential_password": ("unmapped_password", "conditional", "Login events; credential intel"),
    "ftp_command": ("actor_process_cmd_line", "conditional", "FTP command events only"),
    # --- Preserved ---
    "connection_transport": ("connection_transport", "preserve", "TCP/UDP/TLS transport"),
    "src_hostname": ("src_hostname", "preserve", "Reverse DNS hostname"),
}


def normalize_dionaea(df: pl.DataFrame) -> pl.DataFrame:
    """Normalize bronze Dionaea events to OCSF columns.

    Event dispatch:
    - eventid="dionaea.binary.captured" -> File Activity (1001)
      (synthetic event from the disk-scan helper covering SMB/FTP/HTTP
      uploads that dionaea writes to ``var/lib/dionaea/binaries`` without
      ever emitting a hash event to ``log_json``)
    - credential_username present       -> Authentication (3002)
    - ftp_command present               -> Process Activity (1007)
    - other connections                 -> Network Activity (4001)

    Bronze fields are pre-flattened by Vector (connection.* -> connection_*,
    credentials[] -> credential_username/credential_password).
    """
    if df.is_empty():
        return df

    has_credential = (
        (pl.col("credential_username").is_not_null() & (pl.col("credential_username") != ""))
        if "credential_username" in df.columns
        else pl.lit(False)
    )

    has_ftp_command = (
        (pl.col("ftp_command").is_not_null() & (pl.col("ftp_command") != ""))
        if "ftp_command" in df.columns
        else pl.lit(False)
    )

    is_binary_capture = (
        (pl.col("eventid") == "dionaea.binary.captured")
        if "eventid" in df.columns
        else pl.lit(False)
    )

    # OCSF metadata columns + conditional field mappings
    result = df.with_columns(
        # class_uid dispatch — binary_capture wins over credential/ftp because
        # synthetic rows lack those fields and would otherwise fall through to
        # NETWORK_ACTIVITY (the wrong class for a captured malware sample).
        pl.when(is_binary_capture)
        .then(pl.lit(CLASS_FILE_ACTIVITY))
        .when(has_credential)
        .then(pl.lit(CLASS_AUTHENTICATION))
        .when(has_ftp_command)
        .then(pl.lit(CLASS_PROCESS_ACTIVITY))
        .otherwise(pl.lit(CLASS_NETWORK_ACTIVITY))
        .alias("class_uid"),
        # category_uid
        pl.when(is_binary_capture)
        .then(pl.lit(CATEGORY_SYSTEM))
        .when(has_credential)
        .then(pl.lit(CATEGORY_IAM))
        .when(has_ftp_command)
        .then(pl.lit(CATEGORY_SYSTEM))
        .otherwise(pl.lit(CATEGORY_NETWORK))
        .alias("category_uid"),
        # severity_id: binary captures=HIGH, credentials/commands=MEDIUM, connections=LOW
        pl.when(is_binary_capture)
        .then(pl.lit(SEVERITY_HIGH))
        .when(has_credential)
        .then(pl.lit(SEVERITY_MEDIUM))
        .when(has_ftp_command)
        .then(pl.lit(SEVERITY_MEDIUM))
        .otherwise(pl.lit(SEVERITY_LOW))
        .alias("severity_id"),
        # activity_id: 1=Create for binary, 1=Logon for auth, 1=Launch for command, 0=Unknown
        pl.when(is_binary_capture)
        .then(pl.lit(1))
        .when(has_credential)
        .then(pl.lit(1))
        .when(has_ftp_command)
        .then(pl.lit(1))
        .otherwise(pl.lit(0))
        .alias("activity_id"),
        # status_id: unknown for all (Dionaea doesn't track login success/failure)
        pl.lit(STATUS_UNKNOWN).alias("status_id"),
        # Metadata
        pl.lit(OCSF_VERSION).alias("metadata_version"),
        pl.lit(PRODUCT_NAME).alias("metadata_product_name"),
        # Auth-specific: user_name (from credential_username) — guarded so a
        # bronze df without credentials (e.g. synthetic-only) doesn't crash.
        pl.when(has_credential)
        .then(
            pl.col("credential_username")
            if "credential_username" in df.columns
            else pl.lit(None)
        )
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("user_name"),
        # Auth-specific: unmapped_password (from credential_password)
        pl.when(has_credential)
        .then(
            pl.col("credential_password") if "credential_password" in df.columns else pl.lit(None)
        )
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("unmapped_password"),
        # is_cleartext (honeypots always see plaintext credentials)
        pl.when(has_credential).then(pl.lit(True)).otherwise(pl.lit(None)).alias("is_cleartext"),
        # Process-specific: actor_process_cmd_line (from ftp_command)
        pl.when(has_ftp_command)
        .then(pl.col("ftp_command") if "ftp_command" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("actor_process_cmd_line"),
        # File-specific: file_hash_sha256 (only on synthetic binary captures)
        pl.when(is_binary_capture)
        .then(pl.col("shasum") if "shasum" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("file_hash_sha256"),
        # File-specific: file_name (the on-disk binary filename — typically MD5)
        pl.when(is_binary_capture)
        .then(pl.col("binary_file_name") if "binary_file_name" in df.columns else pl.lit(None))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("file_name"),
        # File-intent: always 'malware' for dionaea binary captures (SMB/FTP/HTTP
        # uploads aren't persistence targets, and we don't classify probe-noise
        # this side — Phase 2's probe hash-set is cowrie-context).
        pl.when(is_binary_capture)
        .then(pl.lit("malware"))
        .otherwise(pl.lit(None))
        .cast(pl.Utf8)
        .alias("file_intent"),
    )

    # type_uid = class_uid * 100 + activity_id
    result = result.with_columns(
        (pl.col("class_uid") * 100 + pl.col("activity_id")).alias("type_uid"),
    )

    # message from connection_protocol + connection_type
    result = result.with_columns(
        (pl.col("connection_protocol") + " " + pl.col("connection_type")).alias("message"),
    )

    # Rename shared columns
    rename_map: dict[str, str] = {
        "src_ip": "src_endpoint_ip",
        "dst_ip": "dst_endpoint_ip",
        "src_port": "src_endpoint_port",
        "dst_port": "dst_endpoint_port",
        "timestamp": "time",
        "connection_protocol": "connection_info_protocol_name",
    }
    rename_map = {k: v for k, v in rename_map.items() if k in result.columns}
    result = result.rename(rename_map)

    # Drop raw columns consumed into OCSF equivalents
    drop_cols = [
        c
        for c in ("connection_type", "credential_username", "credential_password", "ftp_command")
        if c in result.columns
    ]
    if drop_cols:
        result = result.drop(drop_cols)

    return result


_GEO_SUBFIELDS: tuple[tuple[str, pl.DataType], ...] = (
    ("country_code", pl.Utf8()),
    ("region_code", pl.Utf8()),
    ("city", pl.Utf8()),
    ("latitude", pl.Float64()),
    ("longitude", pl.Float64()),
    ("timezone", pl.Utf8()),
    ("asn", pl.Int64()),
    ("isp", pl.Utf8()),
)


def _flatten_geo_struct(df: pl.DataFrame) -> pl.DataFrame:
    """Extract Vector's nested ``geo`` struct into flat ``geo.<field>`` columns.

    Vector writes geo enrichment as a single struct at ingest time; downstream
    transform/metrics code (and the dashboard, STIX export, etc.) expects
    flat dotted column names (``geo.country_code``, ``geo.asn``, ...).

    Three bronze shapes are tolerated:

    * **Struct** — the column is already an inferred ``pl.Struct``. Used by
      unit tests that construct frames from Python dicts.
    * **Utf8 (JSON-encoded)** — ``read_bronze_ndjson`` indiscriminately
      JSON-stringifies every nested dict before constructing the DataFrame
      so that mixed-type rows don't break schema inference. Production
      bronze always lands here.
    * **Absent** — no Vector enrichment ran (alternate sensor, partial
      pipeline). Flat columns are filled with typed nulls so silver schema
      is stable regardless.

    The raw ``geo`` column is dropped after extraction to keep silver clean.
    """
    geo_dtype = df.schema.get("geo") if "geo" in df.columns else None

    if geo_dtype == pl.Utf8():
        decode_schema = pl.Struct([pl.Field(sub, dtype) for sub, dtype in _GEO_SUBFIELDS])
        df = df.with_columns(pl.col("geo").str.json_decode(decode_schema).alias("geo"))
        geo_dtype = df.schema.get("geo")

    struct_field_names: set[str] = set()
    if isinstance(geo_dtype, pl.Struct):
        struct_field_names = {f.name for f in geo_dtype.fields}

    new_columns: list[pl.Expr] = []
    for sub, dtype in _GEO_SUBFIELDS:
        flat_name = f"geo.{sub}"
        if flat_name in df.columns:
            continue
        if sub in struct_field_names:
            new_columns.append(pl.col("geo").struct.field(sub).alias(flat_name))
        else:
            new_columns.append(pl.lit(None, dtype=dtype).alias(flat_name))

    if new_columns:
        df = df.with_columns(new_columns)
    if "geo" in df.columns and isinstance(df.schema.get("geo"), pl.Struct):
        df = df.drop("geo")
    return df


def normalize_dataset(df: pl.DataFrame, dataset: str) -> pl.DataFrame:
    """Dispatch normalization to the correct per-dataset function.

    Runs `_flatten_geo_struct` after the per-dataset normaliser so every
    silver row has consistent `geo.<field>` flat columns regardless of
    bronze shape (struct in production, flat in fixtures).
    """
    normalizers = {
        "cowrie": normalize_cowrie,
        "suricata": normalize_suricata,
        "nftables": normalize_nftables,
        "dionaea": normalize_dionaea,
    }
    normalizer = normalizers.get(dataset)
    if normalizer is None:
        msg = f"Unknown dataset: {dataset}"
        raise ValueError(msg)
    return _flatten_geo_struct(normalizer(df))

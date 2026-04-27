"""Polars schema definitions for bronze-layer datasets."""

from __future__ import annotations

import polars as pl

BRONZE_COWRIE_SCHEMA: dict[str, pl.DataType] = {
    "timestamp": pl.Datetime("us"),
    "eventid": pl.Utf8,
    "src_ip": pl.Utf8,
    "src_port": pl.Int64,
    "dst_ip": pl.Utf8,
    "dst_port": pl.Int64,
    "session": pl.Utf8,
    "protocol": pl.Utf8,
    "username": pl.Utf8,
    "password": pl.Utf8,
    "input": pl.Utf8,
    "message": pl.Utf8,
    "sensor": pl.Utf8,
}

BRONZE_SURICATA_SCHEMA: dict[str, pl.DataType] = {
    "timestamp": pl.Datetime("us"),
    "event_type": pl.Utf8,
    "src_ip": pl.Utf8,
    "src_port": pl.Int64,
    "dest_ip": pl.Utf8,
    "dest_port": pl.Int64,
    "proto": pl.Utf8,
    "alert_signature_id": pl.Int64,
    "alert_signature": pl.Utf8,
    "alert_category": pl.Utf8,
    "alert_severity": pl.Int64,
    "alert_action": pl.Utf8,
    "flow_id": pl.Int64,
}

BRONZE_NFTABLES_SCHEMA: dict[str, pl.DataType] = {
    "timestamp": pl.Datetime("us"),
    "action": pl.Utf8,
    "chain": pl.Utf8,
    "src_ip": pl.Utf8,
    "src_port": pl.Int64,
    "dst_ip": pl.Utf8,
    "dst_port": pl.Int64,
    "protocol": pl.Utf8,
    "interface_in": pl.Utf8,
    "interface_out": pl.Utf8,
    "length": pl.Int64,
}

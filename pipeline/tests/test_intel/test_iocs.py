"""Tests for the raw IOC export — the long-tail counterpart to STIX."""

from __future__ import annotations

import csv
import gzip
import io
from datetime import UTC, datetime

import polars as pl
import pytest

from lantana.intel.iocs import _is_real_attacker_ip, build_raw_ioc_export


def _ts(minute: int = 0) -> datetime:
    return datetime(2026, 5, 26, 10, minute, 0, tzinfo=UTC)


class TestIsRealAttackerIp:
    """The noise-IP gate — same rule the brief inventory used pre-Phase-0,
    now living next to the export it actually protects."""

    @pytest.mark.parametrize(
        "ip",
        ["203.0.113.50", "198.51.100.22", "192.0.2.99", "2001:db8::1"],
    )
    def test_real_attacker_ips_pass(self, ip: str) -> None:
        assert _is_real_attacker_ip(ip)

    @pytest.mark.parametrize(
        "ip",
        ["0.0.0.0", "::", "127.0.0.1", "::1", "224.0.0.1", "169.254.1.5"],
    )
    def test_noise_ips_filtered(self, ip: str) -> None:
        """Unspecified, loopback, multicast, link-local all dropped."""
        assert not _is_real_attacker_ip(ip)

    def test_pseudonyms_filtered(self) -> None:
        """Strings that don't parse as IPs (left-over pseudonyms) are dropped."""
        assert not _is_real_attacker_ip("honeypot-sensor-01")
        assert not _is_real_attacker_ip("")


class TestBuildRawIocExport:
    """build_raw_ioc_export aggregates silver IOCs, joins risk_score
    for IPs, gzips the CSV. Returns None when there's nothing to export."""

    def _silver(self) -> pl.DataFrame:
        return pl.DataFrame(
            {
                "src_endpoint_ip": [
                    "203.0.113.50",
                    "203.0.113.50",
                    "198.51.100.22",
                    "0.0.0.0",  # noise — must be filtered out
                    "honeypot-sensor-01",  # pseudonym — must be filtered out
                ],
                "dataset": ["cowrie", "suricata", "cowrie", "nftables", "cowrie"],
                "time": [_ts(0), _ts(5), _ts(2), _ts(3), _ts(4)],
                "file_hash_sha256": [
                    "a" * 64,
                    None,
                    "b" * 64,
                    None,
                    None,
                ],
                "file_url": [
                    "http://example.com/x.sh",
                    None,
                    "http://example.net/y.bin",
                    None,
                    None,
                ],
            }
        )

    def _reputation(self) -> pl.DataFrame:
        return pl.DataFrame(
            {
                "src_endpoint_ip": ["203.0.113.50", "198.51.100.22"],
                "risk_score": [87.5, 42.3],
            }
        )

    def _csv_rows(self, data: bytes) -> list[dict[str, str]]:
        text = gzip.decompress(data).decode("utf-8")
        return list(csv.DictReader(io.StringIO(text)))

    def test_returns_none_for_empty_silver(self) -> None:
        empty = pl.DataFrame(
            schema={
                "src_endpoint_ip": pl.Utf8,
                "dataset": pl.Utf8,
                "time": pl.Datetime,
            }
        ).lazy()
        assert build_raw_ioc_export(empty, self._reputation()) is None

    def test_returns_none_when_no_ip_column(self) -> None:
        """Silver lacking ``src_endpoint_ip`` can't produce an IOC export."""
        df = pl.DataFrame({"some_other_field": ["x"]}).lazy()
        assert build_raw_ioc_export(df, self._reputation()) is None

    def test_emits_ip_hash_and_url_rows(self) -> None:
        result = build_raw_ioc_export(self._silver().lazy(), self._reputation())
        assert result is not None
        data, count = result
        rows = self._csv_rows(data)

        ioc_types = {r["ioc_type"] for r in rows}
        assert ioc_types == {"ip", "hash_sha256", "url"}

        ips = {r["value"] for r in rows if r["ioc_type"] == "ip"}
        assert ips == {"203.0.113.50", "198.51.100.22"}

        hashes = {r["value"] for r in rows if r["ioc_type"] == "hash_sha256"}
        assert hashes == {"a" * 64, "b" * 64}

        urls = {r["value"] for r in rows if r["ioc_type"] == "url"}
        assert urls == {"http://example.com/x.sh", "http://example.net/y.bin"}

        assert count == len(rows)

    def test_noise_ips_and_pseudonyms_dropped(self) -> None:
        result = build_raw_ioc_export(self._silver().lazy(), self._reputation())
        assert result is not None
        rows = self._csv_rows(result[0])
        values = {r["value"] for r in rows}
        assert "0.0.0.0" not in values
        assert "honeypot-sensor-01" not in values

    def test_ip_row_carries_risk_score_from_reputation(self) -> None:
        result = build_raw_ioc_export(self._silver().lazy(), self._reputation())
        assert result is not None
        rows = self._csv_rows(result[0])
        ip_rows = {r["value"]: r for r in rows if r["ioc_type"] == "ip"}
        assert ip_rows["203.0.113.50"]["risk_score"] == "87.5"
        assert ip_rows["198.51.100.22"]["risk_score"] == "42.3"

    def test_hash_and_url_rows_have_null_risk_score(self) -> None:
        """Risk scores are per-IP only; hashes/URLs leave the column empty."""
        result = build_raw_ioc_export(self._silver().lazy(), self._reputation())
        assert result is not None
        rows = self._csv_rows(result[0])
        for r in rows:
            if r["ioc_type"] in ("hash_sha256", "url"):
                assert r["risk_score"] == ""

    def test_multi_dataset_ip_aggregates_datasets(self) -> None:
        """203.0.113.50 appears in cowrie + suricata; both must surface
        as a semicolon-separated string on a single row."""
        result = build_raw_ioc_export(self._silver().lazy(), self._reputation())
        assert result is not None
        rows = self._csv_rows(result[0])
        row = next(r for r in rows if r["value"] == "203.0.113.50")
        assert row["datasets"] == "cowrie;suricata"
        assert row["count"] == "2"

    def test_count_and_seen_columns_present(self) -> None:
        result = build_raw_ioc_export(self._silver().lazy(), self._reputation())
        assert result is not None
        rows = self._csv_rows(result[0])
        row = next(r for r in rows if r["value"] == "198.51.100.22")
        assert row["count"] == "1"
        # first_seen / last_seen are equal when there's only one event.
        assert row["first_seen"] == row["last_seen"]

    def test_csv_header_order_is_stable(self) -> None:
        """Schema is contract — downstream parsers may rely on column order."""
        result = build_raw_ioc_export(self._silver().lazy(), self._reputation())
        assert result is not None
        text = gzip.decompress(result[0]).decode("utf-8")
        header = text.split("\n", 1)[0]
        assert header == "ioc_type,value,datasets,count,risk_score,first_seen,last_seen"

    def test_empty_reputation_leaves_risk_score_null(self) -> None:
        """If reputation is empty (e.g. no enrichment that day), IPs still
        export — they just don't carry a risk_score."""
        empty_rep = pl.DataFrame(
            schema={
                "src_endpoint_ip": pl.Utf8,
                "risk_score": pl.Float64,
            }
        )
        result = build_raw_ioc_export(self._silver().lazy(), empty_rep)
        assert result is not None
        rows = self._csv_rows(result[0])
        ip_rows = [r for r in rows if r["ioc_type"] == "ip"]
        assert ip_rows  # IPs still emitted
        for r in ip_rows:
            assert r["risk_score"] == ""

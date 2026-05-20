"""Tests for lantana.enrichment.ioc — IOC extraction and OPSEC filtering."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import polars as pl

from lantana.common.redact import RedactionConfig

if TYPE_CHECKING:
    from pathlib import Path
from lantana.enrichment.ioc import (
    extract_hashes_from_bronze,
    extract_hashes_from_disk,
    extract_ips,
    filter_internal_ips,
)


def _config() -> RedactionConfig:
    return RedactionConfig(
        infrastructure_ips=["192.0.2.10", "2001:db8::10"],
        infrastructure_cidrs=["10.50.99.0/24", "fd99:10:50:99::/64"],
        pseudonym_map={},
    )


class TestExtractIps:
    def test_returns_unique_set(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50", "203.0.113.50", "198.51.100.22"]})
        assert extract_ips(df) == {"203.0.113.50", "198.51.100.22"}

    def test_no_src_ip_column(self) -> None:
        df = pl.DataFrame({"event": ["login"]})
        assert extract_ips(df) == set()

    def test_drops_nulls_and_blanks(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50", None, ""]})
        result = extract_ips(df)
        assert result == {"203.0.113.50"}


class TestExtractHashesFromBronze:
    def test_returns_unique_shasum_values(self) -> None:
        df = pl.DataFrame({
            "shasum": ["abc" * 21 + "f", "abc" * 21 + "f", "deadbeef" * 8],
        })
        assert extract_hashes_from_bronze(df) == {"abc" * 21 + "f", "deadbeef" * 8}

    def test_no_shasum_column(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50"]})
        assert extract_hashes_from_bronze(df) == set()


class TestExtractHashesFromDisk:
    def test_hashes_files_in_downloads(self, tmp_path: Path) -> None:
        sensor_dir = tmp_path / "sensor"
        (sensor_dir / "cowrie" / "downloads").mkdir(parents=True)
        payload = b"malware-bytes"
        (sensor_dir / "cowrie" / "downloads" / "payload.bin").write_bytes(payload)
        expected = hashlib.sha256(payload).hexdigest()

        assert extract_hashes_from_disk(sensor_dir) == {expected}

    def test_skips_oversized_files(self, tmp_path: Path) -> None:
        sensor_dir = tmp_path / "sensor"
        (sensor_dir / "cowrie" / "downloads").mkdir(parents=True)
        # Create a file > 100 MiB. Use a sparse write so the test stays fast.
        too_big = sensor_dir / "cowrie" / "downloads" / "huge.bin"
        with too_big.open("wb") as f:
            f.seek(100 * 1024 * 1024 + 1)
            f.write(b"\x00")

        assert extract_hashes_from_disk(sensor_dir) == set()

    def test_missing_dirs_treated_as_empty(self, tmp_path: Path) -> None:
        assert extract_hashes_from_disk(tmp_path / "nonexistent") == set()


class TestFilterInternalIps:
    def test_keeps_externals(self) -> None:
        kept = filter_internal_ips({"203.0.113.50", "198.51.100.22"}, _config())
        assert kept == {"203.0.113.50", "198.51.100.22"}

    def test_drops_exact_match(self) -> None:
        kept = filter_internal_ips({"203.0.113.50", "192.0.2.10"}, _config())
        assert kept == {"203.0.113.50"}

    def test_drops_ipv4_cidr_member(self) -> None:
        kept = filter_internal_ips({"10.50.99.100", "203.0.113.50"}, _config())
        assert kept == {"203.0.113.50"}

    def test_drops_ipv6_cidr_member(self) -> None:
        kept = filter_internal_ips({"fd99:10:50:99::1", "2001:db8:1::beef"}, _config())
        assert kept == {"2001:db8:1::beef"}

    def test_non_ip_strings_kept(self) -> None:
        """Hostnames or junk pass through unchanged."""
        kept = filter_internal_ips({"not.an.ip", "203.0.113.50"}, _config())
        assert kept == {"not.an.ip", "203.0.113.50"}

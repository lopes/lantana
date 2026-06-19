"""Tests for lantana.enrichment.ioc — IOC extraction and OPSEC filtering."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import polars as pl

from lantana.common.redact import RedactionConfig
from lantana.enrichment.ioc import (
    extract_dionaea_binary_events,
    extract_hashes_from_bronze,
    extract_hashes_from_disk,
    extract_ips,
    filter_internal_ips,
)

if TYPE_CHECKING:
    import pytest


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
        h1 = "abc" * 21 + "f"
        h2 = "deadbeef" * 8
        df = pl.DataFrame(
            {
                "eventid": [
                    "cowrie.session.file_download",
                    "cowrie.session.file_download",
                    "cowrie.session.file_upload",
                ],
                "shasum": [h1, h1, h2],
            }
        )
        assert extract_hashes_from_bronze(df) == {h1, h2}

    def test_excludes_tty_log_hashes(self) -> None:
        """cowrie.log.closed shasum values are TTY recordings, not malware — must be dropped."""
        malware_hash = "a8460f44" * 8
        tty_hash = "c32b4937" * 8
        df = pl.DataFrame(
            {
                "eventid": [
                    "cowrie.session.file_download",
                    "cowrie.log.closed",
                    "cowrie.log.closed",
                ],
                "shasum": [malware_hash, tty_hash, tty_hash],
            }
        )
        result = extract_hashes_from_bronze(df)
        assert result == {malware_hash}
        assert tty_hash not in result

    def test_no_shasum_column(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50"]})
        assert extract_hashes_from_bronze(df) == set()

    def test_no_eventid_column(self) -> None:
        df = pl.DataFrame({"shasum": ["abc" * 21 + "f"]})
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

    def test_unreadable_file_skipped(self, tmp_path: Path) -> None:
        """Permission-denied on a file is logged and skipped, not raised.

        Production defect 2026-05-25: cowrie writes downloads as stigma;
        the enrichment runner runs as nectar; nectar can iterdir the
        parent but cannot read individual payload files.
        """
        sensor_dir = tmp_path / "sensor"
        (sensor_dir / "cowrie" / "downloads").mkdir(parents=True)

        readable = sensor_dir / "cowrie" / "downloads" / "readable.bin"
        readable.write_bytes(b"ok")
        expected = hashlib.sha256(b"ok").hexdigest()

        unreadable = sensor_dir / "cowrie" / "downloads" / "unreadable.bin"
        unreadable.write_bytes(b"secret")
        unreadable.chmod(0o000)
        try:
            result = extract_hashes_from_disk(sensor_dir)
        finally:
            # Restore so tmp_path cleanup doesn't error
            unreadable.chmod(0o644)

        assert result == {expected}

    def test_file_vanishes_mid_scan_skipped(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If cowrie deletes a file between iterdir() and read_bytes(),
        treat as a benign race and continue.
        """
        sensor_dir = tmp_path / "sensor"
        (sensor_dir / "cowrie" / "downloads").mkdir(parents=True)
        (sensor_dir / "cowrie" / "downloads" / "missing.bin").write_bytes(b"data")

        original_read_bytes = Path.read_bytes

        def _vanishing_read(self: Path) -> bytes:
            raise FileNotFoundError(self)

        monkeypatch.setattr(Path, "read_bytes", _vanishing_read)
        try:
            result = extract_hashes_from_disk(sensor_dir)
        finally:
            monkeypatch.setattr(Path, "read_bytes", original_read_bytes)

        assert result == set()


class TestExtractDionaeaBinaryEvents:
    """Synthetic file-activity events for dionaea SMB/FTP captures.

    Dionaea's ``store`` ihandler writes binaries to
    ``var/lib/dionaea/binaries/`` (MD5-named) but never emits a hash
    event into ``dionaea.json``. Without this scanner, the 192 ELF
    samples op_alpha had captured by 2026-06-19 were completely invisible
    to silver → gold → brief. The scanner closes the gap.
    """

    @staticmethod
    def _set_mtime(path: Path, when: datetime) -> None:
        ts = when.timestamp()
        os.utime(path, (ts, ts))

    def test_returns_one_event_per_binary_dated_target(self, tmp_path: Path) -> None:
        sensor_dir = tmp_path / "sensor"
        binaries = sensor_dir / "dionaea" / "binaries"
        binaries.mkdir(parents=True)
        payload = b"\x7fELF\x02\x01\x01"  # minimal ELF magic, enough for the test
        f = binaries / "00aabbcc11ddeeff"
        f.write_bytes(payload)
        self._set_mtime(f, datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC))

        events = extract_dionaea_binary_events(sensor_dir, date(2026, 6, 18))
        assert len(events) == 1
        ev = events[0]
        assert ev["eventid"] == "dionaea.binary.captured"
        assert ev["shasum"] == hashlib.sha256(payload).hexdigest()
        assert ev["binary_file_name"] == "00aabbcc11ddeeff"
        assert ev["dataset"] == "dionaea"
        # mtime is rendered as a UTC ISO8601 string downstream consumers can parse
        assert ev["timestamp"].startswith("2026-06-18T")
        assert ev["timestamp"].endswith("Z")

    def test_filters_files_outside_target_date(self, tmp_path: Path) -> None:
        sensor_dir = tmp_path / "sensor"
        binaries = sensor_dir / "dionaea" / "binaries"
        binaries.mkdir(parents=True)

        today_file = binaries / "today"
        today_file.write_bytes(b"today")
        self._set_mtime(today_file, datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC))

        yesterday_file = binaries / "yesterday"
        yesterday_file.write_bytes(b"yesterday")
        self._set_mtime(yesterday_file, datetime(2026, 6, 17, 23, 30, 0, tzinfo=UTC))

        tomorrow_file = binaries / "tomorrow"
        tomorrow_file.write_bytes(b"tomorrow")
        self._set_mtime(tomorrow_file, datetime(2026, 6, 19, 0, 30, 0, tzinfo=UTC))

        events = extract_dionaea_binary_events(sensor_dir, date(2026, 6, 18))
        names = {ev["binary_file_name"] for ev in events}
        assert names == {"today"}

    def test_no_binaries_dir_returns_empty(self, tmp_path: Path) -> None:
        assert extract_dionaea_binary_events(tmp_path / "sensor", date(2026, 6, 18)) == []

    def test_skips_oversized_files(self, tmp_path: Path) -> None:
        sensor_dir = tmp_path / "sensor"
        binaries = sensor_dir / "dionaea" / "binaries"
        binaries.mkdir(parents=True)
        huge = binaries / "huge"
        with huge.open("wb") as fh:
            fh.seek(100 * 1024 * 1024 + 1)
            fh.write(b"\x00")
        self._set_mtime(huge, datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC))

        events = extract_dionaea_binary_events(sensor_dir, date(2026, 6, 18))
        assert events == []

    def test_unreadable_file_skipped(self, tmp_path: Path) -> None:
        sensor_dir = tmp_path / "sensor"
        binaries = sensor_dir / "dionaea" / "binaries"
        binaries.mkdir(parents=True)

        readable = binaries / "readable"
        readable.write_bytes(b"ok")
        self._set_mtime(readable, datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC))

        unreadable = binaries / "unreadable"
        unreadable.write_bytes(b"secret")
        self._set_mtime(unreadable, datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC))
        unreadable.chmod(0o000)
        try:
            events = extract_dionaea_binary_events(sensor_dir, date(2026, 6, 18))
        finally:
            unreadable.chmod(0o644)

        names = {ev["binary_file_name"] for ev in events}
        assert names == {"readable"}


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

    def test_drops_rfc1918(self) -> None:
        """RFC1918 addresses unrelated to this operation are dropped too —
        no threat-intel value at any provider, and we observed them
        leaking through bronze in op_alpha's first run.
        """
        kept = filter_internal_ips(
            {"10.69.215.134", "172.16.5.1", "192.168.1.1", "203.0.113.50"},
            _config(),
        )
        assert kept == {"203.0.113.50"}

    def test_drops_link_local(self) -> None:
        """Link-local (fe80::/10, 169.254.0.0/16) is dropped."""
        kept = filter_internal_ips(
            {"fe80::3878:dbff:feae:d1f0", "169.254.1.1", "203.0.113.50"},
            _config(),
        )
        assert kept == {"203.0.113.50"}

    def test_drops_loopback_and_multicast(self) -> None:
        kept = filter_internal_ips(
            {"127.0.0.1", "::1", "224.0.0.1", "203.0.113.50"},
            _config(),
        )
        assert kept == {"203.0.113.50"}

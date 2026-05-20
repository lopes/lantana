"""Tests for lantana.enrichment.runner error handling."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from lantana.common.redact import RedactionConfig
from lantana.enrichment.providers.base import EnrichmentResult
from lantana.enrichment.runner import (
    ErrorAccumulator,
    _classify_http_error,
    _enrich_ips_with_provider,
    _filter_internal_ips,
    _get_cached,
    _record_error,
    _set_cached,
    _write_error_summary,
)

# --- _classify_http_error ---


class TestClassifyHttpError:
    def test_rate_limit(self) -> None:
        assert _classify_http_error(429) == "rate_limit"

    def test_auth_401(self) -> None:
        assert _classify_http_error(401) == "auth"

    def test_auth_403(self) -> None:
        assert _classify_http_error(403) == "auth"

    def test_client_error(self) -> None:
        assert _classify_http_error(400) == "http_4xx"
        assert _classify_http_error(404) == "http_4xx"
        assert _classify_http_error(422) == "http_4xx"

    def test_server_error(self) -> None:
        assert _classify_http_error(500) == "http_5xx"
        assert _classify_http_error(502) == "http_5xx"
        assert _classify_http_error(503) == "http_5xx"


# --- _record_error ---


class TestRecordError:
    def test_first_error_creates_entry(self) -> None:
        errors: ErrorAccumulator = {}
        _record_error(errors, "abuseipdb", "rate_limit", "429 Too Many Requests")
        assert ("abuseipdb", "rate_limit") in errors
        entry = errors[("abuseipdb", "rate_limit")]
        assert entry.count == 1
        assert entry.provider == "abuseipdb"
        assert entry.error_type == "rate_limit"
        assert entry.error_message == "429 Too Many Requests"

    def test_repeated_error_increments_count(self) -> None:
        errors: ErrorAccumulator = {}
        _record_error(errors, "shodan", "timeout", "first timeout")
        _record_error(errors, "shodan", "timeout", "second timeout")
        _record_error(errors, "shodan", "timeout", "third timeout")
        entry = errors[("shodan", "timeout")]
        assert entry.count == 3
        assert entry.error_message == "third timeout"

    def test_different_providers_separate_entries(self) -> None:
        errors: ErrorAccumulator = {}
        _record_error(errors, "abuseipdb", "rate_limit", "429")
        _record_error(errors, "shodan", "rate_limit", "429")
        assert len(errors) == 2

    def test_different_types_separate_entries(self) -> None:
        errors: ErrorAccumulator = {}
        _record_error(errors, "abuseipdb", "rate_limit", "429")
        _record_error(errors, "abuseipdb", "timeout", "timed out")
        assert len(errors) == 2


# --- _write_error_summary ---


class TestWriteErrorSummary:
    def test_writes_ndjson(self, tmp_path: Path) -> None:
        errors: ErrorAccumulator = {}
        _record_error(errors, "abuseipdb", "rate_limit", "429 Too Many Requests")
        errors[("abuseipdb", "rate_limit")].count = 47

        errors_path = tmp_path / "enrichment_errors.json"
        _write_error_summary(errors, date(2026, 4, 28), errors_path)

        lines = errors_path.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["date"] == "2026-04-28"
        assert entry["provider"] == "abuseipdb"
        assert entry["error_type"] == "rate_limit"
        assert entry["count"] == 47
        assert entry["message"] == "429 Too Many Requests"

    def test_appends_to_existing(self, tmp_path: Path) -> None:
        errors_path = tmp_path / "enrichment_errors.json"
        old_entry = json.dumps({
            "date": "2026-04-27", "provider": "shodan",
            "error_type": "timeout", "count": 1, "message": "old",
        })
        errors_path.write_text(old_entry + "\n")

        errors: ErrorAccumulator = {}
        _record_error(errors, "abuseipdb", "rate_limit", "429")
        _write_error_summary(errors, date(2026, 4, 28), errors_path)

        lines = errors_path.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["date"] == "2026-04-27"
        assert json.loads(lines[1])["date"] == "2026-04-28"

    def test_no_write_on_empty_errors(self, tmp_path: Path) -> None:
        errors: ErrorAccumulator = {}
        errors_path = tmp_path / "enrichment_errors.json"
        _write_error_summary(errors, date(2026, 4, 28), errors_path)
        assert not errors_path.exists()

    def test_multiple_error_types(self, tmp_path: Path) -> None:
        errors: ErrorAccumulator = {}
        _record_error(errors, "abuseipdb", "rate_limit", "429")
        _record_error(errors, "shodan", "timeout", "timed out")
        _record_error(errors, "virustotal", "auth", "401 Unauthorized")

        errors_path = tmp_path / "enrichment_errors.json"
        _write_error_summary(errors, date(2026, 4, 28), errors_path)

        lines = errors_path.read_text().strip().splitlines()
        assert len(lines) == 3
        providers = {json.loads(line)["provider"] for line in lines}
        assert providers == {"abuseipdb", "shodan", "virustotal"}


# --- _enrich_ips_with_provider (error paths) ---


def _make_cache(tmp_path: Path) -> sqlite3.Connection:
    """Create an in-memory-like SQLite cache for testing."""
    db_path = tmp_path / "test_cache.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache ("
        "  key TEXT PRIMARY KEY,"
        "  provider TEXT NOT NULL,"
        "  data TEXT NOT NULL,"
        "  queried_at TEXT NOT NULL"
        ")"
    )
    conn.commit()
    return conn


class TestEnrichIpsWithProviderErrors:
    @pytest.mark.asyncio()
    async def test_http_error_recorded(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        response = httpx.Response(status_code=429, request=httpx.Request("GET", "https://api.test"))
        provider.enrich_ip.side_effect = httpx.HTTPStatusError(
            "429 Too Many Requests", request=response.request, response=response
        )

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert results == []
        assert cache_hits == 0
        assert ("test_provider", "rate_limit") in errors
        assert errors[("test_provider", "rate_limit")].count == 1

    @pytest.mark.asyncio()
    async def test_timeout_recorded(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        provider.enrich_ip.side_effect = httpx.ReadTimeout("read timed out")

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert results == []
        assert cache_hits == 0
        assert ("test_provider", "timeout") in errors

    @pytest.mark.asyncio()
    async def test_unknown_error_recorded(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        provider.enrich_ip.side_effect = ValueError("unexpected")

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert results == []
        assert cache_hits == 0
        assert ("test_provider", "unknown") in errors
        assert "unexpected" in errors[("test_provider", "unknown")].error_message

    @pytest.mark.asyncio()
    async def test_success_no_errors(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        provider.enrich_ip.return_value = EnrichmentResult(
            provider="test_provider",
            ip="1.2.3.4",
            data={"score": 50},
            queried_at=datetime.now(tz=UTC),
        )

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert len(results) == 1
        assert cache_hits == 0
        assert errors == {}

    @pytest.mark.asyncio()
    async def test_mixed_success_and_failure(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        success_result = EnrichmentResult(
            provider="test_provider",
            ip="1.2.3.4",
            data={"score": 50},
            queried_at=datetime.now(tz=UTC),
        )
        response = httpx.Response(status_code=429, request=httpx.Request("GET", "https://api.test"))
        provider.enrich_ip.side_effect = [
            success_result,
            httpx.HTTPStatusError("429", request=response.request, response=response),
        ]

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4", "5.6.7.8"], cache, errors
        )
        cache.close()

        assert len(results) == 1
        assert results[0].ip == "1.2.3.4"
        assert cache_hits == 0
        assert ("test_provider", "rate_limit") in errors


# --- Cache hit semantics (Phase 1 bug fix) ---


class TestCacheBehaviour:
    @pytest.mark.asyncio()
    async def test_cache_hit_returns_data(self, tmp_path: Path) -> None:
        """A cached result must be returned without calling the provider."""
        cache = _make_cache(tmp_path)
        cached_result = EnrichmentResult(
            provider="test_provider",
            ip="1.2.3.4",
            data={"abuseipdb_confidence_score": 90},
            queried_at=datetime.now(tz=UTC),
        )
        _set_cached(cache, cached_result)

        provider = AsyncMock()
        provider.enrich_ip.side_effect = AssertionError("provider must not be called on cache hit")

        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert len(results) == 1
        assert results[0].ip == "1.2.3.4"
        assert results[0].data["abuseipdb_confidence_score"] == 90
        assert cache_hits == 1
        assert errors == {}
        provider.enrich_ip.assert_not_called()

    @pytest.mark.asyncio()
    async def test_cache_miss_then_hit(self, tmp_path: Path) -> None:
        """First call fetches and caches; second call returns cached data."""
        cache = _make_cache(tmp_path)
        fresh = EnrichmentResult(
            provider="test_provider",
            ip="1.2.3.4",
            data={"score": 50},
            queried_at=datetime.now(tz=UTC),
        )
        provider = AsyncMock()
        provider.enrich_ip.return_value = fresh

        errors: ErrorAccumulator = {}
        results1, hits1 = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        results2, hits2 = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert len(results1) == 1
        assert hits1 == 0
        assert len(results2) == 1
        assert hits2 == 1
        assert results2[0].data["score"] == 50
        assert provider.enrich_ip.call_count == 1

    def test_get_cached_returns_none_when_missing(self, tmp_path: Path) -> None:
        cache = _make_cache(tmp_path)
        assert _get_cached(cache, "abuseipdb:1.2.3.4") is None
        cache.close()

    def test_get_cached_handles_malformed_row(self, tmp_path: Path) -> None:
        """A corrupt cached row is treated as a miss, not a crash."""
        cache = _make_cache(tmp_path)
        cache.execute(
            "INSERT INTO cache (key, provider, data, queried_at) VALUES (?, ?, ?, ?)",
            ("abuseipdb:1.2.3.4", "abuseipdb", "{not json}", datetime.now(tz=UTC).isoformat()),
        )
        cache.commit()

        assert _get_cached(cache, "abuseipdb:1.2.3.4") is None
        cache.close()


# --- OPSEC IP filter ---


class TestFilterInternalIps:
    def _config(self) -> RedactionConfig:
        return RedactionConfig(
            infrastructure_ips=["192.0.2.10", "2001:db8::10"],
            infrastructure_cidrs=["10.50.99.0/24", "fd99:10:50:99::/64"],
            pseudonym_map={},
        )

    def test_keeps_external_ips(self) -> None:
        kept = _filter_internal_ips(["203.0.113.50", "198.51.100.22"], self._config())
        assert kept == ["203.0.113.50", "198.51.100.22"]

    def test_drops_exact_infrastructure_ip(self) -> None:
        kept = _filter_internal_ips(
            ["203.0.113.50", "192.0.2.10", "198.51.100.22"], self._config(),
        )
        assert "192.0.2.10" not in kept
        assert kept == ["203.0.113.50", "198.51.100.22"]

    def test_drops_cidr_member(self) -> None:
        kept = _filter_internal_ips(["10.50.99.100", "203.0.113.50"], self._config())
        assert kept == ["203.0.113.50"]

    def test_drops_ipv6_cidr_member(self) -> None:
        kept = _filter_internal_ips(
            ["fd99:10:50:99::1", "2001:db8:1::beef"], self._config(),
        )
        assert kept == ["2001:db8:1::beef"]

    def test_non_ip_strings_kept(self) -> None:
        """Hostnames or junk pass through unchanged — runner filters later."""
        kept = _filter_internal_ips(["not.an.ip", "203.0.113.50"], self._config())
        assert kept == ["not.an.ip", "203.0.113.50"]

"""Tests for lantana.enrichment.runner error handling."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from lantana.enrichment.providers.base import EnrichmentResult
from lantana.enrichment.runner import (
    ErrorAccumulator,
    _classify_http_error,
    _enrich_ips_with_provider,
    _record_error,
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
        results = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert results == []
        assert ("test_provider", "rate_limit") in errors
        assert errors[("test_provider", "rate_limit")].count == 1

    @pytest.mark.asyncio()
    async def test_timeout_recorded(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        provider.enrich_ip.side_effect = httpx.ReadTimeout("read timed out")

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert results == []
        assert ("test_provider", "timeout") in errors

    @pytest.mark.asyncio()
    async def test_unknown_error_recorded(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        provider.enrich_ip.side_effect = ValueError("unexpected")

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert results == []
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
        results = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert len(results) == 1
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
        results = await _enrich_ips_with_provider(
            "test_provider", provider, ["1.2.3.4", "5.6.7.8"], cache, errors
        )
        cache.close()

        assert len(results) == 1
        assert results[0].ip == "1.2.3.4"
        assert ("test_provider", "rate_limit") in errors

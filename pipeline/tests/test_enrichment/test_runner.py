"""Tests for lantana.enrichment.runner."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime
from pathlib import Path  # noqa: TC003 - used at runtime in tmp_path fixtures
from unittest.mock import AsyncMock, patch

import httpx
import polars as pl
import pytest

from lantana.enrichment.providers.abuseipdb import AbuseIPDBProvider
from lantana.enrichment.providers.base import EnrichmentResult
from lantana.enrichment.providers.virustotal import VirusTotalProvider
from lantana.enrichment.runner import (
    CIRCUIT_BREAKER_RATE_LIMIT_CUMULATIVE_THRESHOLD,
    CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD,
    IOC_TYPE_HASH,
    IOC_TYPE_IP,
    ErrorAccumulator,
    _build_lookup,
    _classify_http_error,
    _enrich_iocs_with_provider,
    _get_cached,
    _init_cache,
    _merge_lookup,
    _record_error,
    _sanitize_error_message,
    _set_cached,
    _write_error_summary,
)

# --- _classify_http_error ---


class TestClassifyHttpError:
    def test_rate_limit(self) -> None:
        assert _classify_http_error(429) == "rate_limit"

    def test_auth_401(self) -> None:
        assert _classify_http_error(401) == "auth_failed"

    def test_auth_403(self) -> None:
        assert _classify_http_error(403) == "auth_failed"

    def test_not_found(self) -> None:
        assert _classify_http_error(404) == "not_found"

    def test_other_client_errors(self) -> None:
        assert _classify_http_error(400) == "http_4xx"
        assert _classify_http_error(422) == "http_4xx"

    def test_server_error(self) -> None:
        assert _classify_http_error(500) == "server_error"
        assert _classify_http_error(502) == "server_error"
        assert _classify_http_error(503) == "server_error"


# --- _sanitize_error_message ---


class TestSanitizeErrorMessage:
    """Sanitiser strips API keys from URL query strings before persistence.

    Headers-based auth (AbuseIPDB / VirusTotal / GreyNoise) never appears
    in error messages — only query-string auth (Shodan) does, but the
    sanitiser is provider-agnostic so a future provider adopting query
    auth wouldn't leak either.
    """

    def test_shodan_url_key_redacted(self) -> None:
        msg = (
            "Client error '429 Too Many Requests' for url "
            "'https://api.shodan.io/shodan/host/1.2.3.4?key=vN794DcKiMpK48MnhhKik2SwKtXxG4SJ'"
        )
        out = _sanitize_error_message(msg)
        assert "vN794DcKiMpK48MnhhKik2SwKtXxG4SJ" not in out
        assert "key=REDACTED" in out

    def test_multiple_sensitive_param_names(self) -> None:
        for param in ("api_key", "apikey", "token", "access_token"):
            msg = f"https://example.com/x?{param}=SECRET123&other=keep"
            out = _sanitize_error_message(msg)
            assert "SECRET123" not in out, param
            assert f"{param}=REDACTED" in out
            assert "other=keep" in out

    def test_case_insensitive_param_name(self) -> None:
        msg = "https://x.com/y?Key=ABC123"
        assert _sanitize_error_message(msg) == "https://x.com/y?Key=REDACTED"

    def test_param_not_at_start_of_query(self) -> None:
        msg = "https://api.shodan.io/host/1.2.3.4?ipAddress=1.2.3.4&key=SECRET"
        out = _sanitize_error_message(msg)
        assert "SECRET" not in out
        assert "ipAddress=1.2.3.4" in out

    def test_nonmatching_key_substring_preserved(self) -> None:
        # 'key' inside a path segment, JSON body, or as part of another word
        # must NOT trigger redaction.
        msg = "Failed at /v2/keystore — 'key': 'visible'"
        assert _sanitize_error_message(msg) == msg

    def test_no_change_for_clean_message(self) -> None:
        assert _sanitize_error_message("request timed out") == "request timed out"


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

    def test_shodan_url_key_sanitised_before_storage(self) -> None:
        """The bug found 2026-05-22: Shodan key was landing in enrichment_errors.json
        because httpx HTTPStatusError messages embed the full request URL."""
        errors: ErrorAccumulator = {}
        leaky_msg = (
            "Client error '429 Too Many Requests' for url "
            "'https://api.shodan.io/shodan/host/1.2.3.4?key=REAL_KEY_VALUE'"
        )
        _record_error(errors, "shodan", "rate_limit", leaky_msg)
        stored = errors[("shodan", "rate_limit")].error_message
        assert "REAL_KEY_VALUE" not in stored
        assert "key=REDACTED" in stored

    def test_sanitisation_applies_on_update_too(self) -> None:
        """The accumulator's update branch also runs through the sanitiser."""
        errors: ErrorAccumulator = {}
        _record_error(errors, "shodan", "rate_limit", "first")
        _record_error(
            errors,
            "shodan",
            "rate_limit",
            "https://x.com/y?key=LEAK_2",
        )
        assert "LEAK_2" not in errors[("shodan", "rate_limit")].error_message


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
        _record_error(errors, "virustotal", "auth_failed", "401 Unauthorized")

        errors_path = tmp_path / "enrichment_errors.json"
        _write_error_summary(errors, date(2026, 4, 28), errors_path)

        lines = errors_path.read_text().strip().splitlines()
        assert len(lines) == 3
        providers = {json.loads(line)["provider"] for line in lines}
        assert providers == {"abuseipdb", "shodan", "virustotal"}


# --- Cache helper for tests: uses production schema via _init_cache ---


def _make_cache(tmp_path: Path) -> sqlite3.Connection:
    return _init_cache(tmp_path / "test_cache.db")


# --- _enrich_iocs_with_provider (error paths) ---


class TestEnrichIocsWithProviderErrors:
    @pytest.mark.asyncio()
    async def test_http_error_recorded(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        response = httpx.Response(status_code=429, request=httpx.Request("GET", "https://api.test"))
        provider.enrich_ip.side_effect = httpx.HTTPStatusError(
            "429 Too Many Requests", request=response.request, response=response
        )

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
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
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
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
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
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
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
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
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4", "5.6.7.8"], cache, errors,
        )
        cache.close()

        assert len(results) == 1
        assert results[0].ip == "1.2.3.4"
        assert cache_hits == 0
        assert ("test_provider", "rate_limit") in errors


# --- Cache behaviour ---


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
        _set_cached(cache, "test_provider", IOC_TYPE_IP, "1.2.3.4", cached_result)

        provider = AsyncMock()
        provider.enrich_ip.side_effect = AssertionError("provider must not be called on cache hit")

        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
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
        results1, hits1 = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
        )
        results2, hits2 = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
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
        assert _get_cached(cache, "abuseipdb", IOC_TYPE_IP, "1.2.3.4") is None
        cache.close()

    def test_get_cached_handles_malformed_row(self, tmp_path: Path) -> None:
        """A corrupt cached row is treated as a miss, not a crash."""
        cache = _make_cache(tmp_path)
        cache.execute(
            "INSERT INTO cache (provider, ioc_type, ioc_value, data, queried_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("abuseipdb", IOC_TYPE_IP, "1.2.3.4", "{not json}", datetime.now(tz=UTC).isoformat()),
        )
        cache.commit()

        assert _get_cached(cache, "abuseipdb", IOC_TYPE_IP, "1.2.3.4") is None
        cache.close()


# --- Phase 2: error classification end-to-end through the provider retry path ---


class TestErrorClassificationEndToEnd:
    """Exercise provider.enrich_ip → tenacity retry → reraise=True → runner → errors."""

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(("status", "expected"), [
        (401, "auth_failed"),
        (403, "auth_failed"),
        (404, "not_found"),
        (429, "rate_limit"),
        (500, "server_error"),
        (502, "server_error"),
    ])
    async def test_status_to_error_type(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        status: int,
        expected: str,
    ) -> None:
        async def _noop_sleep(_: float) -> None:
            return None
        monkeypatch.setattr("asyncio.sleep", _noop_sleep)

        provider = AbuseIPDBProvider(api_key="test")
        request = httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check")
        response = httpx.Response(status_code=status, request=request)

        with patch.object(
            provider._client, "get", new=AsyncMock(return_value=response),
        ):
            cache = _make_cache(tmp_path)
            errors: ErrorAccumulator = {}
            results, hits = await _enrich_iocs_with_provider(
                "abuseipdb", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
            )
            cache.close()
        await provider.close()

        assert results == []
        assert hits == 0
        assert ("abuseipdb", expected) in errors, (
            f"Expected error_type={expected}, got {list(errors.keys())}"
        )
        assert ("abuseipdb", "unknown") not in errors

    @pytest.mark.asyncio()
    async def test_connect_error_classified(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        provider.enrich_ip.side_effect = httpx.ConnectError("DNS lookup failed")

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results, hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert results == []
        assert hits == 0
        assert ("test_provider", "network_error") in errors
        assert "DNS lookup failed" in errors[("test_provider", "network_error")].error_message

    @pytest.mark.asyncio()
    async def test_unknown_records_repr(self, tmp_path: Path) -> None:
        """A genuinely-unknown exception still gets recorded, with repr for debugging."""
        provider = AsyncMock()
        provider.enrich_ip.side_effect = RuntimeError("something obscure")

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ["1.2.3.4"], cache, errors,
        )
        cache.close()

        assert ("test_provider", "unknown") in errors
        msg = errors[("test_provider", "unknown")].error_message
        assert "RuntimeError" in msg
        assert "something obscure" in msg


# --- Phase 3: IOC-first architecture ---


class TestCacheSchemaMigration:
    def test_legacy_schema_dropped(self, tmp_path: Path) -> None:
        """An existing single-key schema is dropped and recreated under the new PK."""
        db_path = tmp_path / "legacy_cache.db"
        legacy = sqlite3.connect(str(db_path))
        legacy.execute(
            "CREATE TABLE cache ("
            "  key TEXT PRIMARY KEY,"
            "  provider TEXT NOT NULL,"
            "  data TEXT NOT NULL,"
            "  queried_at TEXT NOT NULL"
            ")"
        )
        legacy.execute(
            "INSERT INTO cache (key, provider, data, queried_at) VALUES (?, ?, ?, ?)",
            ("abuseipdb:1.2.3.4", "abuseipdb", "{}", datetime.now(tz=UTC).isoformat()),
        )
        legacy.commit()
        legacy.close()

        conn = _init_cache(db_path)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(cache)").fetchall()}
        assert "ioc_type" in cols
        assert "ioc_value" in cols
        assert "key" not in cols
        # Legacy row didn't survive the drop
        row_count = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        assert row_count == 0
        conn.close()

    def test_new_schema_persists(self, tmp_path: Path) -> None:
        db_path = tmp_path / "new_cache.db"
        conn = _init_cache(db_path)
        conn.close()
        # Reopen — should not drop the (already-new) table
        conn = _init_cache(db_path)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(cache)").fetchall()}
        assert "ioc_type" in cols
        conn.close()


class TestIocTypeIsolation:
    def test_ip_and_hash_with_same_value_are_separate(self, tmp_path: Path) -> None:
        """Cache entries for ioc_type=ip vs ioc_type=hash do not collide."""
        cache = _make_cache(tmp_path)
        ip_result = EnrichmentResult(
            provider="virustotal",
            ip="deadbeef",
            data={"vt_malicious_count": 7},
            queried_at=datetime.now(tz=UTC),
        )
        hash_result = EnrichmentResult(
            provider="virustotal",
            ip="deadbeef",
            data={"vt_file_malicious_count": 99},
            queried_at=datetime.now(tz=UTC),
        )
        _set_cached(cache, "virustotal", IOC_TYPE_IP, "deadbeef", ip_result)
        _set_cached(cache, "virustotal", IOC_TYPE_HASH, "deadbeef", hash_result)

        ip_back = _get_cached(cache, "virustotal", IOC_TYPE_IP, "deadbeef")
        hash_back = _get_cached(cache, "virustotal", IOC_TYPE_HASH, "deadbeef")
        cache.close()

        assert ip_back is not None
        assert hash_back is not None
        assert ip_back.data == {"vt_malicious_count": 7}
        assert hash_back.data == {"vt_file_malicious_count": 99}


class TestHashEnrichmentDispatch:
    @pytest.mark.asyncio()
    async def test_ioc_type_hash_calls_enrich_hash(self, tmp_path: Path) -> None:
        """ioc_type=hash dispatches to provider.enrich_hash, not enrich_ip."""
        provider = AsyncMock(spec=VirusTotalProvider)
        provider.enrich_hash.return_value = EnrichmentResult(
            provider="virustotal",
            ip="deadbeef",
            data={"vt_file_malicious_count": 5},
            queried_at=datetime.now(tz=UTC),
        )

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        results, _ = await _enrich_iocs_with_provider(
            "virustotal", provider, IOC_TYPE_HASH, ["deadbeef"], cache, errors,
        )
        cache.close()

        assert len(results) == 1
        assert results[0].data["vt_file_malicious_count"] == 5
        provider.enrich_hash.assert_called_once_with("deadbeef")
        provider.enrich_ip.assert_not_called()

    @pytest.mark.asyncio()
    async def test_hash_dispatch_rejects_non_vt_provider(self, tmp_path: Path) -> None:
        provider = AsyncMock(spec=AbuseIPDBProvider)
        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        # The TypeError is raised inside _query_provider; the runner's
        # catch-all records it as 'unknown' since it's not an HTTP/timeout/network
        # exception. The IOC is still consumed (i.e. not retried in a loop).
        results, _ = await _enrich_iocs_with_provider(
            "abuseipdb", provider, IOC_TYPE_HASH, ["deadbeef"], cache, errors,
        )
        cache.close()

        assert results == []
        assert ("abuseipdb", "unknown") in errors
        assert "VirusTotal" in errors[("abuseipdb", "unknown")].error_message


class TestMergeLookup:
    def test_joins_enrichment_columns(self) -> None:
        df = pl.DataFrame({
            "src_ip": ["203.0.113.50", "198.51.100.22"],
            "event": ["login", "alert"],
        })
        lookup: dict[str, dict[str, str | int | float | bool | None]] = {
            "203.0.113.50": {"abuseipdb_confidence_score": 88},
            "198.51.100.22": {"abuseipdb_confidence_score": 12},
        }
        merged = _merge_lookup(df, "src_ip", lookup)
        assert "abuseipdb_confidence_score" in merged.columns
        scores = dict(zip(
            merged.get_column("src_ip").to_list(),
            merged.get_column("abuseipdb_confidence_score").to_list(),
            strict=True,
        ))
        assert scores["203.0.113.50"] == 88
        assert scores["198.51.100.22"] == 12

    def test_no_join_col_returns_original(self) -> None:
        df = pl.DataFrame({"event": ["login"]})
        lookup: dict[str, dict[str, str | int | float | bool | None]] = {
            "203.0.113.50": {"score": 1},
        }
        merged = _merge_lookup(df, "src_ip", lookup)
        # No src_ip column → no-op
        assert merged.columns == df.columns

    def test_empty_lookup_returns_original(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50"]})
        merged = _merge_lookup(df, "src_ip", {})
        assert merged.columns == df.columns

    def test_unmatched_rows_get_nulls(self) -> None:
        df = pl.DataFrame({"src_ip": ["203.0.113.50", "203.0.113.99"]})
        lookup: dict[str, dict[str, str | int | float | bool | None]] = {
            "203.0.113.50": {"score": 1},
        }
        merged = _merge_lookup(df, "src_ip", lookup)
        scores = merged.get_column("score").to_list()
        assert scores == [1, None]


class TestBuildLookup:
    def test_merges_results_per_value(self) -> None:
        r1 = EnrichmentResult(
            provider="abuseipdb",
            ip="203.0.113.50",
            data={"abuseipdb_confidence_score": 88},
            queried_at=datetime.now(tz=UTC),
        )
        r2 = EnrichmentResult(
            provider="shodan",
            ip="203.0.113.50",
            data={"shodan_ports": "22,80"},
            queried_at=datetime.now(tz=UTC),
        )
        r3 = EnrichmentResult(
            provider="abuseipdb",
            ip="198.51.100.22",
            data={"abuseipdb_confidence_score": 12},
            queried_at=datetime.now(tz=UTC),
        )
        lookup = _build_lookup([r1, r2, r3])
        assert lookup["203.0.113.50"] == {
            "abuseipdb_confidence_score": 88, "shodan_ports": "22,80",
        }
        assert lookup["198.51.100.22"] == {"abuseipdb_confidence_score": 12}

    def test_empty_list(self) -> None:
        assert _build_lookup([]) == {}


class TestIocDedupAcrossDatasets:
    """When the same IP appears in multiple bronze datasets, the provider
    must only be queried once. Phase 3's IOC-first extraction makes this
    structural: IPs are deduped before the provider loop, so the join
    later is what fan-outs the enrichment per-dataset, not the API call.
    """

    @pytest.mark.asyncio()
    async def test_shared_ip_queried_once(self, tmp_path: Path) -> None:
        provider = AsyncMock()
        provider.enrich_ip.return_value = EnrichmentResult(
            provider="test_provider",
            ip="203.0.113.50",
            data={"score": 75},
            queried_at=datetime.now(tz=UTC),
        )
        # Simulate: cowrie bronze + suricata bronze both contain 203.0.113.50.
        # IOC extraction (set semantics in ioc.py) collapses to one entry.
        # _enrich_iocs_with_provider is called once with the deduped list.
        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        unique_ips = ["203.0.113.50"]  # already deduped via set in runner
        results, _ = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, unique_ips, cache, errors,
        )
        cache.close()

        assert provider.enrich_ip.call_count == 1
        assert len(results) == 1


# --- Circuit breaker ---


def _rate_limit_error() -> httpx.HTTPStatusError:
    req = httpx.Request("GET", "https://api.test")
    resp = httpx.Response(status_code=429, request=req)
    return httpx.HTTPStatusError("429 Too Many Requests", request=req, response=resp)


def _auth_error() -> httpx.HTTPStatusError:
    req = httpx.Request("GET", "https://api.test")
    resp = httpx.Response(status_code=401, request=req)
    return httpx.HTTPStatusError("401 Unauthorized", request=req, response=resp)


class TestCircuitBreaker:
    @pytest.mark.asyncio()
    async def test_rate_limit_trips_after_threshold(self, tmp_path: Path) -> None:
        """N consecutive rate_limit failures stop the loop, skipping remaining IOCs."""
        provider = AsyncMock()
        provider.enrich_ip.side_effect = _rate_limit_error()

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        # Threshold + 10 IPs in queue. Should bail after threshold attempts.
        ips = [f"203.0.113.{i}" for i in range(1, CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD + 11)]
        results, _ = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ips, cache, errors,
        )
        cache.close()

        assert results == []
        # The breaker fires on the IP AFTER the threshold-th failure (the next
        # iteration sees the counter at threshold and breaks before calling).
        # So total calls = threshold.
        assert provider.enrich_ip.call_count == CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD
        assert ("test_provider", "rate_limit") in errors

    @pytest.mark.asyncio()
    async def test_cumulative_rate_limit_trips_through_cache_interleave(
        self, tmp_path: Path,
    ) -> None:
        """Scattered cache hits must not let an exhausted provider keep going.

        Defect #11 from op_alpha 2026-05-21: Shodan had ~25% cache coverage
        of a 4670-IP queue. Cache hits reset the consecutive counter every
        few misses, the consecutive breaker never tripped, and the runner
        ground through ~3400 fresh API calls — each one a 429. The
        cumulative threshold is the safety net for this interleaving
        pattern.
        """
        cache = _make_cache(tmp_path)
        # Seed cache: every 5th IP is a hit, the rest are misses.
        for i in range(0, 500, 5):
            _set_cached(
                cache, "test_provider", IOC_TYPE_IP, f"203.0.113.{i}",
                EnrichmentResult(
                    provider="test_provider", ip=f"203.0.113.{i}",
                    data={"hit": True}, queried_at=datetime.now(tz=UTC),
                ),
            )

        provider = AsyncMock()
        provider.enrich_ip.side_effect = _rate_limit_error()

        errors: ErrorAccumulator = {}
        ips = [f"203.0.113.{i}" for i in range(500)]  # 500 IPs, 100 cached, 400 miss
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ips, cache, errors,
        )
        cache.close()

        # The cumulative breaker (30 total 429s) trips long before we attempt
        # all 400 misses — the consecutive breaker never trips because every
        # 4-5 misses gets interrupted by a cache hit.
        assert provider.enrich_ip.call_count <= CIRCUIT_BREAKER_RATE_LIMIT_CUMULATIVE_THRESHOLD
        assert cache_hits > 0  # cache hits accumulated before the break
        # Only cached entries made it into results — fresh calls all 429'd.
        assert len(results) == cache_hits

    @pytest.mark.asyncio()
    async def test_success_resets_counter(self, tmp_path: Path) -> None:
        """A successful call resets the consecutive-failure counter."""
        provider = AsyncMock()
        ok = EnrichmentResult(
            provider="test_provider",
            ip="ok",
            data={"score": 1},
            queried_at=datetime.now(tz=UTC),
        )
        # Pattern: threshold-1 rate_limits, then success, then threshold-1 more
        # rate_limits — should NOT trip (counter reset by success).
        pre = [_rate_limit_error()] * (CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD - 1)
        post = [_rate_limit_error()] * (CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD - 1)
        provider.enrich_ip.side_effect = [*pre, ok, *post]

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        ips = [f"203.0.113.{i}" for i in range(1, len(pre) + len(post) + 2)]
        results, _ = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ips, cache, errors,
        )
        cache.close()

        # All IPs attempted because counter resets on the success.
        assert provider.enrich_ip.call_count == len(ips)
        assert len(results) == 1  # only the one success

    @pytest.mark.asyncio()
    async def test_cache_hit_resets_counter(self, tmp_path: Path) -> None:
        """A cache hit between failures also resets the breaker."""
        cache = _make_cache(tmp_path)
        cached = EnrichmentResult(
            provider="test_provider",
            ip="cached.ip",
            data={"score": 1},
            queried_at=datetime.now(tz=UTC),
        )
        _set_cached(cache, "test_provider", IOC_TYPE_IP, "cached.ip", cached)

        provider = AsyncMock()
        provider.enrich_ip.side_effect = _rate_limit_error()

        # threshold-1 fails, then cache hit, then threshold-1 fails → no trip
        ips: list[str] = []
        for i in range(CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD - 1):
            ips.append(f"203.0.113.{i}")
        ips.append("cached.ip")
        for i in range(CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD - 1):
            ips.append(f"203.0.114.{i}")

        errors: ErrorAccumulator = {}
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ips, cache, errors,
        )
        cache.close()

        # Provider called for every non-cached IP.
        assert provider.enrich_ip.call_count == len(ips) - 1
        assert cache_hits == 1
        # Cached result is the one entry in results; no successes from API.
        assert len(results) == 1

    @pytest.mark.asyncio()
    async def test_auth_failed_trips_immediately(self, tmp_path: Path) -> None:
        """A single auth_failed short-circuits the provider's queue."""
        provider = AsyncMock()
        provider.enrich_ip.side_effect = _auth_error()

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        ips = [f"203.0.113.{i}" for i in range(1, 21)]
        results, _ = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ips, cache, errors,
        )
        cache.close()

        assert results == []
        # One call burnt to discover auth is broken, then bail.
        assert provider.enrich_ip.call_count == 1
        assert ("test_provider", "auth_failed") in errors

    @pytest.mark.asyncio()
    async def test_transient_errors_dont_count(self, tmp_path: Path) -> None:
        """timeout / network_error / unknown do NOT count toward the rate-limit trip."""
        provider = AsyncMock()
        provider.enrich_ip.side_effect = [
            httpx.ReadTimeout("transient"),
            httpx.ConnectError("transient"),
            ValueError("unexpected"),
            EnrichmentResult(
                provider="test_provider",
                ip="ok",
                data={"score": 1},
                queried_at=datetime.now(tz=UTC),
            ),
        ]

        cache = _make_cache(tmp_path)
        errors: ErrorAccumulator = {}
        ips = ["a", "b", "c", "d"]
        results, _ = await _enrich_iocs_with_provider(
            "test_provider", provider, IOC_TYPE_IP, ips, cache, errors,
        )
        cache.close()

        # All four attempted; the last succeeds. No premature bail.
        assert provider.enrich_ip.call_count == 4
        assert len(results) == 1

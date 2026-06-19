"""Tests for lantana.enrichment.runner."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path  # noqa: TC003 - used at runtime in tmp_path fixtures
from unittest.mock import AsyncMock, patch

import httpx
import polars as pl
import pytest

from lantana.enrichment.providers.abuseipdb import AbuseIPDBProvider
from lantana.enrichment.providers.base import EnrichmentResult
from lantana.enrichment.providers.virustotal import VirusTotalProvider
from lantana.enrichment.runner import (
    CACHE_TTL_BENIGN_DAYS,
    CACHE_TTL_MALICIOUS_DOMAIN_DAYS,
    CACHE_TTL_MALICIOUS_HASH_DAYS,
    CACHE_TTL_MALICIOUS_IP_DAYS,
    CIRCUIT_BREAKER_RATE_LIMIT_CUMULATIVE_THRESHOLD,
    CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD,
    IOC_TYPE_DOMAIN,
    IOC_TYPE_HASH,
    IOC_TYPE_IP,
    RISK_SCORE_MALICIOUS_THRESHOLD,
    ErrorAccumulator,
    ProviderState,
    _build_lookup,
    _classify_http_error,
    _classify_ttl,
    _compute_ip_event_counts,
    _enrich_iocs_with_provider,
    _ensure_ip_score_columns,
    _get_cached,
    _init_cache,
    _load_provider_state,
    _merge_lookup,
    _record_error,
    _sanitize_error_message,
    _save_provider_state,
    _select_ips_for_provider,
    _set_cached,
    _should_skip_provider,
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
        old_entry = json.dumps(
            {
                "date": "2026-04-27",
                "provider": "shodan",
                "error_type": "timeout",
                "count": 1,
                "message": "old",
            }
        )
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4", "5.6.7.8"],
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
        )
        results2, hits2 = await _enrich_iocs_with_provider(
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
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
        """A corrupt cached row is treated as a miss, not a crash.

        Populates ``expires_at`` so the SQL freshness filter doesn't
        short-circuit before the JSON decode path is exercised.
        """
        cache = _make_cache(tmp_path)
        now = datetime.now(tz=UTC)
        cache.execute(
            "INSERT INTO cache (provider, ioc_type, ioc_value, data, queried_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "abuseipdb",
                IOC_TYPE_IP,
                "1.2.3.4",
                "{not json}",
                now.isoformat(),
                (now + timedelta(days=1)).isoformat(),
            ),
        )
        cache.commit()

        assert _get_cached(cache, "abuseipdb", IOC_TYPE_IP, "1.2.3.4") is None
        cache.close()

    def test_expired_row_not_returned(self, tmp_path: Path) -> None:
        """A row whose expires_at is in the past must not be returned."""
        cache = _make_cache(tmp_path)
        now = datetime.now(tz=UTC)
        cache.execute(
            "INSERT INTO cache (provider, ioc_type, ioc_value, data, queried_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "abuseipdb",
                IOC_TYPE_IP,
                "1.2.3.4",
                json.dumps({"abuseipdb_risk_score": 90}),
                (now - timedelta(days=10)).isoformat(),
                (now - timedelta(seconds=1)).isoformat(),
            ),
        )
        cache.commit()
        assert _get_cached(cache, "abuseipdb", IOC_TYPE_IP, "1.2.3.4") is None
        cache.close()

    def test_unexpired_row_returned(self, tmp_path: Path) -> None:
        """A row whose expires_at is in the future must be returned."""
        cache = _make_cache(tmp_path)
        now = datetime.now(tz=UTC)
        cache.execute(
            "INSERT INTO cache (provider, ioc_type, ioc_value, data, queried_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "abuseipdb",
                IOC_TYPE_IP,
                "1.2.3.4",
                json.dumps({"abuseipdb_risk_score": 90}),
                now.isoformat(),
                (now + timedelta(days=30)).isoformat(),
            ),
        )
        cache.commit()
        result = _get_cached(cache, "abuseipdb", IOC_TYPE_IP, "1.2.3.4")
        cache.close()
        assert result is not None
        assert result.data["abuseipdb_risk_score"] == 90

    def test_null_expires_at_row_not_returned(self, tmp_path: Path) -> None:
        """Rows written before the write path was switched (NULL expires_at)
        must read as misses — SQL three-valued logic excludes them and the
        next pipeline run re-queries them under the new policy."""
        cache = _make_cache(tmp_path)
        cache.execute(
            "INSERT INTO cache (provider, ioc_type, ioc_value, data, queried_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, NULL)",
            (
                "abuseipdb",
                IOC_TYPE_IP,
                "1.2.3.4",
                json.dumps({"abuseipdb_risk_score": 90}),
                datetime.now(tz=UTC).isoformat(),
            ),
        )
        cache.commit()
        assert _get_cached(cache, "abuseipdb", IOC_TYPE_IP, "1.2.3.4") is None
        cache.close()


class TestClassifyTtl:
    """Per-row TTL classification.

    A cache row is "malicious" iff its provider risk_score field is
    present in result.data and ≥ RISK_SCORE_MALICIOUS_THRESHOLD.
    Malicious rows get the long ioc_type-specific window (OpenCTI
    defaults: 60 / 90 / 180 days); everything else gets 7 days.
    """

    def test_benign_ip_gets_7d(self) -> None:
        ttl = _classify_ttl("abuseipdb", IOC_TYPE_IP, {"abuseipdb_risk_score": 10})
        assert ttl == timedelta(days=CACHE_TTL_BENIGN_DAYS)

    def test_malicious_ip_gets_60d(self) -> None:
        ttl = _classify_ttl("abuseipdb", IOC_TYPE_IP, {"abuseipdb_risk_score": 90})
        assert ttl == timedelta(days=CACHE_TTL_MALICIOUS_IP_DAYS)

    def test_malicious_domain_gets_90d(self) -> None:
        ttl = _classify_ttl("abuseipdb", IOC_TYPE_DOMAIN, {"abuseipdb_risk_score": 90})
        assert ttl == timedelta(days=CACHE_TTL_MALICIOUS_DOMAIN_DAYS)

    def test_malicious_hash_gets_180d(self) -> None:
        ttl = _classify_ttl("virustotal", IOC_TYPE_HASH, {"vt_file_risk_score": 75})
        assert ttl == timedelta(days=CACHE_TTL_MALICIOUS_HASH_DAYS)

    def test_benign_hash_gets_7d(self) -> None:
        ttl = _classify_ttl("virustotal", IOC_TYPE_HASH, {"vt_file_risk_score": 0})
        assert ttl == timedelta(days=CACHE_TTL_BENIGN_DAYS)

    def test_missing_risk_score_defaults_benign(self) -> None:
        """Empty/legacy data dicts — no risk_score field — get the benign tier."""
        ttl = _classify_ttl("abuseipdb", IOC_TYPE_IP, {})
        assert ttl == timedelta(days=CACHE_TTL_BENIGN_DAYS)

    def test_unknown_provider_defaults_benign(self) -> None:
        """A provider not in _RISK_SCORE_FIELDS cannot be classified malicious."""
        ttl = _classify_ttl("unknown_provider", IOC_TYPE_IP, {"risk_score": 100})
        assert ttl == timedelta(days=CACHE_TTL_BENIGN_DAYS)

    def test_threshold_boundary_50_is_malicious(self) -> None:
        """Exactly RISK_SCORE_MALICIOUS_THRESHOLD crosses into the malicious tier."""
        ttl = _classify_ttl(
            "abuseipdb",
            IOC_TYPE_IP,
            {"abuseipdb_risk_score": RISK_SCORE_MALICIOUS_THRESHOLD},
        )
        assert ttl == timedelta(days=CACHE_TTL_MALICIOUS_IP_DAYS)

    def test_threshold_just_below_50_is_benign(self) -> None:
        ttl = _classify_ttl("abuseipdb", IOC_TYPE_IP, {"abuseipdb_risk_score": 49.99})
        assert ttl == timedelta(days=CACHE_TTL_BENIGN_DAYS)

    def test_virustotal_dual_field_picks_ip_score(self) -> None:
        """VT IP rows expose virustotal_risk_score (not vt_file_risk_score)."""
        ttl = _classify_ttl("virustotal", IOC_TYPE_IP, {"virustotal_risk_score": 100})
        assert ttl == timedelta(days=CACHE_TTL_MALICIOUS_IP_DAYS)

    def test_virustotal_dual_field_picks_file_score(self) -> None:
        """VT hash rows expose vt_file_risk_score (not virustotal_risk_score)."""
        ttl = _classify_ttl("virustotal", IOC_TYPE_HASH, {"vt_file_risk_score": 100})
        assert ttl == timedelta(days=CACHE_TTL_MALICIOUS_HASH_DAYS)

    def test_bool_value_in_score_field_treated_as_missing(self) -> None:
        """Defensive — bool is an int subclass in Python but should NOT be
        misread as a risk score by the isinstance check."""
        ttl = _classify_ttl("abuseipdb", IOC_TYPE_IP, {"abuseipdb_risk_score": True})
        assert ttl == timedelta(days=CACHE_TTL_BENIGN_DAYS)


# --- Phase 2: error classification end-to-end through the provider retry path ---


class TestErrorClassificationEndToEnd:
    """Exercise provider.enrich_ip → tenacity retry → reraise=True → runner → errors."""

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (401, "auth_failed"),
            (403, "auth_failed"),
            (404, "not_found"),
            (429, "rate_limit"),
            (500, "server_error"),
            (502, "server_error"),
        ],
    )
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
            provider._client,
            "get",
            new=AsyncMock(return_value=response),
        ):
            cache = _make_cache(tmp_path)
            errors: ErrorAccumulator = {}
            results, hits = await _enrich_iocs_with_provider(
                "abuseipdb",
                provider,
                IOC_TYPE_IP,
                ["1.2.3.4"],
                cache,
                errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ["1.2.3.4"],
            cache,
            errors,
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
        assert "expires_at" in cols
        conn.close()

    def test_pre_expires_at_schema_dropped(self, tmp_path: Path) -> None:
        """A v3 cache (composite PK, no expires_at) is dropped and recreated.

        Up to 7 days of data is lost — providers refill on the next run.
        Same trade-off accepted for the v2→v3 migration.
        """
        db_path = tmp_path / "v3_cache.db"
        v3 = sqlite3.connect(str(db_path))
        v3.execute(
            "CREATE TABLE cache ("
            "  provider TEXT NOT NULL,"
            "  ioc_type TEXT NOT NULL,"
            "  ioc_value TEXT NOT NULL,"
            "  data TEXT NOT NULL,"
            "  queried_at TEXT NOT NULL,"
            "  PRIMARY KEY (provider, ioc_type, ioc_value)"
            ")"
        )
        v3.execute(
            "INSERT INTO cache (provider, ioc_type, ioc_value, data, queried_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("abuseipdb", IOC_TYPE_IP, "1.2.3.4", "{}", datetime.now(tz=UTC).isoformat()),
        )
        v3.commit()
        v3.close()

        conn = _init_cache(db_path)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(cache)").fetchall()}
        assert "expires_at" in cols
        # The v3 row didn't survive the drop
        assert conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0] == 0
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
            "virustotal",
            provider,
            IOC_TYPE_HASH,
            ["deadbeef"],
            cache,
            errors,
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
            "abuseipdb",
            provider,
            IOC_TYPE_HASH,
            ["deadbeef"],
            cache,
            errors,
        )
        cache.close()

        assert results == []
        assert ("abuseipdb", "unknown") in errors
        assert "VirusTotal" in errors[("abuseipdb", "unknown")].error_message


class TestMergeLookup:
    def test_joins_enrichment_columns(self) -> None:
        df = pl.DataFrame(
            {
                "src_ip": ["203.0.113.50", "198.51.100.22"],
                "event": ["login", "alert"],
            }
        )
        lookup: dict[str, dict[str, str | int | float | bool | None]] = {
            "203.0.113.50": {"abuseipdb_confidence_score": 88},
            "198.51.100.22": {"abuseipdb_confidence_score": 12},
        }
        merged = _merge_lookup(df, "src_ip", lookup)
        assert "abuseipdb_confidence_score" in merged.columns
        scores = dict(
            zip(
                merged.get_column("src_ip").to_list(),
                merged.get_column("abuseipdb_confidence_score").to_list(),
                strict=True,
            )
        )
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


class TestEnsureIpScoreColumns:
    """Phase D.1 invariant: silver always carries all four per-provider risk_score columns.

    When a provider is skipped (rate-limit window, unconfigured) or produces
    zero successful enrichments, _merge_lookup leaves that provider's column
    absent. _ensure_ip_score_columns backfills typed-null Float64 columns so
    every cowrie/suricata/nftables/dionaea silver write carries the same
    schema regardless of which providers happened to have budget that day.
    """

    def test_all_columns_present_passthrough(self) -> None:
        df = pl.DataFrame(
            {
                "src_ip": ["203.0.113.50"],
                "abuseipdb_risk_score": [88.0],
                "virustotal_risk_score": [50.0],
                "shodan_risk_score": [100.0],
                "greynoise_risk_score": [75.0],
            }
        )
        out = _ensure_ip_score_columns(df)
        assert out.columns == df.columns
        assert out.height == 1

    def test_missing_columns_added_as_nulls(self) -> None:
        """All four providers skipped — only src_ip present. Add all four columns."""
        df = pl.DataFrame({"src_ip": ["203.0.113.50"]})
        out = _ensure_ip_score_columns(df)
        for col in (
            "abuseipdb_risk_score",
            "virustotal_risk_score",
            "shodan_risk_score",
            "greynoise_risk_score",
        ):
            assert col in out.columns
            assert out.get_column(col).to_list() == [None]
            assert out.schema[col] == pl.Float64

    def test_partial_columns_filled(self) -> None:
        """Shodan + GreyNoise skipped (production case 2026-05-25 after migration)."""
        df = pl.DataFrame(
            {
                "src_ip": ["203.0.113.50"],
                "abuseipdb_risk_score": [88.0],
                "virustotal_risk_score": [50.0],
            }
        )
        out = _ensure_ip_score_columns(df)
        assert out.get_column("abuseipdb_risk_score").to_list() == [88.0]
        assert out.get_column("virustotal_risk_score").to_list() == [50.0]
        assert out.get_column("shodan_risk_score").to_list() == [None]
        assert out.get_column("greynoise_risk_score").to_list() == [None]

    def test_empty_df_unchanged(self) -> None:
        df = pl.DataFrame({"src_ip": []})
        out = _ensure_ip_score_columns(df)
        assert out.height == 0
        # Empty DF intentionally doesn't get columns backfilled — silver-write
        # logic upstream skips empty datasets entirely via
        # `silver_skipped_empty_after_normalize`, so adding columns here
        # would be dead work.
        assert "shodan_risk_score" not in out.columns


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
            "abuseipdb_confidence_score": 88,
            "shodan_ports": "22,80",
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            unique_ips,
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ips,
            cache,
            errors,
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
        self,
        tmp_path: Path,
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
                cache,
                "test_provider",
                IOC_TYPE_IP,
                f"203.0.113.{i}",
                EnrichmentResult(
                    provider="test_provider",
                    ip=f"203.0.113.{i}",
                    data={"hit": True},
                    queried_at=datetime.now(tz=UTC),
                ),
            )

        provider = AsyncMock()
        provider.enrich_ip.side_effect = _rate_limit_error()

        errors: ErrorAccumulator = {}
        ips = [f"203.0.113.{i}" for i in range(500)]  # 500 IPs, 100 cached, 400 miss
        results, cache_hits = await _enrich_iocs_with_provider(
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ips,
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ips,
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ips,
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ips,
            cache,
            errors,
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
            "test_provider",
            provider,
            IOC_TYPE_IP,
            ips,
            cache,
            errors,
        )
        cache.close()

        # All four attempted; the last succeeds. No premature bail.
        assert provider.enrich_ip.call_count == 4
        assert len(results) == 1


# --- Provider state + IP selection policy ---


class TestProviderStateRoundtrip:
    def test_load_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert _load_provider_state(tmp_path / "nope.json") == {}

    def test_load_malformed_file_returns_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")
        assert _load_provider_state(p) == {}

    def test_save_then_load_roundtrip(self, tmp_path: Path) -> None:
        p = tmp_path / "state.json"
        state: ProviderState = {
            "greynoise": {"last_rate_limited": "2026-05-22"},
            "shodan": {"last_rate_limited": "2026-05-21"},
        }
        _save_provider_state(p, state)
        assert _load_provider_state(p) == state

    def test_save_is_atomic_no_partial_file_on_failure(self, tmp_path: Path) -> None:
        """A successful save leaves no .tmp file behind."""
        p = tmp_path / "state.json"
        _save_provider_state(p, {"x": {"k": "v"}})
        assert not (tmp_path / "state.json.tmp").exists()

    def test_load_drops_non_string_entries(self, tmp_path: Path) -> None:
        """Hand-edited state with junk values is silently normalised."""
        p = tmp_path / "state.json"
        p.write_text(
            json.dumps(
                {
                    "greynoise": {"last_rate_limited": "2026-05-22", "junk": 42},
                    "weird": [1, 2, 3],
                }
            )
        )
        loaded = _load_provider_state(p)
        assert loaded == {"greynoise": {"last_rate_limited": "2026-05-22"}}


class TestShouldSkipProvider:
    def test_no_policy_never_skips(self) -> None:
        """abuseipdb / virustotal have no policy; never skip."""
        assert _should_skip_provider("abuseipdb", {}, date(2026, 5, 22)) is False
        assert _should_skip_provider("virustotal", {}, date(2026, 5, 22)) is False

    def test_no_prior_trip_never_skips(self) -> None:
        """GreyNoise with no recorded trip runs normally."""
        assert _should_skip_provider("greynoise", {}, date(2026, 5, 22)) is False

    def test_within_skip_window_skips(self) -> None:
        """GN policy: 6-day window. Trip on day 0, attempt on day 5 → skip."""
        state: ProviderState = {"greynoise": {"last_rate_limited": "2026-05-15"}}
        assert _should_skip_provider("greynoise", state, date(2026, 5, 20)) is True

    def test_at_skip_window_boundary_resumes(self) -> None:
        """Trip on day 0, attempt on day 6 → resume (window is < not <=)."""
        state: ProviderState = {"greynoise": {"last_rate_limited": "2026-05-15"}}
        assert _should_skip_provider("greynoise", state, date(2026, 5, 21)) is False

    def test_shodan_28_day_window(self) -> None:
        """Shodan's 28-day window must respect its monthly quota."""
        state: ProviderState = {"shodan": {"last_rate_limited": "2026-04-25"}}
        # Day 27 since trip → still in window
        assert _should_skip_provider("shodan", state, date(2026, 5, 22)) is True
        # Day 28 → out of window
        assert _should_skip_provider("shodan", state, date(2026, 5, 23)) is False

    def test_malformed_date_string_treated_as_no_trip(self) -> None:
        """Hand-edited state with garbage date doesn't crash."""
        state: ProviderState = {"greynoise": {"last_rate_limited": "yesterday"}}
        assert _should_skip_provider("greynoise", state, date(2026, 5, 22)) is False


class TestComputeIpEventCounts:
    def test_single_dataset(self) -> None:
        df = pl.DataFrame({"src_ip": ["1.1.1.1", "1.1.1.1", "2.2.2.2"]})
        counts = _compute_ip_event_counts({"cowrie": df})
        assert counts == {"1.1.1.1": 2, "2.2.2.2": 1}

    def test_multi_dataset_sums(self) -> None:
        cowrie = pl.DataFrame({"src_ip": ["1.1.1.1", "1.1.1.1"]})
        suricata = pl.DataFrame({"src_ip": ["1.1.1.1", "2.2.2.2", "2.2.2.2"]})
        counts = _compute_ip_event_counts({"cowrie": cowrie, "suricata": suricata})
        assert counts == {"1.1.1.1": 3, "2.2.2.2": 2}

    def test_missing_src_ip_column_skipped(self) -> None:
        """A dataset without src_ip (broken normaliser, malformed bronze) is ignored."""
        good = pl.DataFrame({"src_ip": ["1.1.1.1"]})
        bad = pl.DataFrame({"other_col": ["x"]})
        counts = _compute_ip_event_counts({"good": good, "bad": bad})
        assert counts == {"1.1.1.1": 1}

    def test_empty_dataset_contributes_nothing(self) -> None:
        empty = pl.DataFrame({"src_ip": []}, schema={"src_ip": pl.Utf8})
        non_empty = pl.DataFrame({"src_ip": ["1.1.1.1"]})
        assert _compute_ip_event_counts({"e": empty, "ne": non_empty}) == {"1.1.1.1": 1}


class TestSelectIpsForProvider:
    def test_no_policy_returns_unchanged(self) -> None:
        ips = ["a", "b", "c"]
        assert _select_ips_for_provider("abuseipdb", ips, {"a": 5, "b": 1}) == ips

    def test_greynoise_subsamples_top_n_by_count(self) -> None:
        """GN policy: top 40. With 50 IPs, return the 40 with highest event counts."""
        ips = [f"ip{i:03d}" for i in range(50)]
        counts = {f"ip{i:03d}": (50 - i) for i in range(50)}  # ip000 is hottest
        selected = _select_ips_for_provider("greynoise", ips, counts)
        assert len(selected) == 40
        assert selected[0] == "ip000"
        assert selected[-1] == "ip039"

    def test_smaller_than_n_returns_unchanged(self) -> None:
        """If the input list is below the cap, no subsampling happens."""
        ips = ["a", "b", "c"]
        selected = _select_ips_for_provider("greynoise", ips, {"a": 1, "b": 2, "c": 3})
        assert selected == ips

    def test_tie_break_alphabetical_when_subsampling(self) -> None:
        """When subsampling fires, identical-count IPs sort alphabetically.

        Sized to force GN's 40-cap to actually kick in; without enough
        IPs the function short-circuits and returns the input unchanged.
        """
        ips = [f"ip-{c:03d}" for c in range(50)]
        # All same count → tie-break decides which 40 of the 50 win.
        counts = dict.fromkeys(ips, 5)
        first = _select_ips_for_provider("greynoise", ips, counts)
        second = _select_ips_for_provider("greynoise", ips, counts)
        assert first == second  # determinism
        assert len(first) == 40
        # Alphabetical tie-break means the first 40 alphabetically win.
        assert first == sorted(ips)[:40]


class TestEnrichmentIOCOrdering:
    """VT's 500/day free-tier quota is shared across hash + IP endpoints,
    and op_alpha sees ~30x more unique IPs than hashes per day. From
    2026-06-11 onwards the IP loop ran first and burned the whole quota
    before the hash loop fired — every brief showed Family=?, Type=?,
    Detections=? because `vt_file_*` columns never made it into silver.
    The runner now enriches hashes first; this test pins that order.
    """

    @pytest.mark.asyncio()
    async def test_hashes_enriched_before_ips(self, tmp_path: Path) -> None:
        from lantana.common.config import (
            OperationConfig,
            OperatorConfig,
            RedactConfig,
            ReportingConfig,
            SecretsConfig,
            SharingConfig,
        )
        from lantana.enrichment.runner import run_enrichment

        secrets = SecretsConfig(
            vault_apikey_virustotal="vt-key",
            vault_apikey_shodan="shodan-key",
            vault_apikey_abuseipdb="abuse-key",
            vault_apikey_greynoise=None,
            vault_apikey_maxmind=None,
            vault_webhook_discord="",
        )
        reporting = ReportingConfig(
            operator=OperatorConfig(
                name="op", handle="op", contact="op@example.com", pgp_fingerprint=""
            ),
            sharing=SharingConfig(tlp="amber", community="", discord_channel=""),
            operation=OperationConfig(
                name="op_test",
                description="",
                sector="",
                region="",
                start_date="2026-06-18",
            ),
            redact=RedactConfig(
                infrastructure_ips=[],
                infrastructure_cidrs=[],
                pseudonym_map={},
            ),
        )

        bronze = pl.DataFrame(
            {
                "src_ip": ["203.0.113.5"],
                "eventid": ["cowrie.session.file_download"],
                "shasum": ["a" * 64],
                "timestamp": ["2026-06-18T12:00:00Z"],
            }
        )

        def fake_read_bronze(target_date: date, dataset: str) -> pl.DataFrame:
            return bronze if dataset == "cowrie" else pl.DataFrame()

        call_log: list[tuple[str, str]] = []

        async def fake_enrich(
            provider_name: str,
            provider: object,
            ioc_type: str,
            iocs: list[str],
            cache: sqlite3.Connection,
            errors: ErrorAccumulator,
        ) -> tuple[list[EnrichmentResult], int]:
            call_log.append((provider_name, ioc_type))
            return [], 0

        with (
            patch("lantana.enrichment.runner.load_secrets", return_value=secrets),
            patch("lantana.enrichment.runner.load_reporting", return_value=reporting),
            patch("lantana.enrichment.runner.read_bronze_ndjson", side_effect=fake_read_bronze),
            patch(
                "lantana.enrichment.runner.extract_hashes_from_disk",
                return_value=set(),
            ),
            patch(
                "lantana.enrichment.runner._enrich_iocs_with_provider",
                side_effect=fake_enrich,
            ),
            patch(
                "lantana.enrichment.runner.normalize_dataset",
                return_value=pl.DataFrame(),
            ),
        ):
            await run_enrichment(
                target_date=date(2026, 6, 18),
                cache_db_path=tmp_path / "cache.db",
                sensor_dir=tmp_path / "sensor",
                errors_path=tmp_path / "errors.json",
                provider_state_path=tmp_path / "state.json",
            )

        assert call_log, "no enrichment calls were dispatched"
        assert call_log[0] == ("virustotal", IOC_TYPE_HASH), (
            f"hash enrichment must run first; got {call_log[0]}"
        )
        ip_indices = [i for i, (_, t) in enumerate(call_log) if t == IOC_TYPE_IP]
        hash_indices = [i for i, (_, t) in enumerate(call_log) if t == IOC_TYPE_HASH]
        assert hash_indices and ip_indices, "expected both hash and IP calls"
        assert max(hash_indices) < min(ip_indices), (
            f"all hash calls must precede all IP calls; got {call_log}"
        )

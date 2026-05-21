"""Tests for the VirusTotal enrichment provider."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from lantana.enrichment.providers.virustotal import VirusTotalProvider


@pytest.fixture()
def provider() -> VirusTotalProvider:
    return VirusTotalProvider(api_key="test-key")


def _ok_ip_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1},
                    "reputation": -5,
                    "as_owner": "Example Hosting",
                },
            },
        },
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"),
    )


def _ok_hash_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 30, "undetected": 40},
                    "meaningful_name": "evil.bin",
                    "type_tag": "elf",
                },
            },
        },
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/abc"),
    )


class TestVirusTotalIP:
    @pytest.mark.asyncio()
    async def test_enrich_ip_returns_normalized_fields(self, provider: VirusTotalProvider) -> None:
        with patch.object(
            provider._client, "get", new_callable=AsyncMock, return_value=_ok_ip_response(),
        ):
            result = await provider.enrich_ip("1.2.3.4")

        assert result.data["vt_malicious_count"] == 2
        assert result.data["vt_suspicious_count"] == 1
        assert result.data["vt_ip_reputation"] == -5
        assert result.data["vt_as_owner"] == "Example Hosting"

    @pytest.mark.asyncio()
    async def test_404_ip_returns_zeros_without_raising(
        self, provider: VirusTotalProvider,
    ) -> None:
        """VT 404 on IP = 'never indexed'. Return empty result, don't error."""
        not_found = httpx.Response(
            404, json={"error": {"code": "NotFoundError"}},
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/ip_addresses/9.9.9.9",
            ),
        )
        with patch.object(
            provider._client, "get", new_callable=AsyncMock, return_value=not_found,
        ):
            result = await provider.enrich_ip("9.9.9.9")

        assert result.data["vt_malicious_count"] == 0
        assert result.data["vt_suspicious_count"] == 0
        assert result.data["vt_ip_reputation"] == 0
        assert result.data["vt_as_owner"] == ""


class TestVirusTotalHash:
    @pytest.mark.asyncio()
    async def test_enrich_hash_returns_normalized_fields(
        self, provider: VirusTotalProvider,
    ) -> None:
        with patch.object(
            provider._client, "get", new_callable=AsyncMock, return_value=_ok_hash_response(),
        ):
            result = await provider.enrich_hash("a" * 64)

        assert result.data["vt_file_malicious_count"] == 30
        assert result.data["vt_file_undetected_count"] == 40
        assert result.data["vt_file_name"] == "evil.bin"
        assert result.data["vt_file_type"] == "elf"

    @pytest.mark.asyncio()
    async def test_404_hash_returns_zeros_without_raising(
        self, provider: VirusTotalProvider,
    ) -> None:
        """VT 404 on hash = 'never analysed'. Common for fresh honeypot malware."""
        not_found = httpx.Response(
            404, json={"error": {"code": "NotFoundError"}},
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/files/abc",
            ),
        )
        with patch.object(
            provider._client, "get", new_callable=AsyncMock, return_value=not_found,
        ):
            result = await provider.enrich_hash("a" * 64)

        assert result.data["vt_file_malicious_count"] == 0
        assert result.data["vt_file_undetected_count"] == 0
        assert result.data["vt_file_name"] == ""
        assert result.data["vt_file_type"] == ""

    @pytest.mark.asyncio()
    async def test_200_ip_without_as_owner_returns_empty_string(
        self, provider: VirusTotalProvider,
    ) -> None:
        """Some VT 200 responses lack `as_owner` (notably on private-space IPs).

        Observed in op_alpha's first enrichment run: KeyError('as_owner')
        on 10.69.215.134. The runner now defends against missing optional
        attributes the same way it does for missing last_analysis_stats keys.
        """
        sparse = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                        "reputation": 0,
                    },
                },
            },
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
            ),
        )
        with patch.object(
            provider._client, "get", new_callable=AsyncMock, return_value=sparse,
        ):
            result = await provider.enrich_ip("1.2.3.4")

        assert result.data["vt_malicious_count"] == 0
        assert result.data["vt_as_owner"] == ""


class TestVirusTotalRetry:
    @pytest.mark.asyncio()
    async def test_429_fails_fast(self, provider: VirusTotalProvider) -> None:
        """Rate-limit 429 must NOT be retried — defect #11.

        429 means "quota exhausted; reset is hours-to-monthly away".
        Tenacity's 2-30 s exponential backoff cannot outwait that, so each
        retried call is pure wall-clock burn. Op_alpha's 2026-05-21 12:10
        re-run for 2026-05-20 wedged for an hour with three providers each
        retrying ~3000 calls 3x because of this. The runner's
        circuit-breaker (consecutive + cumulative thresholds) is the
        correct authority to decide when to stop hitting the provider.
        """
        rate_limited = httpx.Response(
            429, json={"error": "Rate limit"},
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
            ),
        )
        mock_get = AsyncMock(return_value=rate_limited)
        with patch.object(provider._client, "get", mock_get), \
             pytest.raises(httpx.HTTPStatusError) as exc_info:
            await provider.enrich_ip("1.2.3.4")
        assert exc_info.value.response.status_code == 429
        assert mock_get.await_count == 1  # single attempt, no retry

    @pytest.mark.asyncio()
    async def test_403_fails_fast(self, provider: VirusTotalProvider) -> None:
        """Auth errors must NOT be retried."""
        forbidden = httpx.Response(
            403, json={"error": "wrong key"},
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
            ),
        )
        mock_get = AsyncMock(return_value=forbidden)
        with patch.object(provider._client, "get", mock_get), \
             pytest.raises(httpx.HTTPStatusError):
            await provider.enrich_ip("1.2.3.4")
        assert mock_get.await_count == 1

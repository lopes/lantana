"""Tests for the VirusTotal enrichment provider."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import tenacity

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

        assert result.data["vt_malicious_count"] == 30
        assert result.data["vt_undetected_count"] == 40
        assert result.data["vt_name"] == "evil.bin"
        assert result.data["vt_type"] == "elf"

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

        assert result.data["vt_malicious_count"] == 0
        assert result.data["vt_undetected_count"] == 0
        assert result.data["vt_name"] == ""
        assert result.data["vt_type"] == ""


class TestVirusTotalRetry:
    @pytest.mark.asyncio()
    async def test_429_is_retried(self, provider: VirusTotalProvider) -> None:
        """Rate-limit 429 must be retried — that's the only reason for the retry budget.

        After tenacity exhausts its 3 attempts, it wraps the final
        HTTPStatusError in a RetryError. The wrapping itself is the proof
        that retry actually happened.
        """
        rate_limited = httpx.Response(
            429, json={"error": "Rate limit"},
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
            ),
        )
        mock_get = AsyncMock(return_value=rate_limited)
        with patch.object(provider._client, "get", mock_get), \
             pytest.raises(tenacity.RetryError):
            await provider.enrich_ip("1.2.3.4")
        assert mock_get.await_count >= 2

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

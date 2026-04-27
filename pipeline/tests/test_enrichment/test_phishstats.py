"""Tests for the PhishStats enrichment provider."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from lantana.enrichment.providers.phishstats import PhishStatsProvider


@pytest.fixture()
def provider() -> PhishStatsProvider:
    return PhishStatsProvider(api_key="test-key")


class TestPhishStatsProvider:
    @pytest.mark.asyncio()
    async def test_enrich_ip_returns_result(self, provider: PhishStatsProvider) -> None:
        """Successful response produces an EnrichmentResult with expected fields."""
        mock_response = httpx.Response(
            200,
            json=[
                {"url": "http://evil.example.com/login", "date": "2026-04-20"},
                {"url": "http://evil.example.com/phish", "date": "2026-04-21"},
            ],
            request=httpx.Request("GET", "https://phishstats.info:2096/api/phishing"),
        )
        with patch.object(provider._client, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await provider.enrich_ip("203.0.113.50")

        assert result.provider == "phishstats"
        assert result.ip == "203.0.113.50"
        assert result.data["phishstats_url_count"] == 2
        assert result.data["phishstats_last_seen"] == "2026-04-21"

    @pytest.mark.asyncio()
    async def test_enrich_ip_handles_empty_response(self, provider: PhishStatsProvider) -> None:
        """Empty API response returns zero counts."""
        mock_response = httpx.Response(
            200,
            json=[],
            request=httpx.Request("GET", "https://phishstats.info:2096/api/phishing"),
        )
        with patch.object(provider._client, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await provider.enrich_ip("198.51.100.1")

        assert result.data["phishstats_url_count"] == 0
        assert result.data["phishstats_last_seen"] is None

    def test_rate_limit_returns_correct_values(self, provider: PhishStatsProvider) -> None:
        """Rate limit is 10 requests per 60 seconds."""
        assert provider.rate_limit() == (10, 60)

    @pytest.mark.asyncio()
    async def test_close_shuts_down_client(self, provider: PhishStatsProvider) -> None:
        """close() calls aclose on the underlying httpx client."""
        with patch.object(provider._client, "aclose", new_callable=AsyncMock) as mock_close:
            await provider.close()
            mock_close.assert_called_once()

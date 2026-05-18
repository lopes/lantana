"""Tests for the GreyNoise enrichment provider."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from lantana.enrichment.providers.greynoise import GreyNoiseProvider


@pytest.fixture()
def anonymous_provider() -> GreyNoiseProvider:
    return GreyNoiseProvider()


@pytest.fixture()
def keyed_provider() -> GreyNoiseProvider:
    return GreyNoiseProvider(api_key="test-key")


def _ok_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "ip": "212.115.85.236",
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "Mass Scanner",
            "last_seen": "2026-05-15",
            "link": "https://viz.greynoise.io/ip/212.115.85.236",
        },
        request=httpx.Request("GET", "https://api.greynoise.io/v3/community/212.115.85.236"),
    )


class TestGreyNoiseProvider:
    @pytest.mark.asyncio()
    async def test_enrich_ip_returns_full_result(self, keyed_provider: GreyNoiseProvider) -> None:
        """Successful response surfaces classification, noise, riot, name, last_seen, link."""
        with patch.object(
            keyed_provider._client, "get", new_callable=AsyncMock, return_value=_ok_response(),
        ):
            result = await keyed_provider.enrich_ip("212.115.85.236")

        assert result.provider == "greynoise"
        assert result.ip == "212.115.85.236"
        assert result.data["greynoise_classification"] == "malicious"
        assert result.data["greynoise_noise"] is True
        assert result.data["greynoise_riot"] is False
        assert result.data["greynoise_name"] == "Mass Scanner"
        assert result.data["greynoise_last_seen"] == "2026-05-15"
        assert result.data["greynoise_link"].startswith("https://viz.greynoise.io/")

    @pytest.mark.asyncio()
    async def test_anonymous_request_omits_key_header(
        self, anonymous_provider: GreyNoiseProvider,
    ) -> None:
        """When no API key is set, the `key` header must not be sent."""
        mock_get = AsyncMock(return_value=_ok_response())
        with patch.object(anonymous_provider._client, "get", mock_get):
            await anonymous_provider.enrich_ip("212.115.85.236")

        sent_headers = mock_get.call_args.kwargs["headers"]
        assert "key" not in sent_headers
        assert sent_headers["Accept"] == "application/json"

    @pytest.mark.asyncio()
    async def test_keyed_request_includes_key_header(
        self, keyed_provider: GreyNoiseProvider,
    ) -> None:
        """When an API key is set, it must be sent as the `key` header."""
        mock_get = AsyncMock(return_value=_ok_response())
        with patch.object(keyed_provider._client, "get", mock_get):
            await keyed_provider.enrich_ip("212.115.85.236")

        sent_headers = mock_get.call_args.kwargs["headers"]
        assert sent_headers["key"] == "test-key"

    @pytest.mark.asyncio()
    async def test_empty_string_key_is_anonymous(self) -> None:
        """An empty-string api_key must behave as anonymous, not as a literal empty key."""
        provider = GreyNoiseProvider(api_key="")
        mock_get = AsyncMock(return_value=_ok_response())
        with patch.object(provider._client, "get", mock_get):
            await provider.enrich_ip("212.115.85.236")

        sent_headers = mock_get.call_args.kwargs["headers"]
        assert "key" not in sent_headers

    @pytest.mark.asyncio()
    async def test_404_returns_unknown_result(self, keyed_provider: GreyNoiseProvider) -> None:
        """A 404 means the IP is not in the GreyNoise dataset, not an error."""
        not_found = httpx.Response(
            404,
            json={"ip": "203.0.113.1", "message": "IP not observed scanning the internet or contained in RIOT data set"},
            request=httpx.Request("GET", "https://api.greynoise.io/v3/community/203.0.113.1"),
        )
        with patch.object(
            keyed_provider._client, "get", new_callable=AsyncMock, return_value=not_found,
        ):
            result = await keyed_provider.enrich_ip("203.0.113.1")

        assert result.data["greynoise_classification"] == "unknown"
        assert result.data["greynoise_noise"] is False
        assert result.data["greynoise_riot"] is False
        assert result.data["greynoise_name"] == ""
        assert result.data["greynoise_last_seen"] is None

    def test_rate_limit_returns_community_quota(self, keyed_provider: GreyNoiseProvider) -> None:
        """Rate limit reflects the 50-per-week community quota."""
        assert keyed_provider.rate_limit() == (50, 604800)

    @pytest.mark.asyncio()
    async def test_close_shuts_down_client(self, keyed_provider: GreyNoiseProvider) -> None:
        """close() calls aclose on the underlying httpx client."""
        with patch.object(keyed_provider._client, "aclose", new_callable=AsyncMock) as mock_close:
            await keyed_provider.close()
            mock_close.assert_called_once()

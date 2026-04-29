"""GreyNoise enrichment provider."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult


class GreyNoiseProvider:
    """GreyNoise threat intelligence provider.

    Rate limit: 50 requests per 86400 seconds (daily).
    """

    _BASE_URL = "https://api.greynoise.io/v3/community"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=30.0)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(httpx.HTTPStatusError),
    )
    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query GreyNoise for context on an IP address."""
        response = await self._client.get(
            f"{self._BASE_URL}/{ip}",
            headers={
                "key": self._api_key,
                "Accept": "application/json",
            },
        )
        response.raise_for_status()

        data: dict[str, str | bool] = response.json()

        return EnrichmentResult(
            provider="greynoise",
            ip=ip,
            data={
                "greynoise_classification": str(data["classification"]),
                "greynoise_noise": bool(data["noise"]),
                "greynoise_name": str(data["name"]),
                "greynoise_link": str(data["link"]),
            },
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (50, 86400) — 50 requests per day."""
        return (50, 86400)

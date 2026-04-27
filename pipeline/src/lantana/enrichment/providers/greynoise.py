"""GreyNoise enrichment provider."""

from __future__ import annotations

from lantana.enrichment.providers.base import EnrichmentResult


class GreyNoiseProvider:
    """GreyNoise threat intelligence provider.

    Rate limit: 50 requests per 86400 seconds (daily).
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query GreyNoise for context on an IP address."""
        raise NotImplementedError("TODO")

    def rate_limit(self) -> tuple[int, int]:
        """Return (50, 86400) -- 50 requests per day."""
        return (50, 86400)

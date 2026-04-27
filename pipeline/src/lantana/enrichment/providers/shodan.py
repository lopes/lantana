"""Shodan enrichment provider."""

from __future__ import annotations

from lantana.enrichment.providers.base import EnrichmentResult


class ShodanProvider:
    """Shodan internet intelligence provider.

    Rate limit: 100 requests per 2592000 seconds (monthly).
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query Shodan for host information on an IP address."""
        raise NotImplementedError("TODO")

    def rate_limit(self) -> tuple[int, int]:
        """Return (100, 2592000) -- 100 requests per month."""
        return (100, 2592000)

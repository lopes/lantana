"""AbuseIPDB enrichment provider."""

from __future__ import annotations

from lantana.enrichment.providers.base import EnrichmentResult


class AbuseIPDBProvider:
    """AbuseIPDB threat intelligence provider.

    Rate limit: 1000 requests per 86400 seconds (daily).
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query AbuseIPDB for abuse reports on an IP address."""
        raise NotImplementedError("TODO")

    def rate_limit(self) -> tuple[int, int]:
        """Return (1000, 86400) -- 1000 requests per day."""
        return (1000, 86400)

"""VirusTotal enrichment provider."""

from __future__ import annotations

from lantana.enrichment.providers.base import EnrichmentResult


class VirusTotalProvider:
    """VirusTotal threat intelligence provider.

    Rate limit: 4 requests per 60 seconds (per minute).
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query VirusTotal for reputation data on an IP address."""
        raise NotImplementedError("TODO")

    async def enrich_hash(self, sha256: str) -> EnrichmentResult:
        """Query VirusTotal for analysis of a file hash."""
        raise NotImplementedError("TODO")

    def rate_limit(self) -> tuple[int, int]:
        """Return (4, 60) -- 4 requests per minute."""
        return (4, 60)

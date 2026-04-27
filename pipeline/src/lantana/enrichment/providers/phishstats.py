"""PhishStats enrichment provider."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult


class PhishStatsProvider:
    """PhishStats phishing URL intelligence provider.

    Queries PhishStats for phishing URLs associated with an IP address.
    Rate limit: 10 requests per 60 seconds (free tier).
    """

    _BASE_URL = "https://phishstats.info:2096/api/phishing"

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
        """Query PhishStats for phishing URLs hosted on an IP address."""
        response = await self._client.get(
            self._BASE_URL,
            params={"_where": f"(ip,eq,{ip})"},
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()

        entries: list[dict[str, str]] = response.json()

        url_count = len(entries)
        last_seen: str | None = None
        if entries:
            dates = [e.get("date", "") for e in entries if e.get("date")]
            if dates:
                last_seen = max(dates)

        return EnrichmentResult(
            provider="phishstats",
            ip=ip,
            data={
                "phishstats_url_count": url_count,
                "phishstats_last_seen": last_seen,
            },
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (10, 60) -- 10 requests per minute."""
        return (10, 60)

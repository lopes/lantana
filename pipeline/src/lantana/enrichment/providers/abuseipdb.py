"""AbuseIPDB enrichment provider."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult


class AbuseIPDBProvider:
    """AbuseIPDB threat intelligence provider.

    Rate limit: 1000 requests per 86400 seconds (daily).
    """

    _BASE_URL = "https://api.abuseipdb.com/api/v2/check"

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
        """Query AbuseIPDB for abuse reports on an IP address."""
        response = await self._client.get(
            self._BASE_URL,
            headers={
                "Key": self._api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
        )
        response.raise_for_status()

        payload: dict[str, dict[str, str | int | bool]] = response.json()
        data = payload["data"]

        return EnrichmentResult(
            provider="abuseipdb",
            ip=ip,
            data={
                "abuseipdb_confidence_score": int(data["abuseConfidenceScore"]),
                "abuseipdb_total_reports": int(data["totalReports"]),
                "abuseipdb_country": str(data["countryCode"]),
                "abuseipdb_isp": str(data["isp"]),
                "abuseipdb_domain": str(data["domain"]),
            },
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (1000, 86400) -- 1000 requests per day."""
        return (1000, 86400)

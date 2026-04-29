"""VirusTotal enrichment provider."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult


class VirusTotalProvider:
    """VirusTotal threat intelligence provider.

    Rate limit: 4 requests per 60 seconds (per minute).
    """

    _BASE_URL = "https://www.virustotal.com/api/v3"

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
        """Query VirusTotal for reputation data on an IP address."""
        response = await self._client.get(
            f"{self._BASE_URL}/ip_addresses/{ip}",
            headers={"x-apikey": self._api_key},
        )
        response.raise_for_status()

        payload: dict[str, dict[str, dict[str, int | str]]] = response.json()
        attributes = payload["data"]["attributes"]
        last_analysis: dict[str, int] = attributes["last_analysis_stats"]  # type: ignore[assignment]

        return EnrichmentResult(
            provider="virustotal",
            ip=ip,
            data={
                "vt_malicious_count": int(last_analysis["malicious"]),
                "vt_suspicious_count": int(last_analysis["suspicious"]),
                "vt_ip_reputation": int(attributes["reputation"]),
                "vt_as_owner": str(attributes["as_owner"]),
            },
            queried_at=datetime.now(tz=UTC),
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type(httpx.HTTPStatusError),
    )
    async def enrich_hash(self, sha256: str) -> EnrichmentResult:
        """Query VirusTotal for analysis of a file hash."""
        response = await self._client.get(
            f"{self._BASE_URL}/files/{sha256}",
            headers={"x-apikey": self._api_key},
        )
        response.raise_for_status()

        payload: dict[str, dict[str, dict[str, int | str]]] = response.json()
        attributes = payload["data"]["attributes"]
        last_analysis: dict[str, int] = attributes["last_analysis_stats"]  # type: ignore[assignment]

        return EnrichmentResult(
            provider="virustotal",
            ip=sha256,
            data={
                "vt_malicious_count": int(last_analysis["malicious"]),
                "vt_undetected_count": int(last_analysis["undetected"]),
                "vt_name": str(attributes["meaningful_name"]),
                "vt_type": str(attributes["type_tag"]),
            },
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (4, 60) — 4 requests per minute."""
        return (4, 60)

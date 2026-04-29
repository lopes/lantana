"""Shodan enrichment provider."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult


class ShodanProvider:
    """Shodan internet intelligence provider.

    Rate limit: 100 requests per 2592000 seconds (monthly).
    """

    _BASE_URL = "https://api.shodan.io/shodan/host"

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
        """Query Shodan for host information on an IP address."""
        response = await self._client.get(
            f"{self._BASE_URL}/{ip}",
            params={"key": self._api_key},
        )
        response.raise_for_status()

        data: dict[str, str | int | list[int] | list[str] | None] = response.json()

        ports_raw: list[int] = data.get("ports", [])  # type: ignore[assignment]
        ports_str = ",".join(str(p) for p in ports_raw) if ports_raw else ""

        vulns_raw: list[str] | None = data.get("vulns")  # type: ignore[assignment]
        vulns_str: str | None = ",".join(vulns_raw) if vulns_raw else None

        os_value: str | None = data.get("os")  # type: ignore[assignment]

        return EnrichmentResult(
            provider="shodan",
            ip=ip,
            data={
                "shodan_ports": ports_str,
                "shodan_os": os_value,
                "shodan_vulns": vulns_str,
                "shodan_org": str(data["org"]),
                "shodan_asn": str(data["asn"]),
            },
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (100, 2592000) — 100 requests per month."""
        return (100, 2592000)

"""Shodan enrichment provider.

API documentation: https://developer.shodan.io/api
Free-tier (Membership) rate limit: roughly 100 queries per month.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult, is_retryable_http_error


def compute_risk_score(ports_str: str, vulns_str: str | None) -> float:
    """Tri-state Shodan score: 0 / 25 / 100.

    * Any non-empty ``vulns_str`` → 100 (CVE on the IP is the strongest
      Shodan signal — exposed, scanned, known-vulnerable).
    * Ports present but no vulns → 25 (internet-exposed but no
      enumerated CVEs).
    * Both empty → 0 (Shodan responded but has no scan data, e.g. a
      residential / cloud IP they haven't indexed).
    See docs/risk-scoring.md.
    """
    if vulns_str:
        return 100.0
    if ports_str:
        return 25.0
    return 0.0


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
        retry=retry_if_exception(is_retryable_http_error),
        reraise=True,
    )
    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query Shodan for host information on an IP address."""
        response = await self._client.get(
            f"{self._BASE_URL}/{ip}",
            params={"key": self._api_key},
        )

        # 404 = Shodan has never scanned this IP. Common for residential
        # botnets — treat it as "no info" rather than an error so the
        # daily run doesn't drop the row's other-provider enrichment.
        if response.status_code == 404:
            return EnrichmentResult(
                provider="shodan",
                ip=ip,
                data={
                    "shodan_ports": "",
                    "shodan_os": None,
                    "shodan_vulns": None,
                    "shodan_org": "",
                    "shodan_asn": "",
                    "shodan_risk_score": 0.0,
                },
                queried_at=datetime.now(tz=UTC),
            )

        response.raise_for_status()
        data: dict[str, str | int | list[int] | list[str] | None] = response.json()

        # `data` is annotated as a heterogeneous union; mypy can't narrow
        # `data.get` returns to the specific value type. The narrowings below
        # are validated by the test suite against fixtures.
        ports_raw: list[int] = data.get("ports", [])  # type: ignore[assignment]
        ports_str = ",".join(str(p) for p in ports_raw) if ports_raw else ""

        vulns_raw: list[str] | None = data.get("vulns")  # type: ignore[assignment]
        vulns_str: str | None = ",".join(vulns_raw) if vulns_raw else None

        os_value: str | None = data.get("os")  # type: ignore[assignment]

        # Shodan's 200 responses are sparse — fields like `org` / `asn` are
        # routinely absent on hosts the scanner has only partial data for.
        # Default to empty string, matching the 404-fallback shape above.
        return EnrichmentResult(
            provider="shodan",
            ip=ip,
            data={
                "shodan_ports": ports_str,
                "shodan_os": os_value,
                "shodan_vulns": vulns_str,
                "shodan_org": str(data.get("org") or ""),
                "shodan_asn": str(data.get("asn") or ""),
                "shodan_risk_score": compute_risk_score(ports_str, vulns_str),
            },
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (100, 2592000) — 100 requests per month."""
        return (100, 2592000)

"""GreyNoise enrichment provider.

Uses the public Community API (`/v3/community/{ip}`) for every request.
The endpoint is reachable both anonymously and with an API key — the key
only raises the rate limit, it does not unlock different data.

Behaviour:
- ``api_key`` empty or None → anonymous request.
- ``api_key`` non-empty       → sent as the ``key`` header.

API documentation:
  Community API (this is what we use): https://docs.greynoise.io/docs/using-the-greynoise-community-api
  Full v3 API (subscription-only):     https://docs.greynoise.io/docs/using-the-greynoise-api
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult, is_retryable_http_error


def compute_risk_score(
    classification: str,
    noise: bool,
    riot: bool,
) -> float:
    """GreyNoise risk score with RIOT override to 0.

    Logic (in order):
      * ``riot=True`` → 0   (Rule-It-Out: known-benign infrastructure
                              like Censys, NTP, DNS, CDNs. Overrides
                              every other signal — per docs/risk-scoring.md,
                              we keep the row in silver but lower the score.)
      * ``classification == "malicious"`` → 75
      * ``noise=True`` and ``classification == "unknown"`` → 25  (seen
        scanning broadly but not yet labelled)
      * ``classification == "benign"`` → 0
      * else (``"unknown"`` with no noise signal) → 10  (lowest non-zero
        confidence; "we know nothing about this IP" deserves a small
        weight, not a zero.)
    """
    if riot:
        return 0.0
    if classification == "malicious":
        return 75.0
    if classification == "benign":
        return 0.0
    if noise and classification == "unknown":
        return 25.0
    return 10.0


class GreyNoiseProvider:
    """GreyNoise Community API provider.

    Rate limit (free / unauthenticated): 50 searches per 7 days, shared
    across the Community API and the GreyNoise Visualizer.
    """

    _BASE_URL = "https://api.greynoise.io/v3/community"

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or ""
        self._client = httpx.AsyncClient(timeout=30.0)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["key"] = self._api_key
        return headers

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception(is_retryable_http_error),
        reraise=True,
    )
    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query GreyNoise Community for context on an IP address."""
        response = await self._client.get(
            f"{self._BASE_URL}/{ip}",
            headers=self._headers(),
        )

        # 404 = the IP is not in GreyNoise's dataset. Treat it as a valid
        # "no info" response rather than an error so the pipeline keeps moving.
        if response.status_code == 404:
            return EnrichmentResult(
                provider="greynoise",
                ip=ip,
                data={
                    "greynoise_classification": "unknown",
                    "greynoise_noise": False,
                    "greynoise_riot": False,
                    "greynoise_name": "",
                    "greynoise_last_seen": None,
                    "greynoise_link": "",
                    "greynoise_risk_score": compute_risk_score("unknown", False, False),
                },
                queried_at=datetime.now(tz=UTC),
            )

        response.raise_for_status()
        data: dict[str, str | bool | None] = response.json()

        last_seen_raw = data.get("last_seen")
        classification = str(data.get("classification") or "unknown")
        noise = bool(data.get("noise", False))
        riot = bool(data.get("riot", False))

        return EnrichmentResult(
            provider="greynoise",
            ip=ip,
            data={
                "greynoise_classification": classification,
                "greynoise_noise": noise,
                "greynoise_riot": riot,
                "greynoise_name": str(data.get("name") or ""),
                "greynoise_last_seen": str(last_seen_raw) if last_seen_raw else None,
                "greynoise_link": str(data.get("link") or ""),
                "greynoise_risk_score": compute_risk_score(classification, noise, riot),
            },
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (50, 604800) — 50 requests per 7 days (community quota)."""
        return (50, 604800)

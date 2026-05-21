"""Abstract base for enrichment providers."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 - required at runtime by Pydantic
from typing import Protocol, runtime_checkable

import httpx
from pydantic import BaseModel


def is_retryable_http_error(exc: BaseException) -> bool:
    """Decide whether a transport-level failure should be retried.

    Retry: timeouts, 5xx (server error), transport errors. Fail fast on
    everything else — including 429.

    Why not retry 429: rate-limit windows on the free-tier providers we
    use are hours-to-monthly, not seconds. Tenacity's 2-30 s exponential
    backoff cannot outwait a Shodan monthly cap or a VirusTotal daily
    cap, so retries just stack up wall-clock without ever succeeding.
    During op_alpha's 2026-05-21 12:10 re-run for date=2026-05-20, with
    Shodan's 1243 cached IPs scattered through a 4670-IP queue, the
    fast-fail had been *retry* — three attempts x 4 s back-off per call
    x 3427 fresh IPs ≈ 14 hours of pure backoff sleep before the
    consecutive circuit-breaker had a chance to trip. Fail fast and let
    the runner's circuit-breaker (which now also has a cumulative
    threshold) decide when to bail.
    """
    if isinstance(exc, httpx.TimeoutException | httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return 500 <= status < 600
    return False


class EnrichmentResult(BaseModel):
    """Result from an enrichment provider query."""

    provider: str
    ip: str
    data: dict[str, str | int | float | bool | None]
    queried_at: datetime


class EnrichmentError(BaseModel):
    """Aggregated error summary from an enrichment provider."""

    provider: str
    error_type: str
    error_message: str
    count: int = 1
    timestamp: datetime


@runtime_checkable
class EnrichmentProvider(Protocol):
    """Protocol defining the interface for all enrichment providers."""

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query the provider for information about an IP address."""
        ...

    def rate_limit(self) -> tuple[int, int]:
        """Return (max_requests, per_seconds) rate limit tuple."""
        ...

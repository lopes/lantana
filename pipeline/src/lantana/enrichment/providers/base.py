"""Abstract base for enrichment providers."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 - required at runtime by Pydantic
from typing import Protocol, runtime_checkable

from pydantic import BaseModel


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

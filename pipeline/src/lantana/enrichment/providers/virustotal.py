"""VirusTotal enrichment provider.

API documentation: https://docs.virustotal.com/reference/overview (v3)
Free public-tier rate limit: 4 requests per minute, 500 per day.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult, is_retryable_http_error

# VT IP risk-score buckets: (lower_bound_inclusive, score). Evaluated
# highest-first so the largest matching bucket wins.
#
# Calibrated against VT's typical 70-90 engine count:
#   1-2 malicious  → 25  (often single-engine noise / false positives)
#   3-5            → 50  (genuine multi-source agreement)
#   6-10           → 75  (broadly flagged)
#   >10            → 100 (heavily flagged; uncommon for IPs that aren't
#                         known botnet C2 or active malware staging)
VT_IP_RISK_BUCKETS: list[tuple[int, float]] = [
    (11, 100.0),
    (6, 75.0),
    (3, 50.0),
    (1, 25.0),
]


def compute_ip_risk_score(malicious_count: int) -> float:
    """Bucket a VT malicious engine count into a 0..100 risk score.

    See docs/risk-scoring.md.
    """
    for lower_bound, score in VT_IP_RISK_BUCKETS:
        if malicious_count >= lower_bound:
            return score
    return 0.0


# VT file risk-score buckets. File-scan FP rates are far lower than
# IP-list FP rates, so a single engine flagging crosses the cache
# "malicious" threshold (50). Used only for cache TTL classification —
# the gold composite is per-IP and does not include this score.
VT_FILE_RISK_BUCKETS: list[tuple[int, float]] = [
    (5, 100.0),
    (2, 75.0),
    (1, 50.0),
]


def compute_file_risk_score(malicious_count: int) -> float:
    """Bucket a VT malicious engine count for a file hash into a 0..100 score."""
    for lower_bound, score in VT_FILE_RISK_BUCKETS:
        if malicious_count >= lower_bound:
            return score
    return 0.0


def _empty_ip_result(ip: str) -> EnrichmentResult:
    return EnrichmentResult(
        provider="virustotal",
        ip=ip,
        data={
            "vt_malicious_count": 0,
            "vt_suspicious_count": 0,
            "vt_ip_reputation": 0,
            "vt_as_owner": "",
            "virustotal_risk_score": 0.0,
        },
        queried_at=datetime.now(tz=UTC),
    )


def _empty_hash_result(sha256: str) -> EnrichmentResult:
    return EnrichmentResult(
        provider="virustotal",
        ip=sha256,
        data={
            "vt_file_malicious_count": 0,
            "vt_file_undetected_count": 0,
            "vt_file_name": "",
            "vt_file_type": "",
            "vt_file_risk_score": 0.0,
        },
        queried_at=datetime.now(tz=UTC),
    )


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
        retry=retry_if_exception(is_retryable_http_error),
        reraise=True,
    )
    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Query VirusTotal for reputation data on an IP address."""
        response = await self._client.get(
            f"{self._BASE_URL}/ip_addresses/{ip}",
            headers={"x-apikey": self._api_key},
        )

        # 404 = VT has never indexed this IP. Treat as "no info".
        if response.status_code == 404:
            return _empty_ip_result(ip)

        response.raise_for_status()
        payload: dict[str, dict[str, dict[str, int | str]]] = response.json()
        attributes = payload["data"]["attributes"]
        last_analysis: dict[str, int] = attributes.get("last_analysis_stats", {})  # type: ignore[assignment]

        malicious = int(last_analysis.get("malicious", 0))
        return EnrichmentResult(
            provider="virustotal",
            ip=ip,
            data={
                "vt_malicious_count": malicious,
                "vt_suspicious_count": int(last_analysis.get("suspicious", 0)),
                "vt_ip_reputation": int(attributes.get("reputation", 0)),
                "vt_as_owner": str(attributes.get("as_owner") or ""),
                "virustotal_risk_score": compute_ip_risk_score(malicious),
            },
            queried_at=datetime.now(tz=UTC),
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception(is_retryable_http_error),
        reraise=True,
    )
    async def enrich_hash(self, sha256: str) -> EnrichmentResult:
        """Query VirusTotal for analysis of a file hash."""
        response = await self._client.get(
            f"{self._BASE_URL}/files/{sha256}",
            headers={"x-apikey": self._api_key},
        )

        # 404 = VT has never analysed this hash. Common for fresh malware
        # captured by honeypots before any AV vendor has seen it.
        if response.status_code == 404:
            return _empty_hash_result(sha256)

        response.raise_for_status()
        payload: dict[str, dict[str, dict[str, int | str]]] = response.json()
        attributes = payload["data"]["attributes"]
        last_analysis: dict[str, int] = attributes.get("last_analysis_stats", {})  # type: ignore[assignment]

        malicious = int(last_analysis.get("malicious", 0))
        return EnrichmentResult(
            provider="virustotal",
            ip=sha256,
            data={
                "vt_file_malicious_count": malicious,
                "vt_file_undetected_count": int(last_analysis.get("undetected", 0)),
                "vt_file_name": str(attributes.get("meaningful_name") or ""),
                "vt_file_type": str(attributes.get("type_tag") or ""),
                "vt_file_risk_score": compute_file_risk_score(malicious),
            },
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (4, 60) — 4 requests per minute."""
        return (4, 60)

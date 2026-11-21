"""VirusTotal & optional Google Threat Intelligence (GTI) enrichment provider.

API documentation: https://docs.virustotal.com/reference/overview (v3)
Free public-tier rate limit: 4 requests per minute, 500 per day.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from lantana.enrichment.providers.base import EnrichmentResult, is_retryable_http_error

# VT IP / domain risk-score buckets: (lower_bound_inclusive, score).
VT_IP_RISK_BUCKETS: list[tuple[int, float]] = [
    (11, 100.0),
    (6, 75.0),
    (3, 50.0),
    (1, 25.0),
]

# VT file / stager-URL risk-score buckets. File & post-auth URL FP rates are
# much lower than IP-list FP rates, so a single engine flagging crosses 50.
VT_FILE_RISK_BUCKETS: list[tuple[int, float]] = [
    (5, 100.0),
    (2, 75.0),
    (1, 50.0),
]

# Minimum Mandiant confidence score required before surfacing GTI associations
# as threat actors / malware families in Gold & STIX.
GTI_ASSOCIATION_MIN_CONFIDENCE: int = 75
_GTI_RELATIONSHIPS: str = "associations,threat_actors,malware_families,vulnerabilities"
_GTI_BENIGN_VERDICTS: frozenset[str] = frozenset({"VERDICT_BENIGN", "VERDICT_UNDETECTED"})


def compute_ip_risk_score(malicious_count: int) -> float:
    """Bucket a VT malicious engine count into a 0..100 risk score."""
    for lower_bound, score in VT_IP_RISK_BUCKETS:
        if malicious_count >= lower_bound:
            return score
    return 0.0


def compute_file_risk_score(malicious_count: int) -> float:
    """Bucket a VT malicious engine count for a file hash or stager URL into 0..100."""
    for lower_bound, score in VT_FILE_RISK_BUCKETS:
        if malicious_count >= lower_bound:
            return score
    return 0.0


def encode_vt_url_id(url: str) -> str:
    """Encode a URL into VT v3's unpadded URL-safe Base64 identifier."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _empty_ip_result(ip: str) -> EnrichmentResult:
    return EnrichmentResult(
        provider="virustotal",
        ip=ip,
        data={
            "vt_status": "not_found",
            "vt_malicious_count": 0,
            "vt_suspicious_count": 0,
            "vt_ip_reputation": 0,
            "vt_as_owner": "",
            "virustotal_risk_score": None,
        },
        queried_at=datetime.now(tz=UTC),
    )


def _empty_hash_result(sha256: str) -> EnrichmentResult:
    return EnrichmentResult(
        provider="virustotal",
        ip=sha256,
        data={
            "vt_status": "not_found",
            "vt_file_malicious_count": 0,
            "vt_file_undetected_count": 0,
            "vt_file_name": "",
            "vt_file_type": "",
            "vt_file_family": "",
            "vt_file_vhash": "",
            "vt_file_risk_score": None,
        },
        queried_at=datetime.now(tz=UTC),
    )


def _empty_url_result(url: str) -> EnrichmentResult:
    return EnrichmentResult(
        provider="virustotal",
        ip=url,
        data={
            "vt_status": "not_found",
            "vt_url_malicious_count": 0,
            "vt_url_suspicious_count": 0,
            "vt_url_downloaded_sha256": "",
            "vt_url_risk_score": None,
        },
        queried_at=datetime.now(tz=UTC),
    )


def _empty_domain_result(domain: str) -> EnrichmentResult:
    return EnrichmentResult(
        provider="virustotal",
        ip=domain,
        data={
            "vt_status": "not_found",
            "vt_domain_malicious_count": 0,
            "vt_domain_suspicious_count": 0,
            "vt_domain_risk_score": None,
        },
        queried_at=datetime.now(tz=UTC),
    )


def _extract_threat_family(attributes: dict[str, Any]) -> str:
    """Pull a malware family/category from VT's ``popular_threat_classification``."""
    classification = attributes.get("popular_threat_classification") or {}
    if not isinstance(classification, dict):
        return ""

    names = classification.get("popular_threat_name") or []
    if isinstance(names, list) and names:
        first = names[0]
        if isinstance(first, dict):
            value = first.get("value")
            if isinstance(value, str) and value:
                return value

    label = classification.get("suggested_threat_label")
    if isinstance(label, str) and label:
        return label

    return ""


def _extract_downloaded_file_sha256(payload: dict[str, Any]) -> str:
    """Prefer ``relationships.downloaded_files`` over ``last_http_response_content_sha256``."""
    data = payload.get("data")
    if not isinstance(data, dict):
        return ""
    relationships = data.get("relationships")
    if isinstance(relationships, dict):
        downloaded = relationships.get("downloaded_files")
        if isinstance(downloaded, dict):
            items = downloaded.get("data")
            if isinstance(items, list) and items:
                first = items[0]
                if isinstance(first, dict):
                    file_id = first.get("id")
                    if isinstance(file_id, str) and file_id:
                        return file_id
    attributes = data.get("attributes")
    if isinstance(attributes, dict):
        fallback = attributes.get("last_http_response_content_sha256")
        if isinstance(fallback, str) and fallback:
            return fallback
    return ""


def _extract_gti_fields(payload: dict[str, Any]) -> dict[str, str | int | float | bool | None]:
    """Parse optional commercial GTI ``gti_assessment`` + confidence-gated associations."""
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return {}

    assessment = attributes.get("gti_assessment")
    verdict: str | None = None
    severity: str | None = None
    threat_score: int | None = None
    if isinstance(assessment, dict):
        verdict_obj = assessment.get("verdict")
        if isinstance(verdict_obj, dict) and isinstance(verdict_obj.get("value"), str):
            verdict = verdict_obj["value"]
        severity_obj = assessment.get("severity")
        if isinstance(severity_obj, dict) and isinstance(severity_obj.get("value"), str):
            severity = severity_obj["value"]
        score_obj = assessment.get("threat_score")
        if isinstance(score_obj, dict):
            raw_score = score_obj.get("value")
            if isinstance(raw_score, int) and not isinstance(raw_score, bool):
                threat_score = raw_score

    threat_actors: set[str] = set()
    malware_families: set[str] = set()
    if verdict not in _GTI_BENIGN_VERDICTS:
        relationships = data.get("relationships")
        if isinstance(relationships, dict):
            for rel_key, target_set in (
                ("threat_actors", threat_actors),
                ("malware_families", malware_families),
            ):
                rel_obj = relationships.get(rel_key)
                if not isinstance(rel_obj, dict):
                    continue
                rel_items = rel_obj.get("data")
                if not isinstance(rel_items, list):
                    continue
                for item in rel_items:
                    if not isinstance(item, dict):
                        continue
                    attrs = item.get("attributes")
                    attrs_dict = attrs if isinstance(attrs, dict) else {}
                    ctx = item.get("context_attributes")
                    ctx_dict = ctx if isinstance(ctx, dict) else {}
                    conf_raw = ctx_dict.get(
                        "mandiant_confidence_score",
                        attrs_dict.get("mandiant_confidence_score"),
                    )
                    if not isinstance(conf_raw, (int, float)) or isinstance(conf_raw, bool):
                        continue
                    if conf_raw < GTI_ASSOCIATION_MIN_CONFIDENCE:
                        continue
                    name = attrs_dict.get("name") or item.get("id")
                    if isinstance(name, str) and name.strip():
                        target_set.add(name.strip())

            assoc_obj = relationships.get("associations")
            if isinstance(assoc_obj, dict) and isinstance(assoc_obj.get("data"), list):
                for item in assoc_obj["data"]:
                    if not isinstance(item, dict):
                        continue
                    attrs = item.get("attributes")
                    attrs_dict = attrs if isinstance(attrs, dict) else {}
                    ctx = item.get("context_attributes")
                    ctx_dict = ctx if isinstance(ctx, dict) else {}
                    conf_raw = ctx_dict.get(
                        "mandiant_confidence_score",
                        attrs_dict.get("mandiant_confidence_score"),
                    )
                    if not isinstance(conf_raw, (int, float)) or isinstance(conf_raw, bool):
                        continue
                    if conf_raw < GTI_ASSOCIATION_MIN_CONFIDENCE:
                        continue
                    col_type = str(attrs_dict.get("collection_type") or "").lower()
                    name = attrs_dict.get("name") or item.get("id")
                    if not isinstance(name, str) or not name.strip():
                        continue
                    if col_type == "threat-actor":
                        threat_actors.add(name.strip())
                    elif col_type == "malware":
                        malware_families.add(name.strip())

    out: dict[str, str | int | float | bool | None] = {}
    if verdict is not None:
        out["gti_verdict"] = verdict
    if severity is not None:
        out["gti_severity"] = severity
    if threat_score is not None:
        out["gti_score"] = threat_score
    if threat_actors:
        out["gti_threat_actors"] = ",".join(sorted(threat_actors))
    if malware_families:
        out["gti_malware_families"] = ",".join(sorted(malware_families))
    return out


class VirusTotalProvider:
    """VirusTotal v3 & opt-in Google Threat Intelligence provider.

    Free-tier rate limit: 4 requests per 60 seconds (500/day).
    Always identifies requests with ``x-tool: Lantana``.
    """

    _BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, *, gti_enabled: bool = False) -> None:
        self._api_key = api_key
        self._gti_enabled = gti_enabled
        self._client = httpx.AsyncClient(timeout=30.0)

    @property
    def gti_enabled(self) -> bool:
        """Whether commercial GTI assessment & relationships are enabled."""
        return self._gti_enabled

    def _headers(self) -> dict[str, str]:
        return {
            "x-apikey": self._api_key,
            "x-tool": "Lantana",
        }

    def _params(self, extra_relationships: str | None = None) -> dict[str, str] | None:
        rels: list[str] = []
        if extra_relationships:
            rels.append(extra_relationships)
        if self._gti_enabled:
            rels.append(_GTI_RELATIONSHIPS)
        if not rels:
            return None
        return {"relationships": ",".join(rels)}

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
        kwargs: dict[str, Any] = {"headers": self._headers()}
        params = self._params()
        if params:
            kwargs["params"] = params
        response = await self._client.get(
            f"{self._BASE_URL}/ip_addresses/{quote(ip, safe='')}", **kwargs
        )

        if response.status_code == 404:
            return _empty_ip_result(ip)

        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        attributes: dict[str, Any] = payload["data"]["attributes"]
        last_analysis: dict[str, int] = attributes.get("last_analysis_stats", {})

        malicious = int(last_analysis.get("malicious", 0))
        result_data: dict[str, str | int | float | bool | None] = {
            "vt_status": "found",
            "vt_malicious_count": malicious,
            "vt_suspicious_count": int(last_analysis.get("suspicious", 0)),
            "vt_ip_reputation": int(attributes.get("reputation", 0)),
            "vt_as_owner": str(attributes.get("as_owner") or ""),
            "virustotal_risk_score": compute_ip_risk_score(malicious),
        }
        if self._gti_enabled:
            result_data.update(_extract_gti_fields(payload))
        return EnrichmentResult(
            provider="virustotal",
            ip=ip,
            data=result_data,
            queried_at=datetime.now(tz=UTC),
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception(is_retryable_http_error),
        reraise=True,
    )
    async def enrich_hash(self, sha256: str) -> EnrichmentResult:
        """Query VirusTotal for analysis of a file hash (including free ``vhash``)."""
        kwargs: dict[str, Any] = {"headers": self._headers()}
        params = self._params()
        if params:
            kwargs["params"] = params
        response = await self._client.get(
            f"{self._BASE_URL}/files/{quote(sha256, safe='')}", **kwargs
        )

        if response.status_code == 404:
            return _empty_hash_result(sha256)

        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        attributes: dict[str, Any] = payload["data"]["attributes"]
        last_analysis: dict[str, int] = attributes.get("last_analysis_stats", {})

        malicious = int(last_analysis.get("malicious", 0))
        result_data: dict[str, str | int | float | bool | None] = {
            "vt_status": "found",
            "vt_file_malicious_count": malicious,
            "vt_file_undetected_count": int(last_analysis.get("undetected", 0)),
            "vt_file_name": str(attributes.get("meaningful_name") or ""),
            "vt_file_type": str(attributes.get("type_tag") or ""),
            "vt_file_family": _extract_threat_family(attributes),
            "vt_file_vhash": str(attributes.get("vhash") or ""),
            "vt_file_risk_score": compute_file_risk_score(malicious),
        }
        if self._gti_enabled:
            result_data.update(_extract_gti_fields(payload))
        return EnrichmentResult(
            provider="virustotal",
            ip=sha256,
            data=result_data,
            queried_at=datetime.now(tz=UTC),
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception(is_retryable_http_error),
        reraise=True,
    )
    async def enrich_url(self, url: str) -> EnrichmentResult:
        """Query VirusTotal v3 read-only URL report (with ``downloaded_files`` relationship)."""
        url_id = encode_vt_url_id(url)
        kwargs: dict[str, Any] = {"headers": self._headers()}
        params = self._params(extra_relationships="downloaded_files")
        if params:
            kwargs["params"] = params
        response = await self._client.get(f"{self._BASE_URL}/urls/{url_id}", **kwargs)

        if response.status_code == 404:
            return _empty_url_result(url)

        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        attributes: dict[str, Any] = payload["data"]["attributes"]
        last_analysis: dict[str, int] = attributes.get("last_analysis_stats", {})

        malicious = int(last_analysis.get("malicious", 0))
        result_data: dict[str, str | int | float | bool | None] = {
            "vt_status": "found",
            "vt_url_malicious_count": malicious,
            "vt_url_suspicious_count": int(last_analysis.get("suspicious", 0)),
            "vt_url_downloaded_sha256": _extract_downloaded_file_sha256(payload),
            "vt_url_risk_score": compute_file_risk_score(malicious),
        }
        if self._gti_enabled:
            result_data.update(_extract_gti_fields(payload))
        return EnrichmentResult(
            provider="virustotal",
            ip=url,
            data=result_data,
            queried_at=datetime.now(tz=UTC),
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception(is_retryable_http_error),
        reraise=True,
    )
    async def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Query VirusTotal v3 domain report for a post-auth stager domain."""
        kwargs: dict[str, Any] = {"headers": self._headers()}
        params = self._params()
        if params:
            kwargs["params"] = params
        response = await self._client.get(
            f"{self._BASE_URL}/domains/{quote(domain, safe='')}", **kwargs
        )

        if response.status_code == 404:
            return _empty_domain_result(domain)

        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        attributes: dict[str, Any] = payload["data"]["attributes"]
        last_analysis: dict[str, int] = attributes.get("last_analysis_stats", {})

        malicious = int(last_analysis.get("malicious", 0))
        result_data: dict[str, str | int | float | bool | None] = {
            "vt_status": "found",
            "vt_domain_malicious_count": malicious,
            "vt_domain_suspicious_count": int(last_analysis.get("suspicious", 0)),
            "vt_domain_risk_score": compute_ip_risk_score(malicious),
        }
        if self._gti_enabled:
            result_data.update(_extract_gti_fields(payload))
        return EnrichmentResult(
            provider="virustotal",
            ip=domain,
            data=result_data,
            queried_at=datetime.now(tz=UTC),
        )

    def rate_limit(self) -> tuple[int, int]:
        """Return (4, 60) for free VT, or (60, 60) when commercial GTI is enabled."""
        if self._gti_enabled:
            return (60, 60)
        return (4, 60)

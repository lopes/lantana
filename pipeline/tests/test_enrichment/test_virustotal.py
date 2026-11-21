"""Tests for the VirusTotal enrichment provider."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from lantana.enrichment.providers.virustotal import (
    VirusTotalProvider,
    compute_file_risk_score,
    compute_ip_risk_score,
)


@pytest.fixture()
def provider() -> VirusTotalProvider:
    return VirusTotalProvider(api_key="test-key")


def _ok_ip_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1},
                    "reputation": -5,
                    "as_owner": "Example Hosting",
                },
            },
        },
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/ip_addresses/192.0.2.1"),
    )


def _ok_hash_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 30, "undetected": 40},
                    "meaningful_name": "evil.bin",
                    "type_tag": "elf",
                    "popular_threat_classification": {
                        "popular_threat_name": [
                            {"count": 14, "value": "mirai"},
                            {"count": 9, "value": "gafgyt"},
                        ],
                        "suggested_threat_label": "trojan.mirai/cloudbot",
                    },
                },
            },
        },
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/abc"),
    )


class TestVirusTotalIP:
    @pytest.mark.asyncio()
    async def test_enrich_ip_returns_normalized_fields(self, provider: VirusTotalProvider) -> None:
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=_ok_ip_response(),
        ):
            result = await provider.enrich_ip("192.0.2.1")

        assert result.data["vt_malicious_count"] == 2
        assert result.data["vt_suspicious_count"] == 1
        assert result.data["vt_ip_reputation"] == -5
        assert result.data["vt_as_owner"] == "Example Hosting"

    @pytest.mark.asyncio()
    async def test_404_ip_returns_zeros_without_raising(
        self,
        provider: VirusTotalProvider,
    ) -> None:
        """VT 404 on IP = 'never indexed'. Return empty result, don't error."""
        not_found = httpx.Response(
            404,
            json={"error": {"code": "NotFoundError"}},
            request=httpx.Request(
                "GET",
                "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.99",
            ),
        )
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=not_found,
        ):
            result = await provider.enrich_ip("198.51.100.99")

        assert result.data["vt_malicious_count"] == 0
        assert result.data["vt_suspicious_count"] == 0
        assert result.data["vt_ip_reputation"] == 0
        assert result.data["vt_as_owner"] == ""


class TestVirusTotalHash:
    @pytest.mark.asyncio()
    async def test_enrich_hash_returns_normalized_fields(
        self,
        provider: VirusTotalProvider,
    ) -> None:
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=_ok_hash_response(),
        ):
            result = await provider.enrich_hash("a" * 64)

        assert result.data["vt_file_malicious_count"] == 30
        assert result.data["vt_file_undetected_count"] == 40
        assert result.data["vt_file_name"] == "evil.bin"
        assert result.data["vt_file_type"] == "elf"
        assert result.data["vt_file_family"] == "mirai"
        assert result.data["vt_file_risk_score"] == 100.0

    @pytest.mark.asyncio()
    async def test_404_hash_returns_zeros_without_raising(
        self,
        provider: VirusTotalProvider,
    ) -> None:
        """VT 404 on hash = 'never analysed'. Common for fresh honeypot malware."""
        not_found = httpx.Response(
            404,
            json={"error": {"code": "NotFoundError"}},
            request=httpx.Request(
                "GET",
                "https://www.virustotal.com/api/v3/files/abc",
            ),
        )
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=not_found,
        ):
            result = await provider.enrich_hash("a" * 64)

        assert result.data["vt_file_malicious_count"] == 0
        assert result.data["vt_file_undetected_count"] == 0
        assert result.data["vt_file_name"] == ""
        assert result.data["vt_file_type"] == ""
        assert result.data["vt_file_family"] == ""
        assert result.data["vt_file_vhash"] == ""
        assert result.data["vt_status"] == "not_found"
        assert result.data["vt_file_risk_score"] is None

    @pytest.mark.asyncio()
    async def test_family_falls_back_to_suggested_label(
        self,
        provider: VirusTotalProvider,
    ) -> None:
        """When ``popular_threat_name`` is empty but ``suggested_threat_label``
        is present, the suggested label is the family. Saw this on op_alpha
        samples that lacked an AV-consensus name but had a VT-synthesised label."""
        response = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 8, "undetected": 50},
                        "popular_threat_classification": {
                            "popular_threat_name": [],
                            "suggested_threat_label": "downloader.coinminer/xmrig",
                        },
                    },
                },
            },
            request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/abc"),
        )
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=response,
        ):
            result = await provider.enrich_hash("a" * 64)
        assert result.data["vt_file_family"] == "downloader.coinminer/xmrig"

    @pytest.mark.asyncio()
    async def test_family_empty_when_classification_absent(
        self,
        provider: VirusTotalProvider,
    ) -> None:
        """Hash with no consensus and no synthesised label → empty string.

        Common for hashes VT has seen but few engines flagged. The empty
        string keeps the silver schema Utf8-typed (vs None), letting Polars
        treat it uniformly with other absent-family rows."""
        response = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 1, "undetected": 60},
                    },
                },
            },
            request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/abc"),
        )
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=response,
        ):
            result = await provider.enrich_hash("a" * 64)
        assert result.data["vt_file_family"] == ""

    @pytest.mark.asyncio()
    async def test_200_ip_without_as_owner_returns_empty_string(
        self,
        provider: VirusTotalProvider,
    ) -> None:
        """Some VT 200 responses lack `as_owner` (notably on private-space IPs).

        Observed in op_alpha's first enrichment run: KeyError('as_owner')
        on 198.51.100.42. The runner now defends against missing optional
        attributes the same way it does for missing last_analysis_stats keys.
        """
        sparse = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                        "reputation": 0,
                    },
                },
            },
            request=httpx.Request(
                "GET",
                "https://www.virustotal.com/api/v3/ip_addresses/192.0.2.1",
            ),
        )
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=sparse,
        ):
            result = await provider.enrich_ip("192.0.2.1")

        assert result.data["vt_malicious_count"] == 0
        assert result.data["vt_as_owner"] == ""


class TestVirusTotalRetry:
    @pytest.mark.asyncio()
    async def test_429_fails_fast(self, provider: VirusTotalProvider) -> None:
        """Rate-limit 429 must NOT be retried — defect #11.

        429 means "quota exhausted; reset is hours-to-monthly away".
        Tenacity's 2-30 s exponential backoff cannot outwait that, so each
        retried call is pure wall-clock burn. Op_alpha's 2026-05-21 12:10
        re-run for 2026-05-20 wedged for an hour with three providers each
        retrying ~3000 calls 3x because of this. The runner's
        circuit-breaker (consecutive + cumulative thresholds) is the
        correct authority to decide when to stop hitting the provider.
        """
        rate_limited = httpx.Response(
            429,
            json={"error": "Rate limit"},
            request=httpx.Request(
                "GET",
                "https://www.virustotal.com/api/v3/ip_addresses/192.0.2.1",
            ),
        )
        mock_get = AsyncMock(return_value=rate_limited)
        with (
            patch.object(provider._client, "get", mock_get),
            pytest.raises(httpx.HTTPStatusError) as exc_info,
        ):
            await provider.enrich_ip("192.0.2.1")
        assert exc_info.value.response.status_code == 429
        assert mock_get.await_count == 1  # single attempt, no retry

    @pytest.mark.asyncio()
    async def test_403_fails_fast(self, provider: VirusTotalProvider) -> None:
        """Auth errors must NOT be retried."""
        forbidden = httpx.Response(
            403,
            json={"error": "wrong key"},
            request=httpx.Request(
                "GET",
                "https://www.virustotal.com/api/v3/ip_addresses/192.0.2.1",
            ),
        )
        mock_get = AsyncMock(return_value=forbidden)
        with patch.object(provider._client, "get", mock_get), pytest.raises(httpx.HTTPStatusError):
            await provider.enrich_ip("192.0.2.1")
        assert mock_get.await_count == 1


class TestVtIpRiskScore:
    """Bucketed VT IP score per docs/risk-scoring.md.

    Buckets calibrated against VT's typical 70-90 engine count:
      0       → 0   (clean / not seen)
      1-2     → 25  (single-engine noise; often false positives)
      3-5     → 50  (multi-source agreement)
      6-10    → 75  (broadly flagged)
      >10     → 100 (heavily flagged; uncommon outside known C2)
    """

    @pytest.mark.parametrize(
        ("malicious_count", "expected_score"),
        [
            (0, 0.0),
            (1, 25.0),
            (2, 25.0),
            (3, 50.0),
            (4, 50.0),
            (5, 50.0),
            (6, 75.0),
            (8, 75.0),
            (10, 75.0),
            (11, 100.0),
            (50, 100.0),
            (100, 100.0),
        ],
    )
    def test_bucket_boundaries(self, malicious_count: int, expected_score: float) -> None:
        assert compute_ip_risk_score(malicious_count) == expected_score

    def test_negative_treated_as_zero(self) -> None:
        """Defensive — VT shouldn't return negative but if it ever did
        (e.g., a malformed response), return 0 rather than raising."""
        assert compute_ip_risk_score(-1) == 0.0


class TestVtFileRiskScore:
    """Bucketed VT file score used for cache TTL classification.

    File-scan FP rates are much lower than IP-list FP rates, so a
    single engine flagging crosses the cache "malicious" threshold (50):
      0       → 0   (clean / not seen)
      1       → 50  (crosses cache threshold → 180-day TTL)
      2-4     → 75
      ≥5      → 100
    """

    @pytest.mark.parametrize(
        ("malicious_count", "expected_score"),
        [
            (0, 0.0),
            (1, 50.0),
            (2, 75.0),
            (3, 75.0),
            (4, 75.0),
            (5, 100.0),
            (10, 100.0),
            (50, 100.0),
        ],
    )
    def test_bucket_boundaries(self, malicious_count: int, expected_score: float) -> None:
        assert compute_file_risk_score(malicious_count) == expected_score

    def test_negative_treated_as_zero(self) -> None:
        assert compute_file_risk_score(-1) == 0.0


class TestVtIpRiskScoreInResult:
    @pytest.mark.asyncio()
    async def test_200_response_includes_risk_score(self, provider: VirusTotalProvider) -> None:
        """A high-malicious-count IP returns the top-bucket risk score."""
        resp = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 15, "suspicious": 2},
                        "reputation": -50,
                        "as_owner": "Evil Hosting",
                    },
                },
            },
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/ip_addresses/192.0.2.1"
            ),
        )
        mock_get = AsyncMock(return_value=resp)
        with patch.object(provider._client, "get", mock_get):
            result = await provider.enrich_ip("192.0.2.1")
        assert result.data["vt_malicious_count"] == 15
        assert result.data["virustotal_risk_score"] == 100.0

    @pytest.mark.asyncio()
    async def test_404_response_score_is_none(self, provider: VirusTotalProvider) -> None:
        """404 = never indexed by VT -> virustotal_risk_score=None and vt_status=not_found."""
        not_found = httpx.Response(
            404,
            json={},
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.99"
            ),
        )
        mock_get = AsyncMock(return_value=not_found)
        with patch.object(provider._client, "get", mock_get):
            result = await provider.enrich_ip("198.51.100.99")
        assert result.data["vt_status"] == "not_found"
        assert result.data["virustotal_risk_score"] is None


class TestVirusTotalV15Extensions:
    """v1.5 additions: x-tool header, free vhash, URL/domain lookups, and opt-in GTI."""

    @pytest.mark.asyncio()
    async def test_sends_x_tool_lantana_and_extracts_vhash(
        self, provider: VirusTotalProvider
    ) -> None:
        resp = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 12, "undetected": 50},
                        "meaningful_name": "dropper.elf",
                        "type_tag": "elf",
                        "vhash": "014056655d155515z2010z",
                    }
                }
            },
            request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/abc"),
        )
        mock_get = AsyncMock(return_value=resp)
        with patch.object(provider._client, "get", mock_get):
            result = await provider.enrich_hash("a" * 64)
        assert mock_get.call_args.kwargs["headers"]["x-tool"] == "Lantana"
        assert result.data["vt_status"] == "found"
        assert result.data["vt_file_vhash"] == "014056655d155515z2010z"

    @pytest.mark.asyncio()
    async def test_enrich_url_prefers_downloaded_files_relationship(
        self, provider: VirusTotalProvider
    ) -> None:
        resp = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 4, "suspicious": 1},
                        "last_http_response_content_sha256": "fallback" * 8,
                    },
                    "relationships": {
                        "downloaded_files": {"data": [{"id": "preferred" + "0" * 55}]}
                    },
                }
            },
            request=httpx.Request("GET", "https://www.virustotal.com/api/v3/urls/id"),
        )
        mock_get = AsyncMock(return_value=resp)
        with patch.object(provider._client, "get", mock_get):
            result = await provider.enrich_url("http://stager.example.com/bot.sh")
        assert mock_get.call_args.kwargs["params"]["relationships"] == "downloaded_files"
        assert result.data["vt_url_downloaded_sha256"] == "preferred" + "0" * 55
        assert result.data["vt_url_risk_score"] == 75.0
        assert result.data["vt_status"] == "found"

    @pytest.mark.asyncio()
    async def test_enrich_domain_200_and_404(self, provider: VirusTotalProvider) -> None:
        resp_ok = httpx.Response(
            200,
            json={
                "data": {"attributes": {"last_analysis_stats": {"malicious": 6, "suspicious": 0}}}
            },
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/domains/evil.example.com"
            ),
        )
        with patch.object(provider._client, "get", AsyncMock(return_value=resp_ok)):
            res_ok = await provider.enrich_domain("evil.example.com")
        assert res_ok.data["vt_domain_malicious_count"] == 6
        assert res_ok.data["vt_domain_risk_score"] == 75.0
        assert res_ok.data["vt_status"] == "found"

        resp_404 = httpx.Response(
            404,
            json={},
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/domains/new.example.com"
            ),
        )
        with patch.object(provider._client, "get", AsyncMock(return_value=resp_404)):
            res_404 = await provider.enrich_domain("new.example.com")
        assert res_404.data["vt_status"] == "not_found"
        assert res_404.data["vt_domain_risk_score"] is None

    @pytest.mark.asyncio()
    async def test_gti_opt_in_parses_assessment_and_confidence_gates_associations(self) -> None:
        gti_provider = VirusTotalProvider(api_key="SYNTHETIC_TEST_GTI_000000", gti_enabled=True)
        resp = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 20, "undetected": 40},
                        "vhash": "vhash123",
                        "gti_assessment": {
                            "verdict": {"value": "VERDICT_MALICIOUS"},
                            "severity": {"value": "SEVERITY_HIGH"},
                            "threat_score": {"value": 92},
                        },
                    },
                    "relationships": {
                        "threat_actors": {
                            "data": [
                                {
                                    "id": "ta-1",
                                    "attributes": {"name": "UNC9999"},
                                    "context_attributes": {"mandiant_confidence_score": 85},
                                },
                                {
                                    "id": "ta-2",
                                    "attributes": {"name": "LOW_CONF_NOISE"},
                                    "context_attributes": {"mandiant_confidence_score": 40},
                                },
                            ]
                        },
                        "malware_families": {
                            "data": [
                                {
                                    "id": "mf-1",
                                    "attributes": {"name": "MIRAI_VARIANT"},
                                    "context_attributes": {"mandiant_confidence_score": 90},
                                }
                            ]
                        },
                    },
                }
            },
            request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/abc"),
        )
        mock_get = AsyncMock(return_value=resp)
        with patch.object(gti_provider._client, "get", mock_get):
            result = await gti_provider.enrich_hash("b" * 64)
        await gti_provider.close()
        assert "associations" in mock_get.call_args.kwargs["params"]["relationships"]
        assert result.data["gti_verdict"] == "VERDICT_MALICIOUS"
        assert result.data["gti_score"] == 92
        assert result.data["gti_threat_actors"] == "UNC9999"
        assert "LOW_CONF_NOISE" not in str(result.data.get("gti_threat_actors", ""))
        assert result.data["gti_malware_families"] == "MIRAI_VARIANT"

    @pytest.mark.asyncio()
    async def test_gti_benign_verdict_suppresses_associations(self) -> None:
        gti_provider = VirusTotalProvider(api_key="SYNTHETIC_TEST_GTI_000000", gti_enabled=True)
        resp = httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                        "gti_assessment": {
                            "verdict": {"value": "VERDICT_BENIGN"},
                            "threat_score": {"value": 0},
                        },
                    },
                    "relationships": {
                        "threat_actors": {
                            "data": [
                                {
                                    "id": "ta-1",
                                    "attributes": {"name": "FALSE_POSITIVE_ACTOR"},
                                    "context_attributes": {"mandiant_confidence_score": 95},
                                }
                            ]
                        }
                    },
                }
            },
            request=httpx.Request(
                "GET", "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.1"
            ),
        )
        with patch.object(gti_provider._client, "get", AsyncMock(return_value=resp)):
            result = await gti_provider.enrich_ip("198.51.100.1")
        await gti_provider.close()
        assert result.data["gti_verdict"] == "VERDICT_BENIGN"
        assert "gti_threat_actors" not in result.data

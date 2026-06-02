"""Tests for the Shodan enrichment provider."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from lantana.enrichment.providers.shodan import ShodanProvider, compute_risk_score


@pytest.fixture()
def provider() -> ShodanProvider:
    return ShodanProvider(api_key="test-key")


def _ok_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "ports": [22, 80, 443],
            "os": None,
            "vulns": ["CVE-2024-1234"],
            "org": "Example Corp",
            "asn": "AS12345",
            "ip_str": "1.2.3.4",
        },
        request=httpx.Request("GET", "https://api.shodan.io/shodan/host/1.2.3.4"),
    )


class TestShodanProvider:
    @pytest.mark.asyncio()
    async def test_enrich_ip_returns_normalized_fields(self, provider: ShodanProvider) -> None:
        """200 OK populates the five shodan_* fields."""
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=_ok_response(),
        ):
            result = await provider.enrich_ip("1.2.3.4")

        assert result.provider == "shodan"
        assert result.data["shodan_ports"] == "22,80,443"
        assert result.data["shodan_os"] is None
        assert result.data["shodan_vulns"] == "CVE-2024-1234"
        assert result.data["shodan_org"] == "Example Corp"
        assert result.data["shodan_asn"] == "AS12345"

    @pytest.mark.asyncio()
    async def test_404_returns_empty_result_without_raising(self, provider: ShodanProvider) -> None:
        """Shodan 404 means 'IP not scanned' — return an empty result, don't error.

        Common for honeypot attacker IPs (residential botnets Shodan hasn't
        crawled). Treating 404 as an error would drop the row entirely.
        """
        not_found = httpx.Response(
            404,
            json={"error": "No information available for that IP."},
            request=httpx.Request("GET", "https://api.shodan.io/shodan/host/9.9.9.9"),
        )
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=not_found,
        ):
            result = await provider.enrich_ip("9.9.9.9")

        assert result.provider == "shodan"
        assert result.ip == "9.9.9.9"
        assert result.data["shodan_ports"] == ""
        assert result.data["shodan_org"] == ""
        assert result.data["shodan_asn"] == ""
        assert result.data["shodan_os"] is None
        assert result.data["shodan_vulns"] is None

    @pytest.mark.asyncio()
    async def test_200_without_asn_and_org_returns_empty_strings(
        self,
        provider: ShodanProvider,
    ) -> None:
        """Some 200 responses are sparse — `asn`/`org` may simply be absent.

        Observed in op_alpha's first enrichment run: ~30 IPs returned
        200 OK but no asn key, causing KeyError before this fix.
        """
        sparse = httpx.Response(
            200,
            json={"ports": [22], "ip_str": "1.2.3.4"},
            request=httpx.Request("GET", "https://api.shodan.io/shodan/host/1.2.3.4"),
        )
        with patch.object(
            provider._client,
            "get",
            new_callable=AsyncMock,
            return_value=sparse,
        ):
            result = await provider.enrich_ip("1.2.3.4")

        assert result.data["shodan_ports"] == "22"
        assert result.data["shodan_asn"] == ""
        assert result.data["shodan_org"] == ""

    @pytest.mark.asyncio()
    async def test_500_is_retried_then_raises(self, provider: ShodanProvider) -> None:
        """5xx server errors are retried; with reraise=True the original
        HTTPStatusError surfaces after the retry budget is exhausted."""
        bad_gateway = httpx.Response(
            502,
            text="bad gateway",
            request=httpx.Request("GET", "https://api.shodan.io/shodan/host/1.2.3.4"),
        )
        mock_get = AsyncMock(return_value=bad_gateway)
        with (
            patch.object(provider._client, "get", mock_get),
            pytest.raises(httpx.HTTPStatusError) as exc_info,
        ):
            await provider.enrich_ip("1.2.3.4")
        assert exc_info.value.response.status_code == 502
        # Confirm retried at least twice (tenacity stop_after_attempt(3))
        assert mock_get.await_count >= 2

    @pytest.mark.asyncio()
    async def test_401_fails_fast_without_retry(self, provider: ShodanProvider) -> None:
        """4xx auth errors must NOT be retried — wastes the rate budget."""
        unauthorized = httpx.Response(
            401,
            json={"error": "No API key"},
            request=httpx.Request("GET", "https://api.shodan.io/shodan/host/1.2.3.4"),
        )
        mock_get = AsyncMock(return_value=unauthorized)
        with patch.object(provider._client, "get", mock_get), pytest.raises(httpx.HTTPStatusError):
            await provider.enrich_ip("1.2.3.4")
        assert mock_get.await_count == 1


class TestShodanRiskScore:
    """Tri-state Shodan score per docs/risk-scoring.md.

    The CVE signal is the strongest Shodan datum: it implies the IP is
    internet-exposed AND scanned AND has a known vulnerability — three
    facts in one. Ports without CVEs is a weaker but real signal (exposed
    surface). Empty Shodan = 0 (residential / unscanned)."""

    def test_vulns_present_is_max_score(self) -> None:
        assert compute_risk_score("22,80,443", "CVE-2024-1234") == 100.0

    def test_vulns_present_with_no_ports_still_max(self) -> None:
        """Unusual but possible: a CVE-marked IP with no enumerated ports
        (Shodan response shape varies). The CVE is the load-bearing signal."""
        assert compute_risk_score("", "CVE-2023-9999") == 100.0

    def test_ports_only_mid_score(self) -> None:
        assert compute_risk_score("22,80,443", None) == 25.0
        assert compute_risk_score("443", "") == 25.0

    def test_empty_response_zero_score(self) -> None:
        """200-with-no-data (residential IP not in Shodan's scan index)
        and the 404 fallback both reach this branch."""
        assert compute_risk_score("", None) == 0.0
        assert compute_risk_score("", "") == 0.0


class TestShodanRiskScoreInResult:
    @pytest.mark.asyncio()
    async def test_200_response_includes_risk_score(self, provider: ShodanProvider) -> None:
        mock_get = AsyncMock(return_value=_ok_response())
        with patch.object(provider._client, "get", mock_get):
            result = await provider.enrich_ip("1.2.3.4")
        # Fixture has CVE-2024-1234 → expect 100.
        assert result.data["shodan_risk_score"] == 100.0

    @pytest.mark.asyncio()
    async def test_404_response_score_is_zero(self, provider: ShodanProvider) -> None:
        not_found = httpx.Response(
            404,
            json={},
            request=httpx.Request("GET", "https://api.shodan.io/shodan/host/1.2.3.4"),
        )
        mock_get = AsyncMock(return_value=not_found)
        with patch.object(provider._client, "get", mock_get):
            result = await provider.enrich_ip("1.2.3.4")
        assert result.data["shodan_risk_score"] == 0.0

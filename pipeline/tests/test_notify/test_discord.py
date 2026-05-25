"""Tests for Discord webhook notification client."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from lantana.notify.alerts import ErrorBuckets
from lantana.notify.discord import EMBED_COLORS, max_severity, send_notification


@pytest.fixture()
def mock_httpx_client() -> AsyncMock:
    """Mock httpx.AsyncClient for testing without network calls."""
    mock_response = AsyncMock()
    mock_response.status_code = 204
    mock_response.raise_for_status = lambda: None  # sync method on httpx.Response

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


async def test_send_notification_posts_embed(mock_httpx_client: AsyncMock) -> None:
    """send_notification posts a Discord embed with correct color."""
    with patch("lantana.notify.discord.httpx.AsyncClient", return_value=mock_httpx_client):
        await send_notification(
            webhook_url="https://discord.com/api/webhooks/test",
            level="warning",
            title="Disk Warning",
            message="Usage at 75%",
        )

    mock_httpx_client.post.assert_called_once()
    call_kwargs = mock_httpx_client.post.call_args
    payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
    assert payload["embeds"][0]["title"] == "Disk Warning"
    assert payload["embeds"][0]["color"] == EMBED_COLORS["warning"]


async def test_send_notification_info_color(mock_httpx_client: AsyncMock) -> None:
    """Info level uses green embed color."""
    with patch("lantana.notify.discord.httpx.AsyncClient", return_value=mock_httpx_client):
        await send_notification(
            webhook_url="https://discord.com/api/webhooks/test",
            level="info",
            title="Test",
            message="Test message",
        )

    payload = mock_httpx_client.post.call_args.kwargs.get("json")
    assert payload["embeds"][0]["color"] == EMBED_COLORS["info"]


async def test_send_notification_critical_color(mock_httpx_client: AsyncMock) -> None:
    """Critical level uses red embed color."""
    with patch("lantana.notify.discord.httpx.AsyncClient", return_value=mock_httpx_client):
        await send_notification(
            webhook_url="https://discord.com/api/webhooks/test",
            level="critical",
            title="Emergency",
            message="Disk full",
        )

    payload = mock_httpx_client.post.call_args.kwargs.get("json")
    assert payload["embeds"][0]["color"] == EMBED_COLORS["critical"]


async def test_send_notification_with_attachment(
    mock_httpx_client: AsyncMock, tmp_path: str
) -> None:
    """Attachment is sent as multipart form data."""
    from pathlib import Path

    file_path = Path(tmp_path) / "report.txt"
    file_path.write_text("test report content")

    with patch("lantana.notify.discord.httpx.AsyncClient", return_value=mock_httpx_client):
        await send_notification(
            webhook_url="https://discord.com/api/webhooks/test",
            level="info",
            title="Report",
            message="Daily report attached",
            attachment_path=str(file_path),
        )

    call_kwargs = mock_httpx_client.post.call_args
    assert "files" in call_kwargs.kwargs or "files" in (call_kwargs[1] if len(call_kwargs) > 1 else {})


# ---------------------------------------------------------------------------
# max_severity — embed-color decision
# ---------------------------------------------------------------------------


class TestMaxSeverity:
    def test_clean_returns_info(self) -> None:
        """No errors at all → green embed via info level."""
        assert max_severity(ErrorBuckets(critical=[], warning=[])) == "info"

    def test_info_only_returns_info(self) -> None:
        """Rate-limit-only day stays green; routine ops noise doesn't escalate."""
        buckets = ErrorBuckets(
            critical=[],
            warning=[],
            info=[{"provider": "abuseipdb", "error_type": "rate_limit", "count": 100}],
        )
        assert max_severity(buckets) == "info"

    def test_warning_present_returns_warning(self) -> None:
        buckets = ErrorBuckets(
            critical=[],
            warning=[{"provider": "shodan", "error_type": "timeout", "count": 1}],
        )
        assert max_severity(buckets) == "warning"

    def test_critical_present_returns_critical(self) -> None:
        """Critical wins over warning and info."""
        buckets = ErrorBuckets(
            critical=[{"provider": "pipeline", "error_type": "transform_failed", "count": 1}],
            warning=[{"provider": "shodan", "error_type": "timeout", "count": 1}],
            info=[{"provider": "abuseipdb", "error_type": "rate_limit", "count": 100}],
        )
        assert max_severity(buckets) == "critical"

"""Tests for lantana-notify CLI."""

from __future__ import annotations

from lantana.notify.cli import _resolve_webhook_url


def test_resolve_webhook_url_from_arg() -> None:
    """CLI arg takes priority over env and secrets."""
    assert _resolve_webhook_url("https://hooks.example.com") == "https://hooks.example.com"


def test_resolve_webhook_url_from_env(monkeypatch: object) -> None:
    """Env var is used when CLI arg is None."""
    import pytest

    mp = pytest.MonkeyPatch()
    mp.setenv("LANTANA_DISCORD_WEBHOOK", "https://env.example.com")
    try:
        assert _resolve_webhook_url(None) == "https://env.example.com"
    finally:
        mp.undo()


def test_resolve_webhook_url_none_when_missing() -> None:
    """Returns None when no source provides a URL."""
    import os

    # Ensure env var is not set
    os.environ.pop("LANTANA_DISCORD_WEBHOOK", None)
    # secrets.json won't exist in test environment, so this should return None
    result = _resolve_webhook_url(None)
    assert result is None

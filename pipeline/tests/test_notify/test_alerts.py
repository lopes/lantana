"""Tests for the daily error-log alerter (lantana.notify.alerts)."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path  # noqa: TC003 — used at runtime in tmp_path fixtures
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from lantana.notify.alerts import (
    CRITICAL_ERROR_TYPES,
    INFO_ERROR_TYPES,
    ErrorBuckets,
    build_embed_body,
    categorize_errors,
    has_been_alerted,
    load_errors_for_date,
    mark_alerted,
    run_alerter,
)

# ---------------------------------------------------------------------------
# categorize_errors
# ---------------------------------------------------------------------------


class TestCategorizeErrors:
    def test_dataset_processing_failed_is_critical(self) -> None:
        rows = [
            {"error_type": "dataset_processing_failed", "provider": "pipeline", "count": 1},
        ]
        buckets = categorize_errors(rows)
        assert len(buckets.critical) == 1
        assert buckets.warning == []
        assert buckets.has_critical is True
        assert buckets.is_clean is False

    def test_transform_failed_is_critical(self) -> None:
        rows = [
            {"error_type": "transform_failed", "provider": "transform", "count": 1},
        ]
        buckets = categorize_errors(rows)
        assert len(buckets.critical) == 1

    def test_rate_limit_is_info(self) -> None:
        """Rate-limit exhaustion is routine ops noise — info tier, not warning."""
        rows = [
            {"error_type": "rate_limit", "provider": "abuseipdb", "count": 5},
        ]
        buckets = categorize_errors(rows)
        assert buckets.critical == []
        assert buckets.warning == []
        assert len(buckets.info) == 1
        # Info-only days are clean from the alerter's perspective.
        assert buckets.is_clean is True

    def test_auth_failed_is_warning_not_critical(self) -> None:
        """Provider key broken = pipeline still produces files = warning, not critical."""
        rows = [
            {"error_type": "auth_failed", "provider": "virustotal", "count": 1},
        ]
        buckets = categorize_errors(rows)
        assert buckets.critical == []
        assert len(buckets.warning) == 1
        assert buckets.info == []
        assert buckets.has_critical is False

    def test_timeout_is_warning(self) -> None:
        """Non-rate-limit transient errors stay in warning."""
        rows = [
            {"error_type": "timeout", "provider": "shodan", "count": 3},
        ]
        buckets = categorize_errors(rows)
        assert len(buckets.warning) == 1
        assert buckets.info == []

    def test_mixed_severities_three_tier(self) -> None:
        rows = [
            {"error_type": "rate_limit", "provider": "abuseipdb", "count": 5},
            {"error_type": "dataset_processing_failed", "provider": "pipeline", "count": 1},
            {"error_type": "timeout", "provider": "shodan", "count": 3},
        ]
        buckets = categorize_errors(rows)
        assert len(buckets.critical) == 1
        assert len(buckets.warning) == 1  # timeout only — rate_limit moved to info
        assert len(buckets.info) == 1

    def test_clean_day(self) -> None:
        buckets = categorize_errors([])
        assert buckets.is_clean is True
        assert buckets.has_critical is False
        assert buckets.info == []

    def test_critical_set_contract(self) -> None:
        """Pin the critical error-type list so adding a new one is an explicit choice."""
        assert (
            frozenset(
                {
                    "dataset_processing_failed",
                    "transform_failed",
                }
            )
            == CRITICAL_ERROR_TYPES
        )

    def test_info_set_contract(self) -> None:
        """Info tier is routine ops noise; new entries require explicit thought
        about whether rate-limit-class signals are appropriate."""
        assert frozenset({"rate_limit"}) == INFO_ERROR_TYPES


# ---------------------------------------------------------------------------
# load_errors_for_date
# ---------------------------------------------------------------------------


class TestLoadErrorsForDate:
    def _write(self, path: Path, rows: list[dict[str, Any]]) -> None:
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def test_filters_by_date(self, tmp_path: Path) -> None:
        errors_path = tmp_path / "errors.json"
        self._write(
            errors_path,
            [
                {
                    "date": "2026-05-19",
                    "provider": "abuseipdb",
                    "error_type": "rate_limit",
                    "count": 1,
                },
                {
                    "date": "2026-05-20",
                    "provider": "shodan",
                    "error_type": "rate_limit",
                    "count": 5,
                },
                {
                    "date": "2026-05-21",
                    "provider": "pipeline",
                    "error_type": "dataset_processing_failed",
                    "count": 1,
                },
            ],
        )
        rows = load_errors_for_date(errors_path, date(2026, 5, 20))
        assert len(rows) == 1
        assert rows[0]["provider"] == "shodan"

    def test_returns_empty_when_file_missing(self, tmp_path: Path) -> None:
        rows = load_errors_for_date(tmp_path / "no_such_file.json", date(2026, 5, 20))
        assert rows == []

    def test_skips_malformed_rows(self, tmp_path: Path) -> None:
        """A corrupt line must not crash the alerter."""
        errors_path = tmp_path / "errors.json"
        errors_path.write_text(
            '{"date": "2026-05-20", "provider": "ok", "error_type": "rate_limit", "count": 1}\n'
            "{not valid json\n"
            '{"date": "2026-05-20", "provider": "ok2", "error_type": "timeout", "count": 1}\n'
        )
        rows = load_errors_for_date(errors_path, date(2026, 5, 20))
        assert len(rows) == 2
        assert {r["provider"] for r in rows} == {"ok", "ok2"}

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        errors_path = tmp_path / "errors.json"
        errors_path.write_text(
            '{"date": "2026-05-20", "provider": "ok", "error_type": "rate_limit", "count": 1}\n\n\n'
        )
        rows = load_errors_for_date(errors_path, date(2026, 5, 20))
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# build_embed_body
# ---------------------------------------------------------------------------


class TestBuildEmbedBody:
    def test_critical_section_when_present(self) -> None:
        buckets = ErrorBuckets(
            critical=[
                {
                    "provider": "pipeline",
                    "error_type": "dataset_processing_failed",
                    "count": 1,
                    "message": "ValueError: leak in unmapped_password",
                }
            ],
            warning=[],
        )
        body = build_embed_body(date(2026, 5, 20), buckets)
        assert "2026-05-20" in body
        assert "Critical: 1" in body
        assert "pipeline" in body
        assert "dataset_processing_failed" in body

    def test_warning_section_grouped(self) -> None:
        """Repeated (provider, error_type) pairs are aggregated to one row."""
        buckets = ErrorBuckets(
            critical=[],
            warning=[
                {"provider": "abuseipdb", "error_type": "rate_limit", "count": 5},
                {"provider": "abuseipdb", "error_type": "rate_limit", "count": 7},
                {"provider": "shodan", "error_type": "rate_limit", "count": 5},
            ],
        )
        body = build_embed_body(date(2026, 5, 20), buckets)
        assert "Warnings: 17" in body
        # abuseipdb appears once even though it has two source rows
        assert body.count("`abuseipdb`") == 1
        assert "x12" in body  # 5+7 = 12
        assert "`shodan`" in body

    def test_truncates_long_messages(self) -> None:
        long_msg = "x" * 1000
        buckets = ErrorBuckets(
            critical=[
                {
                    "provider": "pipeline",
                    "error_type": "dataset_processing_failed",
                    "count": 1,
                    "message": long_msg,
                }
            ],
            warning=[],
        )
        body = build_embed_body(date(2026, 5, 20), buckets)
        # The message itself is truncated to <= 200 chars in the rendered output
        assert long_msg not in body

    def test_clean_day_renders_empty_body(self) -> None:
        body = build_embed_body(date(2026, 5, 20), ErrorBuckets(critical=[], warning=[]))
        assert "2026-05-20" in body
        assert "Critical" not in body
        assert "Warnings" not in body
        assert "Info" not in body

    def test_info_section_grouped(self) -> None:
        """Info-tier rate-limit rows aggregate by (provider, error_type)."""
        buckets = ErrorBuckets(
            critical=[],
            warning=[],
            info=[
                {"provider": "abuseipdb", "error_type": "rate_limit", "count": 100},
                {"provider": "shodan", "error_type": "rate_limit", "count": 4},
            ],
        )
        body = build_embed_body(date(2026, 5, 20), buckets)
        assert "Info: 104" in body
        assert "abuseipdb" in body
        assert "shodan" in body
        # No critical or warning sections rendered when those buckets are empty.
        assert "Critical" not in body
        assert "Warnings" not in body

    def test_three_tier_body(self) -> None:
        """All three sections render together on a mixed day."""
        buckets = ErrorBuckets(
            critical=[
                {
                    "provider": "pipeline",
                    "error_type": "dataset_processing_failed",
                    "count": 1,
                    "message": "nft schema mismatch",
                }
            ],
            warning=[
                {"provider": "virustotal", "error_type": "timeout", "count": 3},
            ],
            info=[
                {"provider": "abuseipdb", "error_type": "rate_limit", "count": 200},
            ],
        )
        body = build_embed_body(date(2026, 5, 20), buckets)
        assert "Critical: 1" in body
        assert "Warnings: 3" in body
        assert "Info: 200" in body


# ---------------------------------------------------------------------------
# Idempotency marker
# ---------------------------------------------------------------------------


class TestIdempotencyMarker:
    def test_has_been_alerted_false_when_no_file(self, tmp_path: Path) -> None:
        assert has_been_alerted(tmp_path / "marker", date(2026, 5, 20)) is False

    def test_mark_then_check(self, tmp_path: Path) -> None:
        marker = tmp_path / "marker"
        mark_alerted(marker, date(2026, 5, 20))
        assert has_been_alerted(marker, date(2026, 5, 20)) is True
        # Another date is not yet alerted
        assert has_been_alerted(marker, date(2026, 5, 21)) is False

    def test_multiple_dates_in_marker(self, tmp_path: Path) -> None:
        marker = tmp_path / "marker"
        mark_alerted(marker, date(2026, 5, 19))
        mark_alerted(marker, date(2026, 5, 20))
        mark_alerted(marker, date(2026, 5, 21))
        assert has_been_alerted(marker, date(2026, 5, 20)) is True
        assert has_been_alerted(marker, date(2026, 5, 19)) is True
        assert has_been_alerted(marker, date(2026, 5, 22)) is False

    def test_mark_creates_parent_dirs(self, tmp_path: Path) -> None:
        marker = tmp_path / "nested" / "subdirs" / "marker"
        mark_alerted(marker, date(2026, 5, 20))
        assert marker.exists()


# ---------------------------------------------------------------------------
# run_alerter — orchestration
# ---------------------------------------------------------------------------


def _make_reporting() -> Any:
    from lantana.common.config import (
        OperationConfig,
        OperatorConfig,
        RedactConfig,
        ReportingConfig,
        SharingConfig,
    )

    return ReportingConfig(
        operator=OperatorConfig(
            name="Test",
            handle="t",
            contact="x",
            pgp_fingerprint="A",
        ),
        sharing=SharingConfig(tlp="GREEN", community="t", discord_channel="c"),
        operation=OperationConfig(
            name="op_test",
            description="x",
            sector="t",
            region="t",
            start_date="2026-01-01",
        ),
        redact=RedactConfig(infrastructure_ips=[], infrastructure_cidrs=[], pseudonym_map={}),
    )


def _make_secrets(webhook: str = "https://discord.test/webhook") -> Any:
    from lantana.common.config import SecretsConfig

    return SecretsConfig.model_validate(
        {
            "vault_apikey_virustotal": "v",
            "vault_apikey_shodan": "s",
            "vault_apikey_abuseipdb": "a",
            "vault_apikey_greynoise": "g",
            "vault_webhook_discord": webhook,
        }
    )


class TestRunAlerter:
    @pytest.mark.asyncio()
    async def test_clean_day_does_not_send(self, tmp_path: Path) -> None:
        """No errors for the date → no Discord webhook, no marker write."""
        errors_path = tmp_path / "errors.json"
        errors_path.write_text("")  # empty file
        state_path = tmp_path / ".last_alerted"

        with patch("lantana.notify.alerts.send_notification") as mock_send:
            await run_alerter(
                date(2026, 5, 20),
                errors_path=errors_path,
                state_path=state_path,
            )

        mock_send.assert_not_called()
        assert not state_path.exists()

    @pytest.mark.asyncio()
    async def test_critical_day_sends_red_alert(self, tmp_path: Path) -> None:
        errors_path = tmp_path / "errors.json"
        errors_path.write_text(
            json.dumps(
                {
                    "date": "2026-05-20",
                    "provider": "pipeline",
                    "error_type": "dataset_processing_failed",
                    "count": 1,
                    "message": "ValueError(...)",
                }
            )
            + "\n"
        )
        state_path = tmp_path / ".last_alerted"

        with (
            patch("lantana.notify.alerts.send_notification", new=AsyncMock()) as mock_send,
            patch("lantana.notify.alerts.load_secrets", new=_make_secrets),
            patch("lantana.notify.alerts.load_reporting", new=_make_reporting),
        ):
            await run_alerter(
                date(2026, 5, 20),
                errors_path=errors_path,
                state_path=state_path,
            )

        mock_send.assert_called_once()
        kwargs = mock_send.call_args.kwargs
        assert kwargs["level"] == "critical"
        assert "op_test" in kwargs["title"]
        assert "2026-05-20" in kwargs["title"]
        # Marker written so a re-run is idempotent
        assert state_path.exists()

    @pytest.mark.asyncio()
    async def test_warning_only_day_sends_orange_alert(self, tmp_path: Path) -> None:
        """Warning-tier errors (non-rate-limit transient) fire the orange alert."""
        errors_path = tmp_path / "errors.json"
        errors_path.write_text(
            json.dumps(
                {
                    "date": "2026-05-20",
                    "provider": "virustotal",
                    "error_type": "timeout",
                    "count": 5,
                    "message": "Read timeout",
                }
            )
            + "\n"
        )
        state_path = tmp_path / ".last_alerted"

        with (
            patch("lantana.notify.alerts.send_notification", new=AsyncMock()) as mock_send,
            patch("lantana.notify.alerts.load_secrets", new=_make_secrets),
            patch("lantana.notify.alerts.load_reporting", new=_make_reporting),
        ):
            await run_alerter(
                date(2026, 5, 20),
                errors_path=errors_path,
                state_path=state_path,
            )

        mock_send.assert_called_once()
        assert mock_send.call_args.kwargs["level"] == "warning"

    @pytest.mark.asyncio()
    async def test_info_only_day_does_not_send(self, tmp_path: Path) -> None:
        """Rate-limit-only days are info-tier — the alerter stays silent.

        The merged daily report (lantana-report) still surfaces them in its
        attachment, so traceability is preserved.
        """
        errors_path = tmp_path / "errors.json"
        errors_path.write_text(
            json.dumps(
                {
                    "date": "2026-05-20",
                    "provider": "abuseipdb",
                    "error_type": "rate_limit",
                    "count": 200,
                    "message": "429",
                }
            )
            + "\n"
        )
        state_path = tmp_path / ".last_alerted"

        with patch("lantana.notify.alerts.send_notification", new=AsyncMock()) as mock_send:
            await run_alerter(
                date(2026, 5, 20),
                errors_path=errors_path,
                state_path=state_path,
            )

        mock_send.assert_not_called()
        # Same as a clean day — no marker written so a future warning row picked
        # up on a manual --force still alerts.
        assert not state_path.exists()

    @pytest.mark.asyncio()
    async def test_idempotent_second_run(self, tmp_path: Path) -> None:
        errors_path = tmp_path / "errors.json"
        errors_path.write_text(
            json.dumps(
                {
                    "date": "2026-05-20",
                    "provider": "pipeline",
                    "error_type": "dataset_processing_failed",
                    "count": 1,
                    "message": "...",
                }
            )
            + "\n"
        )
        state_path = tmp_path / ".last_alerted"
        # Pre-populate marker as if a prior run had sent the alert
        mark_alerted(state_path, date(2026, 5, 20))

        with patch("lantana.notify.alerts.send_notification", new=AsyncMock()) as mock_send:
            await run_alerter(
                date(2026, 5, 20),
                errors_path=errors_path,
                state_path=state_path,
            )

        mock_send.assert_not_called()

    @pytest.mark.asyncio()
    async def test_force_overrides_marker(self, tmp_path: Path) -> None:
        errors_path = tmp_path / "errors.json"
        errors_path.write_text(
            json.dumps(
                {
                    "date": "2026-05-20",
                    "provider": "pipeline",
                    "error_type": "dataset_processing_failed",
                    "count": 1,
                    "message": "...",
                }
            )
            + "\n"
        )
        state_path = tmp_path / ".last_alerted"
        mark_alerted(state_path, date(2026, 5, 20))

        with (
            patch("lantana.notify.alerts.send_notification", new=AsyncMock()) as mock_send,
            patch("lantana.notify.alerts.load_secrets", new=_make_secrets),
            patch("lantana.notify.alerts.load_reporting", new=_make_reporting),
        ):
            await run_alerter(
                date(2026, 5, 20),
                errors_path=errors_path,
                state_path=state_path,
                force=True,
            )

        mock_send.assert_called_once()

    @pytest.mark.asyncio()
    async def test_no_webhook_configured_skips_send(self, tmp_path: Path) -> None:
        """A missing webhook is logged-and-skipped, not crash."""
        errors_path = tmp_path / "errors.json"
        errors_path.write_text(
            json.dumps(
                {
                    "date": "2026-05-20",
                    "provider": "pipeline",
                    "error_type": "dataset_processing_failed",
                    "count": 1,
                    "message": "...",
                }
            )
            + "\n"
        )
        state_path = tmp_path / ".last_alerted"

        def _empty_secrets() -> Any:
            return _make_secrets(webhook="")

        with (
            patch("lantana.notify.alerts.send_notification", new=AsyncMock()) as mock_send,
            patch("lantana.notify.alerts.load_secrets", new=_empty_secrets),
            patch("lantana.notify.alerts.load_reporting", new=_make_reporting),
        ):
            await run_alerter(
                date(2026, 5, 20),
                errors_path=errors_path,
                state_path=state_path,
            )

        mock_send.assert_not_called()
        # No marker — don't lock in success on a configuration miss
        assert not state_path.exists()

"""Tests for per-step pipeline duration sourcing via systemd."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from lantana.notify.timing import (
    StepTiming,
    _parse_show_output,
    _parse_timestamp,
    collect_step_timings,
    render_timing_one_liner,
    render_timing_section,
)


def _completed(
    stdout: str = "",
    returncode: int = 0,
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    """Build a fake systemctl CompletedProcess for patching subprocess.run."""
    return subprocess.CompletedProcess(
        args=["systemctl"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _st(unit: str, dur: float | None, result: str = "success") -> StepTiming:
    """Compact StepTiming builder for tests — keeps fixture lines under 100 chars."""
    return StepTiming(unit=unit, duration_seconds=dur, result=result, finished_at=None)


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestParseTimestamp:
    def test_parses_systemd_format(self) -> None:
        """systemd renders timestamps as ``Day YYYY-MM-DD HH:MM:SS TZ``."""
        ts = _parse_timestamp("Mon 2026-05-25 04:01:13 UTC")
        assert ts is not None
        assert ts.year == 2026
        assert ts.month == 5
        assert ts.day == 25
        assert ts.hour == 4

    def test_empty_string_returns_none(self) -> None:
        """Never-run services have an empty ExecMainStartTimestamp."""
        assert _parse_timestamp("") is None

    def test_whitespace_only_returns_none(self) -> None:
        assert _parse_timestamp("   ") is None

    def test_zero_string_returns_none(self) -> None:
        """Some systemd versions render unset timestamps as ``0``."""
        assert _parse_timestamp("0") is None

    def test_unparseable_returns_none_does_not_raise(self) -> None:
        """Junk input must not crash — the timing section silently omits."""
        assert _parse_timestamp("not a real timestamp") is None


# ---------------------------------------------------------------------------
# systemctl output parsing
# ---------------------------------------------------------------------------


class TestParseShowOutput:
    def test_parses_key_value_lines(self) -> None:
        stdout = (
            "ExecMainStartTimestamp=Mon 2026-05-25 04:01:13 UTC\n"
            "ExecMainExitTimestamp=Mon 2026-05-25 04:19:55 UTC\n"
            "Result=success\n"
        )
        out = _parse_show_output(stdout)
        assert out["ExecMainStartTimestamp"] == "Mon 2026-05-25 04:01:13 UTC"
        assert out["Result"] == "success"

    def test_skips_lines_without_equals(self) -> None:
        out = _parse_show_output("ExecMainStartTimestamp=foo\nbogus line\nResult=ok\n")
        assert out == {"ExecMainStartTimestamp": "foo", "Result": "ok"}

    def test_empty_values_allowed(self) -> None:
        """Never-run units give us empty values, not missing keys."""
        out = _parse_show_output("ExecMainStartTimestamp=\nResult=success\n")
        assert out["ExecMainStartTimestamp"] == ""


# ---------------------------------------------------------------------------
# collect_step_timings — happy path + failure modes
# ---------------------------------------------------------------------------


class TestCollectStepTimings:
    def test_happy_path_computes_duration(self) -> None:
        stdout = (
            "ExecMainStartTimestamp=Mon 2026-05-25 04:01:00 UTC\n"
            "ExecMainExitTimestamp=Mon 2026-05-25 04:19:30 UTC\n"
            "Result=success\n"
        )
        with patch("lantana.notify.timing.subprocess.run", return_value=_completed(stdout)):
            timings = collect_step_timings(["lantana-enrich"])
        assert len(timings) == 1
        t = timings[0]
        assert t.unit == "lantana-enrich"
        assert t.duration_seconds == 18 * 60 + 30  # 18:30 elapsed
        assert t.duration_minutes is not None
        assert abs(t.duration_minutes - 18.5) < 0.01
        assert t.result == "success"

    def test_never_run_unit_returns_none_duration(self) -> None:
        """Both timestamps empty (e.g. timer fired but unit not yet scheduled)."""
        stdout = "ExecMainStartTimestamp=\nExecMainExitTimestamp=\nResult=success\n"
        with patch("lantana.notify.timing.subprocess.run", return_value=_completed(stdout)):
            timings = collect_step_timings(["lantana-prune"])
        assert timings[0].duration_seconds is None
        # Result still surfaces — operators can see units exist but haven't fired.
        assert timings[0].result == "success"

    def test_subprocess_failure_returns_unknown(self) -> None:
        """FileNotFoundError (no systemctl, e.g. dev macOS) → unknown, not crash."""
        with patch(
            "lantana.notify.timing.subprocess.run",
            side_effect=FileNotFoundError("systemctl not found"),
        ):
            timings = collect_step_timings(["lantana-enrich"])
        assert timings[0].duration_seconds is None
        assert timings[0].result == "unknown"

    def test_subprocess_timeout_returns_unknown(self) -> None:
        """If D-Bus is wedged the call times out — must not block the brief."""
        with patch(
            "lantana.notify.timing.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="systemctl", timeout=10),
        ):
            timings = collect_step_timings(["lantana-enrich"])
        assert timings[0].duration_seconds is None
        assert timings[0].result == "unknown"

    def test_nonzero_returncode_returns_unknown(self) -> None:
        """systemctl returning non-zero (e.g. unknown unit) is treated as a query failure."""
        with patch(
            "lantana.notify.timing.subprocess.run",
            return_value=_completed(stdout="", returncode=4, stderr="Unit not loaded."),
        ):
            timings = collect_step_timings(["lantana-typo"])
        assert timings[0].duration_seconds is None
        assert timings[0].result == "unknown"

    def test_failed_result_surfaces(self) -> None:
        """A unit that ran but failed surfaces with result=failed.

        This is the key signal for ``run_summary`` not emitted: the unit
        crashed before writing the errors row, but the operator still sees
        the failure in the timing table."""
        stdout = (
            "ExecMainStartTimestamp=Mon 2026-05-25 04:01:00 UTC\n"
            "ExecMainExitTimestamp=Mon 2026-05-25 04:01:30 UTC\n"
            "Result=failed\n"
        )
        with patch("lantana.notify.timing.subprocess.run", return_value=_completed(stdout)):
            timings = collect_step_timings(["lantana-transform"])
        assert timings[0].duration_seconds == 30
        assert timings[0].result == "failed"

    def test_preserves_unit_order(self) -> None:
        """Output order matches input order — the brief's row order is the caller's call."""
        ok = _completed("Result=success\n")
        units = ["lantana-prune", "lantana-enrich", "lantana-transform"]
        with patch("lantana.notify.timing.subprocess.run", return_value=ok):
            timings = collect_step_timings(units)
        assert [t.unit for t in timings] == units

    def test_oneshot_with_empty_active_enter_still_resolves(self) -> None:
        """Regression: oneshot services have empty ActiveEnterTimestamp.

        Discovered 2026-05-25 on op_alpha's lantana-enrich.service: systemd
        does not populate ``ActiveEnterTimestamp`` for short oneshot units
        (they never dwell in the active state). The query must read
        ``ExecMainStartTimestamp`` / ``ExecMainExitTimestamp`` instead.
        This fixture simulates the production shape — ``ActiveEnterTimestamp``
        present but empty, ``ExecMainStart/ExitTimestamp`` populated — and
        asserts the duration is still computed.
        """
        stdout = (
            "ActiveEnterTimestamp=\n"
            "InactiveEnterTimestamp=Mon 2026-05-25 16:32:33 UTC\n"
            "ExecMainStartTimestamp=Mon 2026-05-25 16:31:09 UTC\n"
            "ExecMainExitTimestamp=Mon 2026-05-25 16:32:33 UTC\n"
            "Result=success\n"
        )
        with patch("lantana.notify.timing.subprocess.run", return_value=_completed(stdout)):
            timings = collect_step_timings(["lantana-enrich"])
        t = timings[0]
        assert t.duration_seconds == 84.0  # 16:32:33 - 16:31:09 = 1m 24s
        assert t.result == "success"

    def test_inactive_before_active_returns_none(self) -> None:
        """Defensive: if timestamps are swapped (e.g. unit just started, not yet finished),
        duration should be None rather than negative."""
        stdout = (
            "ExecMainStartTimestamp=Mon 2026-05-25 04:05:00 UTC\n"
            "ExecMainExitTimestamp=Mon 2026-05-25 04:01:00 UTC\n"
            "Result=success\n"
        )
        with patch("lantana.notify.timing.subprocess.run", return_value=_completed(stdout)):
            timings = collect_step_timings(["lantana-enrich"])
        assert timings[0].duration_seconds is None


# ---------------------------------------------------------------------------
# Markdown renderers
# ---------------------------------------------------------------------------


class TestRenderTimingSection:
    def test_renders_table_header_and_rows(self) -> None:
        timings = [
            _st("lantana-prune", 24.6),
            _st("lantana-enrich", 1110.0),
        ]
        out = "\n".join(render_timing_section(timings))
        assert "## Pipeline Timing" in out
        assert "| Step | Duration (min) | Result |" in out
        assert "| prune | 0.4 | success |" in out
        assert "| enrich | 18.5 | success |" in out

    def test_renders_dash_for_missing_duration(self) -> None:
        out = "\n".join(render_timing_section([_st("lantana-prune", None, result="unknown")]))
        assert "| prune | — | unknown |" in out

    def test_empty_list_returns_empty(self) -> None:
        """An empty timing collection skips the section entirely (data-presence rule)."""
        assert render_timing_section([]) == []

    def test_includes_self_time_disclaimer(self) -> None:
        out = "\n".join(render_timing_section([_st("lantana-prune", 10.0)]))
        assert "lantana-report" in out
        assert "previous day" in out


class TestRenderTimingOneLiner:
    def test_renders_per_step_durations(self) -> None:
        timings = [
            _st("lantana-prune", 24.0),
            _st("lantana-enrich", 1110.0),
            _st("lantana-transform", 72.0),
        ]
        line = render_timing_one_liner(timings)
        assert line is not None
        assert "prune 0.4m" in line
        assert "enrich 18.5m" in line
        assert "transform 1.2m" in line

    def test_skips_steps_with_no_duration(self) -> None:
        timings = [
            _st("lantana-prune", None, result="unknown"),
            _st("lantana-enrich", 1110.0),
        ]
        line = render_timing_one_liner(timings)
        assert line is not None
        assert "prune" not in line
        assert "enrich 18.5m" in line

    def test_all_missing_returns_none(self) -> None:
        """When the whole sweep failed (e.g. no systemctl), the embed skips the line."""
        timings = [
            _st("lantana-prune", None, result="unknown"),
            _st("lantana-enrich", None, result="unknown"),
        ]
        assert render_timing_one_liner(timings) is None

    def test_empty_list_returns_none(self) -> None:
        assert render_timing_one_liner([]) is None

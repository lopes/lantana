"""Per-step pipeline duration sourced from systemd unit metadata.

The 06:00 daily brief surfaces how long the prior night's pipeline took at
each step. Source of truth is systemd's own bookkeeping — ``systemctl show
<unit>.service --property=ActiveEnterTimestamp,InactiveEnterTimestamp,Result``
gives us the wall-clock start, finish, and exit result of the most recent
run without requiring any instrumentation inside the runners themselves.

Failure mode: subprocess error, missing timestamps, or parse failure all
return ``StepTiming(duration_seconds=None, result="unknown")`` rather than
raising. The brief section is then omitted by the caller. The "no single
defect cancels more than its scope" rule applies — a broken timing query
must not break the brief.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Final

import structlog

logger = structlog.get_logger()

# systemd renders timestamps as e.g. `Mon 2026-05-25 04:01:13 UTC`. An empty
# value means the service has never run (or was reset).
_TIMESTAMP_FORMAT: Final[str] = "%a %Y-%m-%d %H:%M:%S %Z"
_SYSTEMCTL_TIMEOUT_SECONDS: Final[float] = 10.0


@dataclass(frozen=True)
class StepTiming:
    """One pipeline step's run shape from systemd's most-recent invocation."""

    unit: str
    duration_seconds: float | None
    result: str
    finished_at: datetime | None

    @property
    def duration_minutes(self) -> float | None:
        if self.duration_seconds is None:
            return None
        return self.duration_seconds / 60.0


def _parse_timestamp(raw: str) -> datetime | None:
    """Parse a systemctl timestamp like ``Mon 2026-05-25 04:01:13 UTC``.

    Empty / "n/a" / unparseable inputs return ``None`` — the caller treats
    those as "step has not completed", which collapses to duration=None.
    """
    value = raw.strip()
    if not value or value.lower() in {"n/a", "0"}:
        return None
    try:
        return datetime.strptime(value, _TIMESTAMP_FORMAT)
    except ValueError:
        logger.warning("timing_parse_failed", raw=raw)
        return None


def _parse_show_output(stdout: str) -> dict[str, str]:
    """Convert ``Key=Value`` lines from ``systemctl show`` into a dict."""
    out: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key] = value
    return out


def _query_unit(unit: str) -> StepTiming:
    """Shell out to ``systemctl show`` for one unit; return its StepTiming."""
    full_unit = unit if unit.endswith(".service") else f"{unit}.service"
    try:
        completed = subprocess.run(
            [
                "systemctl",
                "show",
                full_unit,
                "--property=ActiveEnterTimestamp,InactiveEnterTimestamp,Result",
            ],
            capture_output=True,
            text=True,
            timeout=_SYSTEMCTL_TIMEOUT_SECONDS,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        # FileNotFoundError on non-systemd hosts (dev macOS), Timeout if D-Bus
        # is wedged, OSError catches the broader exec-failed class.
        logger.warning(
            "timing_subprocess_failed",
            unit=full_unit,
            error_type=type(exc).__name__,
            error=repr(exc),
        )
        return StepTiming(unit=unit, duration_seconds=None, result="unknown", finished_at=None)

    if completed.returncode != 0:
        logger.warning(
            "timing_systemctl_nonzero",
            unit=full_unit,
            returncode=completed.returncode,
            stderr=completed.stderr.strip()[:200],
        )
        return StepTiming(unit=unit, duration_seconds=None, result="unknown", finished_at=None)

    props = _parse_show_output(completed.stdout)
    started = _parse_timestamp(props.get("ActiveEnterTimestamp", ""))
    finished = _parse_timestamp(props.get("InactiveEnterTimestamp", ""))
    result = props.get("Result", "unknown") or "unknown"

    duration_seconds: float | None = None
    if started is not None and finished is not None and finished >= started:
        duration_seconds = (finished - started).total_seconds()

    return StepTiming(
        unit=unit,
        duration_seconds=duration_seconds,
        result=result,
        finished_at=finished,
    )


def collect_step_timings(units: list[str]) -> list[StepTiming]:
    """Query ``systemctl show`` for each unit and return their StepTimings.

    Order is preserved (caller controls the brief's row order).
    A query failure for one unit does not affect the others — that unit
    surfaces as ``duration_seconds=None, result="unknown"`` and the rest
    proceed normally.
    """
    return [_query_unit(unit) for unit in units]


def render_timing_section(timings: list[StepTiming]) -> list[str]:
    """Markdown ``## Pipeline Timing`` section for the brief attachment.

    Returns an empty list when no timing was collected — the caller appends
    these lines into the running brief, and an empty list means the section
    is silently omitted (the "no single defect cancels more than its scope"
    rule). The lantana-report self-time omission is documented inline.
    """
    if not timings:
        return []
    from lantana.notify.explanations import BRIEF_SECTIONS
    lines: list[str] = ["## Pipeline Timing\n"]
    triplet = BRIEF_SECTIONS.get("Pipeline Timing")
    if triplet is not None:
        lines.append(triplet.italic_one_liner() + "\n")
    lines.append("| Step | Duration (min) | Result |")
    lines.append("|------|----------------|--------|")
    for t in timings:
        # Strip the ``lantana-`` prefix in the rendered table to keep columns
        # narrow; the unit name is documented above and operators recognise
        # ``prune`` / ``enrich`` / ``transform`` at a glance.
        label = t.unit.removeprefix("lantana-")
        duration_cell = "—" if t.duration_minutes is None else f"{t.duration_minutes:.1f}"
        lines.append(f"| {label} | {duration_cell} | {t.result} |")
    lines.append("")
    lines.append(
        "_Note: report runtime is not shown — this section is generated by "
        "lantana-report itself, so its `systemctl show` would return the "
        "previous day's run._"
    )
    lines.append("")
    return lines


def render_timing_one_liner(timings: list[StepTiming]) -> str | None:
    """Compact 1-line timing summary for the Discord embed description.

    Returns ``None`` when every step's duration is unavailable — the embed
    caller skips appending the line. Otherwise renders like
    ``⏱ prune 0.4m · enrich 18.7m · transform 1.2m``.
    """
    parts: list[str] = []
    for t in timings:
        if t.duration_minutes is None:
            continue
        label = t.unit.removeprefix("lantana-")
        parts.append(f"{label} {t.duration_minutes:.1f}m")
    if not parts:
        return None
    return "⏱ " + " · ".join(parts)

"""OPSEC-safe host sensor-egress.log parser for blocked sensor egress attempts.

Reads root-owned ``0644`` ``/var/log/lantana/honeywall/nftables/sensor-egress.log``
(plus ``.1`` and ``.2.gz`` rotated files, falling back to sibling ``firewall.log``
when ``sensor-egress.log`` has not yet been created) strictly in read-only mode
without ever storing or emitting ``SRC=`` (which holds the host WAN IP on
single-node ``OUTPUT`` drops or ``10.50.99.x`` on multi-node ``FORWARD`` drops).

Because Lantana v1.5.1 ships non-egressing Cowrie and Dionaea container images
alongside a 100% dark ``meta skuid stigma`` nftables policy, any non-canary drop
is a high-signal Critical containment alert.
"""

from __future__ import annotations

import gzip
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from datetime import date

DEFAULT_FIREWALL_LOG_PATH: Final[Path] = Path(
    os.environ.get(
        "LANTANA_FIREWALL_LOG",
        "/var/log/lantana/honeywall/nftables/sensor-egress.log",
    )
)

# RFC 5737 TEST-NET-2 canary IP and loopback TCP canary port used by validate-canaries.yml
CANARY_WAN_DST_IPS: Final[frozenset[str]] = frozenset({"198.51.100.250"})
CANARY_LOCAL_DST_IPS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1"})
CANARY_LOCAL_DST_PORTS: Final[frozenset[int]] = frozenset({1})

_MONTH_MAP: Final[dict[str, int]] = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

# Match traditional BSD syslog prefix ("Jul  5 01:00:00" / "Jul 16 03:12:01") OR ISO-8601
_SYSLOG_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<iso_date>\d{4}-\d{2}-\d{2})T|(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+\d{2}:\d{2}:\d{2})"
)
_TAG_RE: Final[re.Pattern[str]] = re.compile(
    r"\[(?P<tag>LANTANA_(?:OUTPUT_DROP_SENSOR_(?:LO|WAN)|FORWARD_DROP_EGRESS))\]\s+(?P<payload>.+)$"
)
_KV_RE: Final[re.Pattern[str]] = re.compile(r"\b([A-Z]+)=([^\s]*)")
_SAFE_PROTO_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9_-]{1,16}$")

# Tail-read window per file so even an unexpectedly large fallback firewall.log
# never blinds recent containment alerts at the end of the file.
_MAX_TAIL_BYTES: Final[int] = 64 * 1024 * 1024


@dataclass(frozen=True)
class SensorEgressSummary:
    """Aggregated sensor egress drop counts for one or more UTC dates (zero WAN-IP data)."""

    wan_drops: int = 0
    local_drops: int = 0
    canary_drops: int = 0
    top_targets: dict[tuple[str, int | None], int] = field(default_factory=dict)

    @property
    def total_violations(self) -> int:
        return self.wan_drops + self.local_drops


def _line_matches_dates(line: str, target_dates: frozenset[date]) -> bool:
    match = _SYSLOG_PREFIX_RE.match(line)
    if match is None:
        return False
    iso_date = match.group("iso_date")
    if iso_date is not None:
        return any(iso_date == d.isoformat() for d in target_dates)
    mon_num = _MONTH_MAP.get(match.group("mon") or "")
    day_str = match.group("day")
    if mon_num is None or day_str is None:
        return False
    day_num = int(day_str)
    return any(mon_num == d.month and day_num == d.day for d in target_dates)


def _candidate_log_files(firewall_log_path: Path) -> list[Path]:
    """Return existing non-symlink primary, .1, and .2.gz rotated log files.

    When using the default ``sensor-egress.log`` path on a host upgraded from
    v1.5.0 that only has ``firewall.log``, fall back to sibling ``firewall.log``
    so single-node hosts never falsely show as remote collectors.
    """
    base = firewall_log_path
    if not base.exists() and base == DEFAULT_FIREWALL_LOG_PATH:
        fallback = base.with_name("firewall.log")
        if fallback.is_file() and not fallback.is_symlink():
            base = fallback

    candidates: list[Path] = []
    for path in (
        base,
        base.with_name(f"{base.name}.1"),
        base.with_name(f"{base.name}.2.gz"),
    ):
        try:
            if path.is_file() and not path.is_symlink():
                candidates.append(path)
        except OSError:
            continue
    return candidates


def _iter_log_lines(path: Path) -> Iterable[str]:
    """Yield decoded lines from a plain or gzipped log file, tail-seeking huge files."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as gz_fh:
            bytes_read = 0
            for line in gz_fh:
                bytes_read += len(line)
                if bytes_read > _MAX_TAIL_BYTES:
                    break
                yield line
        return

    with path.open("rb") as bin_fh:
        bin_fh.seek(0, os.SEEK_END)
        size = bin_fh.tell()
        if size > _MAX_TAIL_BYTES:
            bin_fh.seek(size - _MAX_TAIL_BYTES)
            # Discard partial first line after seeking mid-file
            bin_fh.readline()
        else:
            bin_fh.seek(0)
        for raw in bin_fh:
            yield raw.decode("utf-8", errors="replace")


def _sanitize_proto(raw_proto: str) -> str:
    candidate = raw_proto.strip().lower()
    if _SAFE_PROTO_RE.match(candidate):
        return candidate
    return "unknown"


def collect_sensor_egress_summary(
    target_date: date,
    *,
    firewall_log_path: Path = DEFAULT_FIREWALL_LOG_PATH,
    extra_dates: Sequence[date] | None = None,
) -> SensorEgressSummary | None:
    """Scan local sensor egress logs for blocked sensor egress on ``target_date``.

    Returns ``None`` when no local firewall/egress log exists (e.g. dedicated
    multi-node collector host). Never returns ``SRC=`` values or raw syslog lines.
    """
    files = _candidate_log_files(firewall_log_path)
    if not files:
        return None

    target_dates = frozenset({target_date, *(extra_dates or ())})
    wan_drops = 0
    local_drops = 0
    canary_drops = 0
    targets: Counter[tuple[str, int | None]] = Counter()

    for path in files:
        try:
            for line in _iter_log_lines(path):
                if "[LANTANA_" not in line:
                    continue
                tag_match = _TAG_RE.search(line)
                if tag_match is None:
                    continue
                if not _line_matches_dates(line, target_dates):
                    continue

                tag = tag_match.group("tag")
                payload = tag_match.group("payload")
                kv = dict(_KV_RE.findall(payload))
                dst_ip = kv.get("DST", "")
                proto = _sanitize_proto(kv.get("PROTO", ""))
                dpt_raw = kv.get("DPT", "")
                dst_port: int | None
                try:
                    dst_port = int(dpt_raw) if dpt_raw else None
                except ValueError:
                    dst_port = None

                if tag == "LANTANA_OUTPUT_DROP_SENSOR_LO":
                    if (
                        dst_ip in CANARY_LOCAL_DST_IPS
                        and proto == "tcp"
                        and dst_port in CANARY_LOCAL_DST_PORTS
                    ):
                        canary_drops += 1
                    else:
                        local_drops += 1
                        targets[(proto, dst_port)] += 1
                else:
                    # LANTANA_OUTPUT_DROP_SENSOR_WAN or LANTANA_FORWARD_DROP_EGRESS
                    if dst_ip in CANARY_WAN_DST_IPS:
                        canary_drops += 1
                    else:
                        wan_drops += 1
                        targets[(proto, dst_port)] += 1
        except OSError:
            continue

    top_targets = dict(targets.most_common(10))
    return SensorEgressSummary(
        wan_drops=wan_drops,
        local_drops=local_drops,
        canary_drops=canary_drops,
        top_targets=top_targets,
    )


def evaluate_sensor_egress_alerts(
    target_date: date,
    summary: SensorEgressSummary | None,
) -> list[dict[str, Any]]:
    """Return a Critical synthetic alert row when any non-canary sensor egress was blocked."""
    if summary is None or summary.total_violations == 0:
        return []

    target_parts: list[str] = []
    for (proto, port), count in list(summary.top_targets.items())[:5]:
        label = f"{proto}/{port}" if port is not None else proto
        target_parts.append(f"{label} (x{count})")
    targets_clause = f"; top targets: {', '.join(target_parts)}" if target_parts else ""

    return [
        {
            "date": target_date.isoformat(),
            "provider": "firewall",
            "error_type": "sensor_egress_blocked",
            "count": summary.total_violations,
            "message": (
                f"Blocked {summary.total_violations} unsolicited sensor egress attempt(s): "
                f"{summary.wan_drops} WAN, {summary.local_drops} local/loopback{targets_clause}."
            ),
        }
    ]

"""Read-only operator health collector for the Vigil ``/health`` view.

Surfaces:
- 3rd-party API integration configuration (boolean/mode only — zero secret values)
  and last-run status (OK / Warning (Rate Limit) / Error / Not Configured).
- Pipeline systemd unit last run results and durations.
- Stateless dead-man's-switch dataset liveness (Bronze & Silver freshness).
- Live non-root usable filesystem usage (``os.statvfs``) and per-tier datalake
  storage footprint (Bronze, Silver, Gold, SQLite enrichment cache, errors log).
- Recent pipeline & provider error messages from ``enrichment_errors.json``.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lantana.common.config import (
    DEFAULT_SECRETS_PATH,
    SecretsConfig,
    load_secrets,
)
from lantana.common.datalake import (
    GOLD_ROOT,
    SILVER_ROOT,
    read_gold_table,
)
from lantana.notify.alerts import (
    CRITICAL_ERROR_TYPES,
    INFO_ERROR_TYPES,
    ErrorBuckets,
    categorize_errors,
    evaluate_liveness_alerts,
    load_errors_for_date,
)
from lantana.notify.timing import StepTiming, collect_step_timings
from lantana.prune import (
    BRONZE_RETENTION_DAYS,
    DEFAULT_LAKE_DIR,
    DISK_CRITICAL_THRESHOLD,
    DISK_WARNING_THRESHOLD,
    SILVER_GOLD_RETENTION_DAYS,
    check_disk_usage,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from lantana.common.config import ReportingConfig

DEFAULT_GEOIP_DIR = Path("/var/lib/lantana/collector/geoip")
_PIPELINE_UNITS: tuple[tuple[str, str], ...] = (
    ("lantana-prune", "00:15 UTC"),
    ("lantana-enrich", "01:00 UTC"),
    ("lantana-transform", "05:30 UTC"),
    ("lantana-report", "06:00 UTC"),
)
_PROVIDER_COOLDOWN_DAYS: dict[str, int] = {
    "greynoise": 6,
    "shodan": 28,
}
_MAX_WALK_DEPTH = 12


@dataclass(frozen=True)
class IntegrationHealth:
    """Configuration & latest-run health for one external 3rd-party integration."""

    name: str
    key_id: str
    role: str
    config_mode: str  # "Configured", "Configured (GTI)", "Anonymous (Free)", "Not Configured"
    status: str  # "OK", "Warning (Rate Limit)", "Error", "Not Configured", "Cooldown"
    last_message: str
    cache_entries: int | None = None
    last_rate_limited: str | None = None


@dataclass(frozen=True)
class DiskHealth:
    """Live non-root usable filesystem stats via ``os.statvfs``."""

    usage_pct: float
    used_bytes: int
    free_bytes: int
    total_usable_bytes: int
    status: str  # "OK", "Warning", "Critical"


@dataclass(frozen=True)
class StorageTierStats:
    """Size and item count for one datalake storage tier."""

    tier: str
    retention: str
    files: int
    size_bytes: int


@dataclass(frozen=True)
class DatasetLiveness:
    """Bronze/Silver freshness and liveness status for one expected dataset."""

    dataset: str
    latest_bronze: str
    latest_silver: str
    silver_size_bytes: int
    status: str  # "Active", "Silent (1d)", "Silent (2+d)", "No Data"


@dataclass(frozen=True)
class UnitHealth:
    """Last-run status and timing for one scheduled pipeline systemd unit."""

    step: str
    unit: str
    schedule: str
    status: str  # "OK", "Error", "Unknown"
    raw_result: str
    duration_display: str
    finished_at_display: str


@dataclass(frozen=True)
class HealthSnapshot:
    """Complete read-only operator health snapshot for ``/health``."""

    overall_status: str  # "Healthy", "Degraded", "Critical"
    overall_tone: str  # "low", "med", "high"
    target_date: date | None
    secrets_loaded: bool
    disk: DiskHealth | None
    integrations: list[IntegrationHealth]
    units: list[UnitHealth]
    datasets: list[DatasetLiveness]
    storage_tiers: list[StorageTierStats]
    cache_active_entries: int
    cache_size_bytes: int
    buckets: ErrorBuckets
    recent_messages: list[dict[str, object]]


def format_bytes(num_bytes: int) -> str:
    """Format byte counts into concise human-readable units."""
    val = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0 or unit == "TB":
            return f"{val:.1f} {unit}" if unit != "B" else f"{int(val)} B"
        val /= 1024.0
    return f"{num_bytes} B"


def _scan_dir_footprint(root: Path) -> tuple[int, int]:
    """Return ``(file_count, total_bytes)`` without following symlinks (bounded depth)."""
    if not root.exists() or root.is_symlink() or not root.is_dir():
        return (0, 0)
    files = 0
    total_bytes = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            continue
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_file(follow_symlinks=False):
                            files += 1
                            total_bytes += entry.stat(follow_symlinks=False).st_size
                        elif entry.is_dir(follow_symlinks=False) and depth < _MAX_WALK_DEPTH:
                            stack.append((Path(entry.path), depth + 1))
                    except OSError:
                        continue
        except OSError:
            continue
    return (files, total_bytes)


def _read_disk_health(path: Path) -> DiskHealth | None:
    """Read live non-root usable disk metrics via ``os.statvfs``."""
    probe = path
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    if not probe.exists():
        return None
    try:
        pct = check_disk_usage(probe)
        st = os.statvfs(probe)
    except OSError:
        return None
    block_size = st.f_frsize or st.f_bsize
    used_blocks = max(0, st.f_blocks - st.f_bfree)
    avail_blocks = max(0, st.f_bavail)
    total_usable = (used_blocks + avail_blocks) * block_size
    used_bytes = used_blocks * block_size
    free_bytes = avail_blocks * block_size
    if pct > DISK_CRITICAL_THRESHOLD:
        status = "Critical"
    elif pct > DISK_WARNING_THRESHOLD:
        status = "Warning"
    else:
        status = "OK"
    return DiskHealth(
        usage_pct=pct,
        used_bytes=used_bytes,
        free_bytes=free_bytes,
        total_usable_bytes=total_usable,
        status=status,
    )


def _read_cache_counts(cache_path: Path) -> tuple[int, dict[str, int], int]:
    """Read active SQLite cache entry counts strictly in read-only mode."""
    if not cache_path.is_file() or cache_path.is_symlink():
        return (0, {}, 0)
    try:
        size_bytes = cache_path.stat().st_size
    except OSError:
        size_bytes = 0
    conn: sqlite3.Connection | None = None
    by_provider: dict[str, int] = {}
    total = 0
    try:
        conn = sqlite3.connect(f"file:{cache_path}?mode=ro", uri=True, timeout=2.0)
        now_iso = datetime.now(tz=UTC).isoformat()
        rows = conn.execute(
            "SELECT provider, COUNT(*) FROM cache "
            "WHERE expires_at IS NULL OR expires_at > ? "
            "GROUP BY provider",
            (now_iso,),
        ).fetchall()
        for prov, cnt in rows:
            c = int(cnt)
            by_provider[str(prov)] = c
            total += c
    except sqlite3.Error:
        return (0, {}, size_bytes)
    finally:
        if conn is not None:
            conn.close()
    return (total, by_provider, size_bytes)


def _read_provider_state(state_path: Path) -> dict[str, dict[str, str]]:
    if not state_path.is_file() or state_path.is_symlink():
        return {}
    try:
        raw: object = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for k, v in raw.items():
        if isinstance(k, str) and isinstance(v, dict):
            out[k] = {str(ek): str(ev) for ek, ev in v.items() if isinstance(ev, str)}
    return out


def _load_recent_errors(
    errors_path: Path,
    *,
    dates: list[date],
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Load recent NDJSON rows from ``enrichment_errors.json`` (window-scoped or latest)."""
    if not errors_path.is_file() or errors_path.is_symlink():
        return []
    date_set = {d.isoformat() for d in dates}
    all_rows: list[dict[str, Any]] = []
    try:
        with errors_path.open(encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    all_rows.append(entry)
    except OSError:
        return []

    filtered = [r for r in all_rows if r.get("date") in date_set] if date_set else all_rows
    if not filtered and all_rows:
        # Fall back to the most recent error entries so operators still see failures on empty days.
        filtered = all_rows[-limit:]
    filtered.sort(key=lambda r: str(r.get("date") or ""), reverse=True)
    return filtered[:limit]


def _classify_severity(error_type: str) -> str:
    if error_type in CRITICAL_ERROR_TYPES:
        return "Critical"
    if error_type in INFO_ERROR_TYPES:
        return "Info"
    return "Warning"


def _is_in_cooldown(provider: str, last_rl: str | None, ref_date: date) -> bool:
    window_days = _PROVIDER_COOLDOWN_DAYS.get(provider)
    if window_days is None or not last_rl:
        return False
    try:
        last_dt = date.fromisoformat(last_rl)
    except ValueError:
        return False
    return (ref_date - last_dt).days < window_days


def _latest_partition_date(base_dir: Path, dataset: str) -> tuple[date | None, int]:
    """Return ``(latest_date, size_bytes)`` for ``base_dir/dataset=<ds>/date=YYYY-MM-DD``."""
    ds_dir = base_dir / f"dataset={dataset}"
    if not ds_dir.is_dir() or ds_dir.is_symlink():
        return (None, 0)
    best_date: date | None = None
    best_dir: Path | None = None
    for child in ds_dir.glob("date=*"):
        if not child.is_dir() or child.is_symlink():
            continue
        try:
            d = date.fromisoformat(child.name[5:])
        except ValueError:
            continue
        if best_date is None or d > best_date:
            best_date = d
            best_dir = child
    if best_date is None or best_dir is None:
        return (None, 0)
    _, total_bytes = _scan_dir_footprint(best_dir)
    return (best_date, total_bytes)


def _evaluate_provider_status(
    *,
    key_id: str,
    configured: bool,
    latest_errors: list[dict[str, Any]],
    last_rl: str | None,
    ref_date: date,
) -> tuple[str, str]:
    """Derive ``(status_badge, last_message)`` for one enrichment provider."""
    if not configured:
        return ("Not Configured", "API key not set in secrets.json — skipped cleanly.")

    prov_errors = [r for r in latest_errors if str(r.get("provider") or "").lower() == key_id]
    non_routine = [r for r in prov_errors if str(r.get("error_type") or "") not in INFO_ERROR_TYPES]
    rate_limits = [r for r in prov_errors if str(r.get("error_type") or "") == "rate_limit"]

    if non_routine:
        first = non_routine[-1]
        etype = str(first.get("error_type") or "error")
        msg = str(first.get("message") or "").strip()
        count = sum(int(r.get("count", 1)) for r in non_routine)
        detail = f"{etype} (x{count})" + (f" — {msg}" if msg else "")
        return ("Error", detail)

    if rate_limits:
        count = sum(int(r.get("count", 1)) for r in rate_limits)
        return (
            "Warning (Rate Limit)",
            f"rate_limit (x{count}) on {ref_date.isoformat()} — circuit breaker tripped.",
        )

    if _is_in_cooldown(key_id, last_rl, ref_date):
        days = _PROVIDER_COOLDOWN_DAYS[key_id]
        return (
            "Warning (Rate Limit)",
            f"In {days}d cooldown skip-window (last 429 on {last_rl}).",
        )

    return ("OK", "No errors recorded on latest run.")


def _build_integrations(
    secrets: SecretsConfig | None,
    latest_errors: list[dict[str, Any]],
    provider_state: dict[str, dict[str, str]],
    cache_by_provider: dict[str, int],
    *,
    geoip_dir: Path,
    ref_date: date,
) -> list[IntegrationHealth]:
    """Build status rows for all 6 third-party integrations without touching secret values."""
    integrations: list[IntegrationHealth] = []

    def _has_str(val: str | None) -> bool:
        return bool(val and val.strip())

    # 1. AbuseIPDB
    abuse_cfg = secrets is not None and _has_str(secrets.abuseipdb)
    abuse_rl = provider_state.get("abuseipdb", {}).get("last_rate_limited")
    abuse_status, abuse_msg = _evaluate_provider_status(
        key_id="abuseipdb",
        configured=abuse_cfg,
        latest_errors=latest_errors,
        last_rl=abuse_rl,
        ref_date=ref_date,
    )
    integrations.append(
        IntegrationHealth(
            name="AbuseIPDB",
            key_id="abuseipdb",
            role="IP abuse confidence & community reports (1,000/day free)",
            config_mode="Configured" if abuse_cfg else "Not Configured",
            status=abuse_status,
            last_message=abuse_msg,
            cache_entries=cache_by_provider.get("abuseipdb", 0),
            last_rate_limited=abuse_rl,
        )
    )

    # 2. VirusTotal / GTI
    vt_gti = bool(
        secrets is not None
        and secrets.gti_enabled
        and (_has_str(secrets.gti) or _has_str(secrets.virustotal))
    )
    vt_free = bool(secrets is not None and not vt_gti and _has_str(secrets.virustotal))
    vt_cfg = vt_gti or vt_free
    vt_mode = (
        "Configured (GTI)" if vt_gti else ("Configured (Free)" if vt_free else "Not Configured")
    )
    vt_rl = provider_state.get("virustotal", {}).get("last_rate_limited")
    vt_status, vt_msg = _evaluate_provider_status(
        key_id="virustotal",
        configured=vt_cfg,
        latest_errors=latest_errors,
        last_rl=vt_rl,
        ref_date=ref_date,
    )
    integrations.append(
        IntegrationHealth(
            name="VirusTotal / GTI",
            key_id="virustotal",
            role="Malware hashes (vhash), C2 IPs, stager URLs/domains, inbound IPs",
            config_mode=vt_mode,
            status=vt_status,
            last_message=vt_msg,
            cache_entries=cache_by_provider.get("virustotal", 0),
            last_rate_limited=vt_rl,
        )
    )

    # 3. Shodan
    shodan_cfg = secrets is not None and _has_str(secrets.shodan)
    shodan_rl = provider_state.get("shodan", {}).get("last_rate_limited")
    shodan_status, shodan_msg = _evaluate_provider_status(
        key_id="shodan",
        configured=shodan_cfg,
        latest_errors=latest_errors,
        last_rl=shodan_rl,
        ref_date=ref_date,
    )
    integrations.append(
        IntegrationHealth(
            name="Shodan",
            key_id="shodan",
            role="Open ports, banners, CVEs, hosting org (100/mo free, 28d cooldown)",
            config_mode="Configured" if shodan_cfg else "Not Configured",
            status=shodan_status,
            last_message=shodan_msg,
            cache_entries=cache_by_provider.get("shodan", 0),
            last_rate_limited=shodan_rl,
        )
    )

    # 4. GreyNoise Community
    gn_keyed = bool(secrets is not None and _has_str(secrets.greynoise))
    gn_anon = bool(secrets is not None and secrets.greynoise is not None and not gn_keyed)
    gn_active = gn_keyed or gn_anon
    gn_mode = (
        "Configured (Keyed)" if gn_keyed else ("Anonymous (Free)" if gn_anon else "Not Configured")
    )
    gn_rl = provider_state.get("greynoise", {}).get("last_rate_limited")
    gn_status, gn_msg = _evaluate_provider_status(
        key_id="greynoise",
        configured=gn_active,
        latest_errors=latest_errors,
        last_rl=gn_rl,
        ref_date=ref_date,
    )
    integrations.append(
        IntegrationHealth(
            name="GreyNoise Community",
            key_id="greynoise",
            role="RIOT / benign scanner brake & actor labels (50/wk free, 6d cooldown)",
            config_mode=gn_mode,
            status=gn_status,
            last_message=gn_msg,
            cache_entries=cache_by_provider.get("greynoise", 0),
            last_rate_limited=gn_rl,
        )
    )

    # 5. MaxMind GeoLite2 (Vector ingestion-time MMDBs)
    mm_cfg = secrets is not None and _has_str(secrets.maxmind)
    city_db = geoip_dir / "GeoLite2-City.mmdb"
    asn_db = geoip_dir / "GeoLite2-ASN.mmdb"
    has_city = city_db.is_file()
    has_asn = asn_db.is_file()
    if has_city and has_asn:
        try:
            mtime = datetime.fromtimestamp(city_db.stat().st_mtime, tz=UTC).strftime("%Y-%m-%d")
        except OSError:
            mtime = "present"
        mm_status = "OK"
        mm_msg = f"GeoLite2-City & GeoLite2-ASN MMDBs present (updated {mtime})."
        mm_mode = "Configured" if mm_cfg else "Local MMDBs"
    elif mm_cfg:
        missing = [
            name
            for name, ok in (("GeoLite2-City.mmdb", has_city), ("GeoLite2-ASN.mmdb", has_asn))
            if not ok
        ]
        mm_status = "Error"
        mm_msg = f"License key set, but missing on disk: {', '.join(missing)}."
        mm_mode = "Configured"
    else:
        mm_status = "Not Configured"
        mm_msg = "vault_apikey_maxmind unset — Geography map, countries, and ASNs stay empty."
        mm_mode = "Not Configured"
    integrations.append(
        IntegrationHealth(
            name="MaxMind GeoLite2",
            key_id="maxmind",
            role="Vector ingestion-time City/LatLon & ASN enrichment (/geography)",
            config_mode=mm_mode,
            status=mm_status,
            last_message=mm_msg,
        )
    )

    # 6. Discord Webhook
    dc_cfg = secrets is not None and _has_str(secrets.discord_webhook)
    integrations.append(
        IntegrationHealth(
            name="Discord Webhook",
            key_id="discord",
            role="06:00 UTC Daily Brief & critical health alerting",
            config_mode="Configured" if dc_cfg else "Not Configured",
            status="OK" if dc_cfg else "Not Configured",
            last_message=(
                "Webhook configured for daily brief & critical alerts."
                if dc_cfg
                else "vault_webhook_discord unset — lantana-report logs locally only."
            ),
        )
    )

    return integrations


def collect_health_snapshot(
    *,
    dates: list[date],
    reporting: ReportingConfig,
    gold_root: Path = GOLD_ROOT,
    silver_root: Path = SILVER_ROOT,
    datalake_root: Path | None = None,
    secrets_path: Path | None = None,
    geoip_dir: Path | None = None,
    collect_timings_fn: Callable[[list[str]], list[StepTiming]] = collect_step_timings,
) -> HealthSnapshot:
    """Gather a read-only operator health snapshot without leaking secrets."""
    resolved_lake = (
        datalake_root
        if datalake_root is not None
        else (gold_root.parent if gold_root != GOLD_ROOT else DEFAULT_LAKE_DIR)
    )
    resolved_secrets = secrets_path if secrets_path is not None else DEFAULT_SECRETS_PATH
    resolved_geoip = geoip_dir if geoip_dir is not None else DEFAULT_GEOIP_DIR

    secrets: SecretsConfig | None = None
    secrets_loaded = False
    if resolved_secrets.is_file():
        try:
            secrets = load_secrets(resolved_secrets)
            secrets_loaded = True
        except Exception:
            secrets = None
            secrets_loaded = False

    target_date = dates[-1] if dates else None
    ref_date = target_date or datetime.now(tz=UTC).date()

    errors_path = resolved_lake / "enrichment_errors.json"
    state_path = resolved_lake / ".provider_state.json"
    cache_path = resolved_lake / ".enrichment_cache.db"

    latest_errors = load_errors_for_date(errors_path, ref_date)
    recent_raw = _load_recent_errors(errors_path, dates=dates, limit=100)
    provider_state = _read_provider_state(state_path)
    cache_total, cache_by_provider, cache_size = _read_cache_counts(cache_path)
    disk = _read_disk_health(resolved_lake)

    timings = collect_timings_fn([u for u, _ in _PIPELINE_UNITS])
    units: list[UnitHealth] = []
    for (unit_name, sched), t in zip(_PIPELINE_UNITS, timings, strict=True):
        if t.result == "success":
            u_status = "OK"
        elif t.result in ("", "unknown"):
            u_status = "Unknown"
        else:
            u_status = "Error"
        dur = (
            "—"
            if t.duration_seconds is None
            else (
                f"{t.duration_seconds:.1f}s"
                if t.duration_seconds < 60.0
                else f"{t.duration_seconds / 60.0:.1f}m"
            )
        )
        fin = t.finished_at.strftime("%Y-%m-%d %H:%M UTC") if t.finished_at is not None else "—"
        units.append(
            UnitHealth(
                step=unit_name.removeprefix("lantana-"),
                unit=f"{unit_name}.service",
                schedule=sched,
                status=u_status,
                raw_result=t.result,
                duration_display=dur,
                finished_at_display=fin,
            )
        )

    # Dead-man's-switch liveness across expected datasets
    expected_datasets = list(reporting.operation.expected_datasets)
    bronze_root = resolved_lake / "bronze"
    datasets: list[DatasetLiveness] = []
    for ds in expected_datasets:
        b_date, _ = _latest_partition_date(bronze_root, ds)
        s_date, s_bytes = _latest_partition_date(silver_root, ds)
        if s_date is None and b_date is None:
            ds_status = "No Data"
        elif target_date is not None and s_date == target_date and s_bytes > 0:
            ds_status = "Active"
        elif s_date is not None and (ref_date - s_date) <= timedelta(days=1):
            ds_status = (
                "Silent (1d)" if target_date is not None and s_date < target_date else "Active"
            )
        elif s_date is not None:
            ds_status = "Silent (2+d)"
        else:
            ds_status = "No Data"
        datasets.append(
            DatasetLiveness(
                dataset=ds,
                latest_bronze=b_date.isoformat() if b_date else "—",
                latest_silver=s_date.isoformat() if s_date else "—",
                silver_size_bytes=s_bytes,
                status=ds_status,
            )
        )

    # Combine enrichment errors + stateless liveness alerts (same engine as Daily Brief)
    summary_df = (
        read_gold_table("daily_summary", target_date, gold_root=gold_root)
        if target_date is not None
        else read_gold_table("daily_summary", ref_date, gold_root=gold_root)
    )
    liveness_alerts = (
        evaluate_liveness_alerts(
            target_date=target_date,
            summary=summary_df,
            expected_datasets=expected_datasets,
            silver_root=silver_root,
            timings=timings,
            disk_usage_pct=disk.usage_pct if disk is not None else None,
        )
        if target_date is not None
        else []
    )
    buckets = categorize_errors(latest_errors + liveness_alerts)

    integrations = _build_integrations(
        secrets,
        latest_errors,
        provider_state,
        cache_by_provider,
        geoip_dir=resolved_geoip,
        ref_date=ref_date,
    )

    # Storage breakdown per datalake tier
    bronze_files, bronze_bytes = _scan_dir_footprint(bronze_root)
    silver_files, silver_bytes = _scan_dir_footprint(silver_root)
    gold_files, gold_bytes = _scan_dir_footprint(gold_root)
    err_bytes = errors_path.stat().st_size if errors_path.is_file() else 0
    storage_tiers = [
        StorageTierStats(
            tier="Bronze (NDJSON)",
            retention=f"{BRONZE_RETENTION_DAYS}d (verified Silver gate)",
            files=bronze_files,
            size_bytes=bronze_bytes,
        ),
        StorageTierStats(
            tier="Silver (OCSF Parquet)",
            retention=f"{SILVER_GOLD_RETENTION_DAYS}d",
            files=silver_files,
            size_bytes=silver_bytes,
        ),
        StorageTierStats(
            tier="Gold (Analytics Parquet)",
            retention=f"{SILVER_GOLD_RETENTION_DAYS}d",
            files=gold_files,
            size_bytes=gold_bytes,
        ),
        StorageTierStats(
            tier="Enrichment Cache (SQLite)",
            retention="Tiered TTL (7d / 60d / 90d / 180d)",
            files=1 if cache_path.is_file() else 0,
            size_bytes=cache_size,
        ),
        StorageTierStats(
            tier="Errors Log (NDJSON)",
            retention=f"{SILVER_GOLD_RETENTION_DAYS}d",
            files=1 if errors_path.is_file() else 0,
            size_bytes=err_bytes,
        ),
    ]

    # Recent messages table rows (window errors + active liveness alerts)
    recent_messages: list[dict[str, object]] = []
    for row in liveness_alerts + recent_raw:
        etype = str(row.get("error_type") or "unknown")
        recent_messages.append(
            {
                "date": str(row.get("date") or "—"),
                "severity": _classify_severity(etype),
                "provider": str(row.get("provider") or "—"),
                "error_type": etype,
                "count": int(row.get("count") or 1),
                "message": str(row.get("message") or "—"),
            }
        )

    # Overall status roll-up
    has_provider_error = any(i.status == "Error" for i in integrations)
    has_provider_warn = any(i.status == "Warning (Rate Limit)" for i in integrations)
    disk_crit = disk is not None and disk.status == "Critical"
    disk_warn = disk is not None and disk.status == "Warning"
    if buckets.has_critical or disk_crit:
        overall_status, overall_tone = "Critical", "high"
    elif buckets.has_warning or has_provider_error or has_provider_warn or disk_warn:
        overall_status, overall_tone = "Degraded", "med"
    else:
        overall_status, overall_tone = "Healthy", "low"

    return HealthSnapshot(
        overall_status=overall_status,
        overall_tone=overall_tone,
        target_date=target_date,
        secrets_loaded=secrets_loaded,
        disk=disk,
        integrations=integrations,
        units=units,
        datasets=datasets,
        storage_tiers=storage_tiers,
        cache_active_entries=cache_total,
        cache_size_bytes=cache_size,
        buckets=buckets,
        recent_messages=recent_messages,
    )

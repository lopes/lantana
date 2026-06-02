"""Main enrichment orchestrator — IOC-first.

Daily workflow:
1. Load every dataset's bronze NDJSON for the target date.
2. Extract IOCs globally across datasets (IPs from all four datasets,
   SHA256 hashes from cowrie file_download events plus a defensive
   disk scan).
3. OPSEC-filter IPs against the operation's infrastructure ranges.
4. For each (provider, ioc_type) pair, fulfil each IOC cache-first;
   freshly-queried results land in the cache so subsequent runs
   short-circuit the HTTP call.
5. Per dataset: merge enrichments by `src_ip` (and by `shasum` for
   cowrie), OCSF-normalize, redact infrastructure IPs, write silver
   Parquet.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import polars as pl
import structlog

from lantana.common.config import load_reporting, load_secrets
from lantana.common.datalake import read_bronze_ndjson, write_silver_partition
from lantana.common.redact import (
    RedactionConfig,
    drop_infrastructure_source_rows,
    redact_infrastructure_ips,
    validate_no_leaks,
)
from lantana.enrichment.ioc import (
    extract_hashes_from_bronze,
    extract_hashes_from_disk,
    extract_ips,
    filter_internal_ips,
)
from lantana.enrichment.providers.abuseipdb import AbuseIPDBProvider
from lantana.enrichment.providers.base import EnrichmentError, EnrichmentResult
from lantana.enrichment.providers.greynoise import GreyNoiseProvider
from lantana.enrichment.providers.shodan import ShodanProvider
from lantana.enrichment.providers.virustotal import VirusTotalProvider
from lantana.models.normalize import normalize_dataset

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = structlog.get_logger()

CACHE_DB_PATH = Path("/var/lib/lantana/datalake/.enrichment_cache.db")

# Tiered cache TTLs by classification and ioc_type. Malicious-tier values
# match OpenCTI's default decay-rule durations (IPv4 60d, domain 90d,
# file hash 180d). The benign tier stays short so noise / unclassified
# IOCs are re-checked frequently. Classification is per-row, derived
# from the provider's own risk_score field (see _classify_ttl).
CACHE_TTL_BENIGN_DAYS = 7
CACHE_TTL_MALICIOUS_IP_DAYS = 60
CACHE_TTL_MALICIOUS_DOMAIN_DAYS = 90
CACHE_TTL_MALICIOUS_HASH_DAYS = 180
RISK_SCORE_MALICIOUS_THRESHOLD = 50.0

ERRORS_PATH = Path(
    os.environ.get("LANTANA_ENRICHMENT_ERRORS", "/var/lib/lantana/datalake/enrichment_errors.json")
)
PROVIDER_STATE_PATH = Path("/var/lib/lantana/datalake/.provider_state.json")

DATASETS = ["cowrie", "suricata", "nftables", "dionaea"]

IOC_TYPE_IP = "ip"
IOC_TYPE_HASH = "hash"
IOC_TYPE_DOMAIN = "domain"  # placeholder; no provider enriches domains yet


# Per-provider IP-selection policy. Two knobs:
#
#   * subsample_top_n: when set, pass only the N highest-event-count IPs to
#     this provider instead of the full sorted unique-IP list. Used for tiny
#     free-tier quotas where calling every IP is impossible (GreyNoise's
#     50/week makes ~1100 daily IPs unreachable; without subsampling, the
#     scarce budget burns on lowest-numbered IPs alphabetically).
#
#   * skip_window_days: when set, if the previous run hit a rate_limit
#     error for this provider AND fewer than N days have passed since,
#     skip the provider entirely (no HTTP calls). Avoids burning quota
#     on a provider whose window hasn't refreshed yet. Pairs with the
#     ``.provider_state.json`` file to persist trip dates across runs.
#
# Providers absent from this map (abuseipdb, virustotal) use the default
# behaviour: full sorted IP list, no cross-run skipping. Their quota
# windows are short enough (daily / per-minute) that skipping isn't
# useful — the next day's run gets a fresh allowance.
_PROVIDER_POLICY: dict[str, dict[str, int]] = {
    # 50/week → 40 IPs gives a 10-IP safety margin. 6-day skip leaves 1
    # day for the quota to definitely refresh before the next attempt.
    "greynoise": {"subsample_top_n": 40, "skip_window_days": 6},
    # 100/month → cache holds the long tail. Skip if exhausted; the
    # 28-day window leaves a 2-day margin under the rolling 30-day cap.
    "shodan": {"skip_window_days": 28},
}

# Circuit-breaker thresholds for _enrich_iocs_with_provider.
#
# Two complementary counters guard against burning wall-clock against a
# provider whose quota has reset hours from now:
#
#   * RATE_LIMIT_THRESHOLD (consecutive): trips when N 429s arrive in a row
#     with no successful response between them. Fast path for fully-
#     exhausted providers with a sparse-or-empty cache — the very first IPs
#     trip it, the remaining queue is skipped.
#   * RATE_LIMIT_CUMULATIVE_THRESHOLD: trips on the total count of 429s
#     across the whole loop, even if interleaved cache hits keep resetting
#     the consecutive counter. Without this, a provider whose cache holds
#     ~25% of the day's IPs (Shodan post-multi-day-accumulation) processes
#     the entire queue because every 4-5 misses hit one cache entry — the
#     consecutive counter never reaches 5. Defect #11, observed on the
#     2026-05-21 12:10 re-run for date=2026-05-20.
#
# Auth failures don't fix themselves mid-run either — one is enough.
CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD = 5
CIRCUIT_BREAKER_RATE_LIMIT_CUMULATIVE_THRESHOLD = 30
CIRCUIT_BREAKER_AUTH_FAILED_THRESHOLD = 1


# -- Cache -------------------------------------------------------------------


# Per-provider risk_score field names in EnrichmentResult.data. Probed
# in order — first hit wins. VirusTotal lists two entries because IP
# and file results share the same provider key but expose distinct
# fields (`virustotal_risk_score` on IPs, `vt_file_risk_score` on hashes).
_RISK_SCORE_FIELDS: dict[str, tuple[str, ...]] = {
    "abuseipdb": ("abuseipdb_risk_score",),
    "virustotal": ("virustotal_risk_score", "vt_file_risk_score"),
    "greynoise": ("greynoise_risk_score",),
    "shodan": ("shodan_risk_score",),
}


def _classify_ttl(
    provider: str,
    ioc_type: str,
    data: Mapping[str, object],
) -> timedelta:
    """Return the TTL to apply to a freshly written cache row.

    A row is malicious iff its provider's risk_score field is present
    in `data` and ≥ RISK_SCORE_MALICIOUS_THRESHOLD. Malicious rows
    decay over OpenCTI-default windows (60/90/180d by ioc_type);
    everything else falls into the 7-day benign tier.
    """
    fields = _RISK_SCORE_FIELDS.get(provider, ())
    score: float | None = None
    for field in fields:
        raw = data.get(field)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            score = float(raw)
            break

    is_malicious = score is not None and score >= RISK_SCORE_MALICIOUS_THRESHOLD
    if not is_malicious:
        return timedelta(days=CACHE_TTL_BENIGN_DAYS)
    if ioc_type == IOC_TYPE_HASH:
        return timedelta(days=CACHE_TTL_MALICIOUS_HASH_DAYS)
    if ioc_type == IOC_TYPE_DOMAIN:
        return timedelta(days=CACHE_TTL_MALICIOUS_DOMAIN_DAYS)
    return timedelta(days=CACHE_TTL_MALICIOUS_IP_DAYS)


def _init_cache(db_path: Path) -> sqlite3.Connection:
    """Initialise the SQLite enrichment cache.

    Schema versions handled by the auto-migration:
      * v2 — legacy single-``key`` column. Drop and recreate.
      * v3 — composite PK ``(provider, ioc_type, ioc_value)`` but no
        ``expires_at``; flat 7-day TTL. Drop and recreate so the new
        tiered policy applies cleanly. Up to ~7 days of cache loss;
        providers refill on the next run (Shodan's 100/month free
        tier is the only painful one — see docs/pipeline.md).
      * v4 — current: composite PK plus per-row ``expires_at``.

    ``expires_at`` is nullable so the read path can survive rows
    written before the write path was switched over; the SQL comparison
    ``expires_at > NOW()`` returns NULL for them, which is treated as
    expired — exactly what we want for unmigrated rows.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(cache)").fetchall()}
    if existing_cols and "ioc_type" not in existing_cols:
        logger.info(
            "cache_schema_migration",
            reason="dropping_legacy_v2_schema",
            from_version="v2",
            to_version="v4",
        )
        conn.execute("DROP TABLE cache")
        conn.commit()
    elif existing_cols and "expires_at" not in existing_cols:
        logger.info(
            "cache_schema_migration",
            reason="dropping_pre_expires_at_schema",
            from_version="v3",
            to_version="v4",
        )
        conn.execute("DROP TABLE cache")
        conn.commit()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache ("
        "  provider TEXT NOT NULL,"
        "  ioc_type TEXT NOT NULL,"
        "  ioc_value TEXT NOT NULL,"
        "  data TEXT NOT NULL,"
        "  queried_at TEXT NOT NULL,"
        "  expires_at TEXT,"
        "  PRIMARY KEY (provider, ioc_type, ioc_value)"
        ")"
    )
    conn.commit()
    return conn


def _get_cached(
    conn: sqlite3.Connection,
    provider: str,
    ioc_type: str,
    ioc_value: str,
) -> EnrichmentResult | None:
    """Return the cached result for (provider, ioc_type, ioc_value), or None.

    Freshness is decided per-row by the ``expires_at`` column set at
    write time (see ``_classify_ttl``). Rows with NULL ``expires_at``
    — only possible for entries written before the write path was
    switched over — are excluded by the SQL comparison (NULL > anything
    is NULL, which is falsy), so they read as misses and get re-queried.

    Malformed cached rows (data JSON that no longer deserialises) are
    also treated as a miss so one bad row cannot poison a whole batch.
    """
    now_iso = datetime.now(tz=UTC).isoformat()
    row = conn.execute(
        "SELECT data, queried_at FROM cache "
        "WHERE provider = ? AND ioc_type = ? AND ioc_value = ? "
        "AND expires_at > ?",
        (provider, ioc_type, ioc_value, now_iso),
    ).fetchone()
    if row is None:
        return None
    data_json, queried_at_str = row
    try:
        return EnrichmentResult(
            provider=provider,
            ip=ioc_value,
            data=json.loads(data_json),
            queried_at=datetime.fromisoformat(queried_at_str),
        )
    except (ValueError, json.JSONDecodeError):
        return None


def _set_cached(
    conn: sqlite3.Connection,
    provider: str,
    ioc_type: str,
    ioc_value: str,
    result: EnrichmentResult,
) -> None:
    """Store an enrichment result keyed by (provider, ioc_type, ioc_value).

    ``expires_at`` is derived per-row from the result's own data via
    ``_classify_ttl``: malicious rows (provider risk_score ≥ threshold)
    get the long ioc_type-specific window, everything else gets 7 days.
    """
    expires_at = result.queried_at + _classify_ttl(provider, ioc_type, result.data)
    conn.execute(
        "INSERT OR REPLACE INTO cache "
        "(provider, ioc_type, ioc_value, data, queried_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            provider,
            ioc_type,
            ioc_value,
            json.dumps(result.data),
            result.queried_at.isoformat(),
            expires_at.isoformat(),
        ),
    )
    conn.commit()


# -- Error handling ----------------------------------------------------------


ErrorAccumulator = dict[tuple[str, str], EnrichmentError]

# Query-string parameters whose values must never reach disk. Some providers
# (notably Shodan) take the API key as a URL query parameter, and httpx's
# HTTPStatusError stringifies the full request URL verbatim into its message
# — which would then land in /var/lib/lantana/datalake/enrichment_errors.json
# in cleartext, get read by the alerter, and potentially Discord-embedded.
# Headers-based auth (AbuseIPDB / VirusTotal / GreyNoise) is unaffected;
# headers never appear in the error string.
_SENSITIVE_QUERY_PARAMS = ("key", "api_key", "apikey", "token", "access_token")
_SENSITIVE_QUERY_RE = re.compile(
    r"([?&])(" + "|".join(_SENSITIVE_QUERY_PARAMS) + r")=[^&\s'\"]+",
    flags=re.IGNORECASE,
)


def _sanitize_error_message(message: str) -> str:
    """Strip API keys from URL query strings in error messages.

    Returns the message with `key=<value>` (and similar sensitive
    parameter names) replaced by `key=REDACTED`. Anchored to `?` or `&`
    so it never matches the same substring inside a JSON body, free
    text, or path segment.
    """
    return _SENSITIVE_QUERY_RE.sub(r"\1\2=REDACTED", message)


def _classify_http_error(status_code: int) -> str:
    """Map HTTP status code to a structured error type label.

    `auth_failed` (401/403) is the only one operators must act on — it
    means a vault key is broken. `not_found` is normal for IP lookups
    and is logged at debug level. `rate_limit` and `server_error` are
    expected throttling/transient signals.
    """
    if status_code == 429:
        return "rate_limit"
    if status_code in (401, 403):
        return "auth_failed"
    if status_code == 404:
        return "not_found"
    if 400 <= status_code < 500:
        return "http_4xx"
    return "server_error"


def _log_failure(error_type: str, **fields: object) -> None:
    """Route enrichment failures to the right log level by category."""
    if error_type == "auth_failed":
        logger.error("enrichment_failed", error_type=error_type, **fields)
    elif error_type == "not_found":
        logger.debug("enrichment_failed", error_type=error_type, **fields)
    else:
        logger.warning("enrichment_failed", error_type=error_type, **fields)


def _record_error(
    errors: ErrorAccumulator,
    provider: str,
    error_type: str,
    message: str,
) -> None:
    """Accumulate an error, incrementing count for repeated (provider, error_type).

    The message is run through ``_sanitize_error_message`` before storage
    so that API keys embedded in request URLs (Shodan query-string auth)
    never reach the enrichment_errors.json file.
    """
    safe_message = _sanitize_error_message(message)
    key = (provider, error_type)
    if key in errors:
        errors[key].count += 1
        errors[key].error_message = safe_message
    else:
        errors[key] = EnrichmentError(
            provider=provider,
            error_type=error_type,
            error_message=safe_message,
            timestamp=datetime.now(tz=UTC),
        )


def _write_error_summary(
    errors: ErrorAccumulator,
    target_date: date,
    errors_path: Path,
) -> None:
    """Append error summary lines to the enrichment errors file (NDJSON)."""
    if not errors:
        return
    errors_path.parent.mkdir(parents=True, exist_ok=True)
    with errors_path.open("a", encoding="utf-8") as f:
        for error in errors.values():
            line = json.dumps(
                {
                    "date": target_date.isoformat(),
                    "provider": error.provider,
                    "error_type": error.error_type,
                    "count": error.count,
                    "message": error.error_message,
                }
            )
            f.write(line + "\n")


# -- Provider state (cross-run skip + IP subsampling) ------------------------


ProviderState = dict[str, dict[str, str]]


def _load_provider_state(path: Path) -> ProviderState:
    """Load the persisted provider-state file, or return an empty dict.

    The state file is best-effort: a malformed or missing file is treated
    as an empty state so an operator manually editing it cannot bomb a
    run.
    """
    if not path.exists():
        return {}
    try:
        loaded: object = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("provider_state_load_failed", path=str(path), exc_repr=repr(exc))
        return {}
    if not isinstance(loaded, dict):
        return {}
    # Narrow object → ProviderState shape, dropping anything malformed.
    result: ProviderState = {}
    for provider, entry in loaded.items():
        if isinstance(provider, str) and isinstance(entry, dict):
            result[provider] = {
                k: v for k, v in entry.items() if isinstance(k, str) and isinstance(v, str)
            }
    return result


def _save_provider_state(path: Path, state: ProviderState) -> None:
    """Write the provider-state file atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(path)


def _should_skip_provider(
    provider_name: str,
    state: ProviderState,
    target_date: date,
) -> bool:
    """Return True if the provider's skip-window from its last rate-limit
    trip has not yet elapsed.

    Behaviour:
      * No policy for this provider → never skip.
      * No prior trip recorded → never skip.
      * Last trip + skip_window_days > target_date → skip.
    """
    policy = _PROVIDER_POLICY.get(provider_name, {})
    window_days = policy.get("skip_window_days")
    if window_days is None:
        return False
    last = state.get(provider_name, {}).get("last_rate_limited")
    if not last:
        return False
    try:
        last_date = date.fromisoformat(last)
    except ValueError:
        return False
    return (target_date - last_date).days < window_days


def _compute_ip_event_counts(dfs: dict[str, pl.DataFrame]) -> dict[str, int]:
    """Count events per source IP across all bronze datasets.

    Used to pick the highest-signal IPs when a provider's quota forces
    subsampling. ``src_ip`` is the canonical bronze column populated by
    Vector for every dataset that has IPs at all (cowrie, suricata,
    nftables); datasets without it contribute zero rows to the count.

    Implementation note: iterates raw Python rather than calling
    ``value_counts()`` because polars' value_counts is not order-stable
    between calls — pairing two separate column extractions misaligns IPs
    with their counts.
    """
    counts: dict[str, int] = {}
    for df in dfs.values():
        if df.is_empty() or "src_ip" not in df.columns:
            continue
        for ip in df.get_column("src_ip").drop_nulls().to_list():
            counts[str(ip)] = counts.get(str(ip), 0) + 1
    return counts


def _select_ips_for_provider(
    provider_name: str,
    ip_list: list[str],
    event_counts: dict[str, int],
) -> list[str]:
    """Apply per-provider subsampling.

    If the provider has ``subsample_top_n`` set, return the top-N IPs by
    event count (descending); tie-break alphabetical for determinism.
    Otherwise return the full sorted list unchanged.
    """
    policy = _PROVIDER_POLICY.get(provider_name, {})
    top_n = policy.get("subsample_top_n")
    if top_n is None or len(ip_list) <= top_n:
        return ip_list
    return sorted(
        ip_list,
        key=lambda ip: (-event_counts.get(ip, 0), ip),
    )[:top_n]


# -- Enrichment --------------------------------------------------------------


_ProviderType = AbuseIPDBProvider | GreyNoiseProvider | ShodanProvider | VirusTotalProvider


async def _query_provider(
    provider: _ProviderType,
    ioc_type: str,
    ioc_value: str,
) -> EnrichmentResult:
    """Dispatch to enrich_ip / enrich_hash based on ioc_type."""
    if ioc_type == IOC_TYPE_HASH:
        if not isinstance(provider, VirusTotalProvider):
            msg = f"hash enrichment is VirusTotal-only, got {type(provider).__name__}"
            raise TypeError(msg)
        return await provider.enrich_hash(ioc_value)
    return await provider.enrich_ip(ioc_value)


async def _enrich_iocs_with_provider(
    provider_name: str,
    provider: _ProviderType,
    ioc_type: str,
    iocs: list[str],
    cache: sqlite3.Connection,
    errors: ErrorAccumulator,
) -> tuple[list[EnrichmentResult], int]:
    """For one (provider, ioc_type) pair, enrich each IOC cache-first.

    Returns (combined results including cache hits, cache_hit_count).
    """
    log_field = "ip" if ioc_type == IOC_TYPE_IP else "sha256"
    results: list[EnrichmentResult] = []
    cache_hits = 0
    consecutive_rate_limits = 0
    cumulative_rate_limits = 0
    auth_failures = 0
    for index, value in enumerate(iocs):
        cached = _get_cached(cache, provider_name, ioc_type, value)
        if cached is not None:
            results.append(cached)
            cache_hits += 1
            consecutive_rate_limits = 0
            continue
        if consecutive_rate_limits >= CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD:
            logger.warning(
                "provider_short_circuited",
                provider=provider_name,
                ioc_type=ioc_type,
                reason="rate_limit_threshold",
                consecutive=consecutive_rate_limits,
                skipped=len(iocs) - index,
            )
            break
        if cumulative_rate_limits >= CIRCUIT_BREAKER_RATE_LIMIT_CUMULATIVE_THRESHOLD:
            logger.warning(
                "provider_short_circuited",
                provider=provider_name,
                ioc_type=ioc_type,
                reason="rate_limit_cumulative",
                cumulative=cumulative_rate_limits,
                skipped=len(iocs) - index,
            )
            break
        if auth_failures >= CIRCUIT_BREAKER_AUTH_FAILED_THRESHOLD:
            logger.error(
                "provider_short_circuited",
                provider=provider_name,
                ioc_type=ioc_type,
                reason="auth_failed",
                skipped=len(iocs) - index,
            )
            break
        try:
            result = await _query_provider(provider, ioc_type, value)
            _set_cached(cache, provider_name, ioc_type, value, result)
            results.append(result)
            consecutive_rate_limits = 0
        except httpx.HTTPStatusError as exc:
            etype = _classify_http_error(exc.response.status_code)
            _record_error(errors, provider_name, etype, str(exc))
            _log_failure(etype, provider=provider_name, **{log_field: value})
            if etype == "rate_limit":
                consecutive_rate_limits += 1
                cumulative_rate_limits += 1
            elif etype == "auth_failed":
                auth_failures += 1
            else:
                consecutive_rate_limits = 0
        except httpx.TimeoutException:
            _record_error(errors, provider_name, "timeout", "request timed out")
            _log_failure("timeout", provider=provider_name, **{log_field: value})
        except httpx.ConnectError as exc:
            _record_error(errors, provider_name, "network_error", str(exc))
            _log_failure("network_error", provider=provider_name, **{log_field: value})
        except Exception as exc:
            _record_error(errors, provider_name, "unknown", repr(exc))
            _log_failure(
                "unknown",
                provider=provider_name,
                exc_repr=repr(exc),
                **{log_field: value},
            )
    return results, cache_hits


def _build_lookup(
    results: list[EnrichmentResult],
) -> dict[str, dict[str, str | int | float | bool | None]]:
    """Collapse a flat list of EnrichmentResult into a `value → merged data` dict."""
    lookup: dict[str, dict[str, str | int | float | bool | None]] = {}
    for result in results:
        if result.ip not in lookup:
            lookup[result.ip] = {}
        lookup[result.ip].update(result.data)
    return lookup


def _merge_lookup(
    df: pl.DataFrame,
    join_col: str,
    lookup: dict[str, dict[str, str | int | float | bool | None]],
) -> pl.DataFrame:
    """Left-join enrichment columns onto `df` keyed by `join_col`."""
    if df.is_empty() or not lookup or join_col not in df.columns:
        return df
    records = [{"_enrich_key": value, **data} for value, data in lookup.items()]
    enrich_df = pl.DataFrame(records)
    return df.join(enrich_df, left_on=join_col, right_on="_enrich_key", how="left")


# Phase D.1 invariant: silver always carries all four IP-side
# <provider>_risk_score columns so gold's mean_horizontal composite has
# the same inputs every day. When a provider produces zero results
# (skipped via _should_skip_provider, quota exhausted with no successes,
# or unconfigured), _merge_lookup leaves the column absent — this helper
# backfills typed-null columns so downstream consumers see a stable schema.
_IP_RISK_SCORE_COLUMNS: tuple[str, ...] = (
    "abuseipdb_risk_score",
    "virustotal_risk_score",
    "shodan_risk_score",
    "greynoise_risk_score",
)


def _ensure_ip_score_columns(df: pl.DataFrame) -> pl.DataFrame:
    """Add typed-null Float64 columns for any missing per-provider risk_score."""
    if df.is_empty():
        return df
    missing = [c for c in _IP_RISK_SCORE_COLUMNS if c not in df.columns]
    if not missing:
        return df
    return df.with_columns([pl.lit(None, dtype=pl.Float64).alias(c) for c in missing])


# -- Orchestration -----------------------------------------------------------


async def run_enrichment(
    target_date: date,
    cache_db_path: Path = CACHE_DB_PATH,
    sensor_dir: Path = Path("/var/lib/lantana/sensor"),
    errors_path: Path = ERRORS_PATH,
    provider_state_path: Path = PROVIDER_STATE_PATH,
) -> None:
    """Run the full enrichment pipeline for a given date."""
    secrets = load_secrets()
    reporting = load_reporting()

    redact_config = RedactionConfig(
        infrastructure_ips=reporting.redact.infrastructure_ips,
        infrastructure_cidrs=reporting.redact.infrastructure_cidrs,
        pseudonym_map=reporting.redact.pseudonym_map,
    )

    cache = _init_cache(cache_db_path)
    errors: ErrorAccumulator = {}

    # Aggregated counters for the end-of-run summary. Filled in as Phases
    # B and C progress so operators get one structlog line per run with
    # the full picture instead of having to grep for every dataset and
    # provider event.
    silver_rows: dict[str, int] = {}
    provider_stats: dict[str, dict[str, int]] = {}

    # GreyNoise is skipped when the vault key is absent (None); an empty
    # string keeps it enabled in its unauthenticated Community-API mode.
    providers: dict[str, _ProviderType] = {
        "abuseipdb": AbuseIPDBProvider(secrets.abuseipdb),
        "shodan": ShodanProvider(secrets.shodan),
        "virustotal": VirusTotalProvider(secrets.virustotal),
    }
    if secrets.greynoise is not None:
        providers["greynoise"] = GreyNoiseProvider(secrets.greynoise)
    else:
        logger.info("provider_disabled", provider="greynoise", reason="not_configured")

    try:
        # Phase A: load all bronze, extract IOCs globally
        dfs: dict[str, pl.DataFrame] = {}
        for dataset in DATASETS:
            df = read_bronze_ndjson(target_date, dataset=dataset)
            if df.is_empty():
                logger.info("enrichment_skip_empty", dataset=dataset)
                continue
            dfs[dataset] = df

        if not dfs:
            logger.info("enrichment_no_data", date=target_date.isoformat())
            return

        raw_ips: set[str] = set()
        for ds_df in dfs.values():
            raw_ips.update(extract_ips(ds_df))
        unique_ips = filter_internal_ips(raw_ips, redact_config)
        if len(raw_ips) != len(unique_ips):
            logger.info("internal_ips_filtered", count=len(raw_ips) - len(unique_ips))
        logger.info(
            "unique_iocs_found",
            ioc_type=IOC_TYPE_IP,
            count=len(unique_ips),
        )

        unique_hashes: set[str] = set()
        for ds_df in dfs.values():
            unique_hashes.update(extract_hashes_from_bronze(ds_df))
        unique_hashes.update(extract_hashes_from_disk(sensor_dir))
        logger.info(
            "unique_iocs_found",
            ioc_type=IOC_TYPE_HASH,
            count=len(unique_hashes),
        )

        # Phase B: enrich each IOC type once, across the relevant providers.
        # Two pre-flight steps before the loop:
        #   1. Load persisted provider state (cross-run rate-limit memory)
        #   2. Compute IP→event-count for subsampling on tiny-quota providers
        provider_state = _load_provider_state(provider_state_path)
        event_counts = _compute_ip_event_counts(dfs)
        full_ip_list = sorted(unique_ips)
        ip_results: list[EnrichmentResult] = []
        for name, provider in providers.items():
            if _should_skip_provider(name, provider_state, target_date):
                last = provider_state.get(name, {}).get("last_rate_limited", "?")
                logger.info(
                    "provider_skipped_rate_limit_window",
                    provider=name,
                    last_rate_limited=last,
                    target_date=target_date.isoformat(),
                )
                provider_stats[f"{name}:{IOC_TYPE_IP}"] = {
                    "enriched": 0,
                    "fresh": 0,
                    "cache_hits": 0,
                    "skipped_rate_limit": 1,
                }
                continue

            selected_ips = _select_ips_for_provider(name, full_ip_list, event_counts)
            if len(selected_ips) != len(full_ip_list):
                logger.info(
                    "provider_subsampled",
                    provider=name,
                    selected=len(selected_ips),
                    total=len(full_ip_list),
                )

            results, hits = await _enrich_iocs_with_provider(
                name,
                provider,
                IOC_TYPE_IP,
                selected_ips,
                cache,
                errors,
            )
            ip_results.extend(results)
            provider_stats[f"{name}:{IOC_TYPE_IP}"] = {
                "enriched": len(results),
                "fresh": len(results) - hits,
                "cache_hits": hits,
            }
            logger.info(
                "provider_done",
                provider=name,
                ioc_type=IOC_TYPE_IP,
                enriched=len(results),
                fresh=len(results) - hits,
                cache_hits=hits,
            )

            # Persist rate-limit trip date so future runs can short-circuit
            # this provider until its quota window has elapsed. Any
            # rate_limit error at all this run is sufficient signal — even
            # one means the cache is exhausted enough that further calls
            # are likely to fail.
            if (name, "rate_limit") in errors:
                provider_state.setdefault(name, {})["last_rate_limited"] = target_date.isoformat()

        hash_results: list[EnrichmentResult] = []
        if unique_hashes:
            vt_provider = providers["virustotal"]
            hash_results, hash_hits = await _enrich_iocs_with_provider(
                "virustotal",
                vt_provider,
                IOC_TYPE_HASH,
                sorted(unique_hashes),
                cache,
                errors,
            )
            provider_stats[f"virustotal:{IOC_TYPE_HASH}"] = {
                "enriched": len(hash_results),
                "fresh": len(hash_results) - hash_hits,
                "cache_hits": hash_hits,
            }
            logger.info(
                "provider_done",
                provider="virustotal",
                ioc_type=IOC_TYPE_HASH,
                enriched=len(hash_results),
                fresh=len(hash_results) - hash_hits,
                cache_hits=hash_hits,
            )

        ip_lookup = _build_lookup(ip_results)
        hash_lookup = _build_lookup(hash_results)

        # Phase C: per-dataset merge + normalise + redact + write.
        # Each dataset is wrapped in try/except so a failure in one dataset's
        # normaliser (e.g. unparsed bronze, schema drift, polars error) doesn't
        # cancel the silver writes for the others. Today's op_alpha runs hit
        # this twice in one day (suricata struct, nftables raw-message) — one
        # dataset's defect should never torpedo the rest.
        for dataset, df in dfs.items():
            try:
                enriched_df = _merge_lookup(df, "src_ip", ip_lookup)
                enriched_df = _ensure_ip_score_columns(enriched_df)
                if dataset == "cowrie":
                    enriched_df = _merge_lookup(enriched_df, "shasum", hash_lookup)

                normalized_df = normalize_dataset(enriched_df, dataset)
                if normalized_df.is_empty():
                    logger.info(
                        "silver_skipped_empty_after_normalize",
                        dataset=dataset,
                        reason="bronze_lacked_required_fields_or_normalize_returned_empty",
                    )
                    continue

                # Drop outbound-response noise where the honeypot itself appears
                # as source (Suricata sees both flow directions; Vector's
                # Layer-1 filter currently catches internal-prefix sources but
                # not WAN sources).
                row_count_before = normalized_df.height
                cleaned_df = drop_infrastructure_source_rows(normalized_df, redact_config)
                dropped = row_count_before - cleaned_df.height
                if dropped:
                    logger.info(
                        "infrastructure_source_rows_dropped",
                        dataset=dataset,
                        count=dropped,
                    )
                redacted_df = redact_infrastructure_ips(cleaned_df, redact_config)
                validate_no_leaks(redacted_df, redact_config)

                servers = (
                    redacted_df.get_column("server").unique().to_list()
                    if "server" in redacted_df.columns
                    else ["unknown"]
                )
                for server in servers:
                    server_df = (
                        redacted_df.filter(pl.col("server") == server)
                        if len(servers) > 1
                        else redacted_df
                    )
                    write_silver_partition(server_df, target_date, dataset, str(server))

                silver_rows[dataset] = len(redacted_df)
                logger.info("enrichment_done", dataset=dataset, rows=len(redacted_df))
            except Exception as exc:
                logger.error(
                    "dataset_processing_failed",
                    dataset=dataset,
                    exc_repr=repr(exc),
                )
                _record_error(errors, "pipeline", "dataset_processing_failed", repr(exc))

        _save_provider_state(provider_state_path, provider_state)
        logger.info(
            "run_summary",
            date=target_date.isoformat(),
            silver_rows=silver_rows,
            unique_ips=len(unique_ips),
            unique_hashes=len(unique_hashes),
            providers=provider_stats,
            error_count=sum(e.count for e in errors.values()),
        )
        _write_error_summary(errors, target_date, errors_path)

    finally:
        for provider in providers.values():
            await provider.close()
        cache.close()


def main() -> None:
    """CLI entry point for lantana-enrich."""
    parser = argparse.ArgumentParser(
        prog="lantana-enrich",
        description="Enrich bronze NDJSON into silver Parquet for a given date.",
    )
    parser.add_argument(
        "--date",
        type=date.fromisoformat,
        default=None,
        metavar="YYYY-MM-DD",
        help="Date to enrich (UTC). Defaults to yesterday.",
    )
    args = parser.parse_args()
    target = args.date if args.date is not None else date.today() - timedelta(days=1)
    asyncio.run(run_enrichment(target))

"""Main enrichment orchestrator — IOC-first, priority-ranked, rate-limited.

Daily workflow:
1. Load every dataset's bronze NDJSON for the target date.
2. Extract IOCs globally across datasets from Bronze telemetry only: inbound IPs,
   malware SHA-256 hashes, outbound C2 IPs, and post-auth stager URLs & domains.
3. OPSEC-filter all IPs, URLs, and domains against infrastructure ranges and
   hostnames before any external API lookup.
4. Enrich cache-first with token-bucket rate limiting and behavioral priority
   sorting. VirusTotal/GTI runs a unified priority queue:
   hashes -> outbound C2 IPs -> post-auth stager URLs/domains -> inbound IPs.
5. Per dataset: merge enrichments, OCSF-normalize, drop infra-source rows,
   redact infra IPs/variants/hostnames, validate zero leaks, write silver
   Parquet.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import os
import re
import sqlite3
import time
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
    scrub_infra_strings,
    validate_no_leaks,
)
from lantana.enrichment.ioc import (
    extract_hashes_from_bronze,
    extract_ips,
    extract_outbound_c2_ips,
    extract_outbound_urls,
    extract_stager_domains,
    filter_internal_ips,
)
from lantana.enrichment.providers.abuseipdb import AbuseIPDBProvider
from lantana.enrichment.providers.base import EnrichmentError, EnrichmentResult
from lantana.enrichment.providers.greynoise import GreyNoiseProvider
from lantana.enrichment.providers.shodan import ShodanProvider
from lantana.enrichment.providers.virustotal import VirusTotalProvider
from lantana.models.normalize import normalize_dataset

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

logger = structlog.get_logger()

CACHE_DB_PATH = Path("/var/lib/lantana/datalake/.enrichment_cache.db")

# Tiered cache TTLs by classification and ioc_type (OpenCTI decay defaults).
CACHE_TTL_BENIGN_DAYS = 7
CACHE_TTL_MALICIOUS_IP_DAYS = 60
CACHE_TTL_MALICIOUS_DOMAIN_DAYS = 90
CACHE_TTL_MALICIOUS_URL_DAYS = 90
CACHE_TTL_MALICIOUS_HASH_DAYS = 180
RISK_SCORE_MALICIOUS_THRESHOLD = 50.0

ERRORS_PATH = Path(
    os.environ.get("LANTANA_ENRICHMENT_ERRORS", "/var/lib/lantana/datalake/enrichment_errors.json")
)
PROVIDER_STATE_PATH = Path("/var/lib/lantana/datalake/.provider_state.json")

DATASETS = ["cowrie", "suricata", "nftables", "dionaea"]

IOC_TYPE_IP = "ip"
IOC_TYPE_HASH = "hash"
IOC_TYPE_URL = "url"
IOC_TYPE_DOMAIN = "domain"

# Free VT daily quota is 500/day shared across hashes/IPs/URLs/domains; keep a
# 20-request margin and stay comfortably inside the 01:00-05:30 UTC window.
VT_FREE_DAILY_REQUEST_BUDGET = 480

# Per-provider IP-selection policy.
_PROVIDER_POLICY: dict[str, dict[str, int]] = {
    "greynoise": {"subsample_top_n": 40, "skip_window_days": 6},
    "shodan": {"skip_window_days": 28},
}

# Circuit-breaker thresholds for _enrich_iocs_with_provider.
CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD = 5
CIRCUIT_BREAKER_RATE_LIMIT_CUMULATIVE_THRESHOLD = 30
CIRCUIT_BREAKER_AUTH_FAILED_THRESHOLD = 1


# -- Token-bucket rate limiter -----------------------------------------------


class _AsyncRateLimiter:
    """Async token-bucket pacer honoring ``provider.rate_limit()``.

    Short windows (``per_seconds <= 3600``, e.g. VT's ``(4, 60)``) are paced
    strictly at ``max_requests / per_seconds`` with burst capacity
    ``max_requests``. Multi-day quota windows (``per_seconds > 3600``, e.g.
    AbuseIPDB ``(1000, 86400)``, Shodan ``(100, 2592000)``, GreyNoise
    ``(50, 604800)``) are paced gently at 1 req/s (burst 2) so we respect
    per-second API rules without sleeping hours between requests.
    """

    def __init__(
        self,
        max_requests: int,
        per_seconds: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._clock = clock
        self._sleep = sleep
        if max_requests <= 0 or per_seconds <= 0:
            self._enabled = False
            self._capacity = 0.0
            self._rate = 0.0
            self._tokens = 0.0
            self._last = 0.0
            return

        self._enabled = True
        if per_seconds <= 3600:
            self._capacity = float(max_requests)
            self._rate = float(max_requests) / float(per_seconds)
        else:
            self._capacity = 2.0
            self._rate = 1.0
        self._tokens = self._capacity
        self._last = self._clock()

    async def acquire(self) -> None:
        """Consume one token, sleeping only when the bucket is empty."""
        if not self._enabled:
            return
        now = self._clock()
        elapsed = max(0.0, now - self._last)
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return
        wait_seconds = (1.0 - self._tokens) / self._rate
        await self._sleep(wait_seconds)
        self._last = self._clock()
        self._tokens = 0.0


def _build_rate_limiter(provider: object) -> _AsyncRateLimiter | None:
    """Construct an _AsyncRateLimiter from ``provider.rate_limit()`` when valid."""
    rl_fn = getattr(provider, "rate_limit", None)
    if not callable(rl_fn) or inspect.iscoroutinefunction(rl_fn):
        return None
    raw = rl_fn()
    if inspect.iscoroutine(raw):
        raw.close()
        return None
    if (
        isinstance(raw, tuple)
        and len(raw) == 2
        and isinstance(raw[0], int)
        and isinstance(raw[1], int)
        and not isinstance(raw[0], bool)
        and not isinstance(raw[1], bool)
    ):
        return _AsyncRateLimiter(raw[0], raw[1])
    return None


# -- Cache -------------------------------------------------------------------


_RISK_SCORE_FIELDS: dict[str, tuple[str, ...]] = {
    "abuseipdb": ("abuseipdb_risk_score",),
    "virustotal": (
        "virustotal_risk_score",
        "vt_file_risk_score",
        "vt_url_risk_score",
        "vt_domain_risk_score",
    ),
    "greynoise": ("greynoise_risk_score",),
    "shodan": ("shodan_risk_score",),
}


def _classify_ttl(
    provider: str,
    ioc_type: str,
    data: Mapping[str, object],
) -> timedelta:
    """Return the TTL to apply to a freshly written cache row."""
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
    if ioc_type == IOC_TYPE_URL:
        return timedelta(days=CACHE_TTL_MALICIOUS_URL_DAYS)
    if ioc_type == IOC_TYPE_DOMAIN:
        return timedelta(days=CACHE_TTL_MALICIOUS_DOMAIN_DAYS)
    return timedelta(days=CACHE_TTL_MALICIOUS_IP_DAYS)


def _init_cache(db_path: Path) -> sqlite3.Connection:
    """Initialise the SQLite enrichment cache (schema v4)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
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
    now_iso = datetime.now(tz=UTC).isoformat()
    conn.execute(
        "DELETE FROM cache WHERE expires_at IS NOT NULL AND expires_at <= ?",
        (now_iso,),
    )
    conn.commit()
    return conn


def _get_cached(
    conn: sqlite3.Connection,
    provider: str,
    ioc_type: str,
    ioc_value: str,
) -> EnrichmentResult | None:
    """Return the cached result for (provider, ioc_type, ioc_value), or None."""
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
    """Store an enrichment result keyed by (provider, ioc_type, ioc_value)."""
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


def load_enrichment_cache_lookup(
    cache_db_path: Path = CACHE_DB_PATH,
    provider: str = "virustotal",
) -> dict[tuple[str, str], dict[str, str | int | float | bool | None]]:
    """Read active cached enrichment records keyed by ``(ioc_type, ioc_value)``.

    Used at the IO edge by ``transform/runner.py`` to hydrate VT/GTI verdicts
    for durable outbound IOCs (C2 IPs, stager URLs, stager domains, hashes)
    into the ``extracted_iocs`` gold table without adding extra silver tables.
    """
    if not cache_db_path.exists():
        return {}
    now_iso = datetime.now(tz=UTC).isoformat()
    lookup: dict[tuple[str, str], dict[str, str | int | float | bool | None]] = {}
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{cache_db_path}?mode=ro", uri=True)
        rows = conn.execute(
            "SELECT ioc_type, ioc_value, data FROM cache "
            "WHERE provider = ? AND (expires_at IS NULL OR expires_at > ?)",
            (provider, now_iso),
        ).fetchall()
        for ioc_type, ioc_value, data_json in rows:
            try:
                parsed = json.loads(data_json)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(parsed, dict):
                lookup[(str(ioc_type), str(ioc_value))] = parsed
    except sqlite3.Error as exc:
        logger.warning("cache_lookup_read_failed", path=str(cache_db_path), exc_repr=repr(exc))
    finally:
        if conn is not None:
            conn.close()
    return lookup


# -- Error handling ----------------------------------------------------------


ErrorAccumulator = dict[tuple[str, str], EnrichmentError]

_SENSITIVE_QUERY_PARAMS = ("key", "api_key", "apikey", "license_key", "token", "access_token")
_SENSITIVE_QUERY_RE = re.compile(
    r"([?&])(" + "|".join(_SENSITIVE_QUERY_PARAMS) + r")=[^&\s'\"]+",
    flags=re.IGNORECASE,
)


def _sanitize_error_message(
    message: str,
    redact_config: RedactionConfig | None = None,
) -> str:
    """Strip API keys from URL query strings AND scrub infra IPs/hostnames."""
    sanitized = _SENSITIVE_QUERY_RE.sub(r"\1\2=REDACTED", message)
    if redact_config is not None:
        sanitized = scrub_infra_strings(sanitized, redact_config)
    return sanitized


def _classify_http_error(status_code: int) -> str:
    """Map HTTP status code to a structured error type label."""
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
    redact_config: RedactionConfig | None = None,
) -> None:
    """Accumulate an error after scrubbing secrets and infrastructure strings."""
    safe_message = _sanitize_error_message(message, redact_config=redact_config)
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


# -- Provider state & behavioral priority ranking ----------------------------


ProviderState = dict[str, dict[str, str]]
IpPriorityTuple = tuple[int, int, int, int, int, int]


def _load_provider_state(path: Path) -> ProviderState:
    """Load the persisted provider-state file, or return an empty dict."""
    if not path.exists():
        return {}
    try:
        loaded: object = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("provider_state_load_failed", path=str(path), exc_repr=repr(exc))
        return {}
    if not isinstance(loaded, dict):
        return {}
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
    """Return True if the provider's skip-window from its last rate-limit trip has not elapsed."""
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
    """Count events per source IP across all bronze datasets."""
    counts: dict[str, int] = {}
    for df in dfs.values():
        if df.is_empty() or "src_ip" not in df.columns:
            continue
        for ip in df.get_column("src_ip").drop_nulls().to_list():
            counts[str(ip)] = counts.get(str(ip), 0) + 1
    return counts


def _compute_ip_priority(
    dfs: dict[str, pl.DataFrame],
    c2_ips: set[str] | None = None,
) -> dict[str, IpPriorityTuple]:
    """Rank every observed IP by behavioral signal before API lookup.

    Tuple ordering (descending):
      ``(is_c2_ip, downloads, commands, auth_attempts, findings, total_events)``
    Ensures scarce API quotas (AbuseIPDB, GreyNoise, Shodan, VT) spend calls on
    interactive attackers and outbound C2 infrastructure instead of alphabetically
    low port scanners.
    """
    c2_set = c2_ips or set()
    stats: dict[str, list[int]] = {}

    def _slot(ip: str) -> list[int]:
        entry = stats.get(ip)
        if entry is None:
            entry = [1 if ip in c2_set else 0, 0, 0, 0, 0, 0]
            stats[ip] = entry
        return entry

    for ip in c2_set:
        _slot(ip)

    for dataset, df in dfs.items():
        if df.is_empty() or "src_ip" not in df.columns:
            continue
        cols = ["src_ip"]
        for opt in ("eventid", "event_type", "credential_username", "ftp_command"):
            if opt in df.columns:
                cols.append(opt)
        for row in df.select(cols).iter_rows(named=True):
            raw_ip = row.get("src_ip")
            if not raw_ip:
                continue
            slot = _slot(str(raw_ip))
            slot[5] += 1  # total_events
            eventid = str(row.get("eventid") or "")
            event_type = str(row.get("event_type") or "")
            if eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                slot[1] += 1  # downloads
            elif eventid.startswith("cowrie.command") or row.get("ftp_command"):
                slot[2] += 1  # commands
            elif eventid.startswith("cowrie.login") or row.get("credential_username"):
                slot[3] += 1  # auth_attempts
            elif dataset == "suricata" and event_type == "alert":
                slot[4] += 1  # findings

    return {ip: (s[0], s[1], s[2], s[3], s[4], s[5]) for ip, s in stats.items()}


def _select_ips_for_provider(
    provider_name: str,
    ip_list: list[str],
    event_counts: dict[str, int],
    priority_map: Mapping[str, IpPriorityTuple] | None = None,
) -> list[str]:
    """Order IPs by behavioral priority (or event counts) and apply per-provider cap."""
    policy = _PROVIDER_POLICY.get(provider_name, {})
    top_n = policy.get("subsample_top_n")

    if priority_map is not None:
        ordered = sorted(
            ip_list,
            key=lambda ip: (
                tuple(-v for v in priority_map.get(ip, (0, 0, 0, 0, 0, event_counts.get(ip, 0)))),
                ip,
            ),
        )
        return ordered[:top_n] if top_n is not None else ordered

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
    """Dispatch to enrich_ip / enrich_hash / enrich_url / enrich_domain."""
    if ioc_type == IOC_TYPE_HASH:
        if not isinstance(provider, VirusTotalProvider):
            msg = f"hash enrichment is VirusTotal-only, got {type(provider).__name__}"
            raise TypeError(msg)
        return await provider.enrich_hash(ioc_value)
    if ioc_type == IOC_TYPE_URL:
        if not isinstance(provider, VirusTotalProvider):
            msg = f"url enrichment is VirusTotal-only, got {type(provider).__name__}"
            raise TypeError(msg)
        return await provider.enrich_url(ioc_value)
    if ioc_type == IOC_TYPE_DOMAIN:
        if not isinstance(provider, VirusTotalProvider):
            msg = f"domain enrichment is VirusTotal-only, got {type(provider).__name__}"
            raise TypeError(msg)
        return await provider.enrich_domain(ioc_value)
    return await provider.enrich_ip(ioc_value)


async def _enrich_iocs_with_provider(
    provider_name: str,
    provider: _ProviderType,
    ioc_type: str,
    iocs: list[str],
    cache: sqlite3.Connection,
    errors: ErrorAccumulator,
    *,
    rate_limiter: _AsyncRateLimiter | None = None,
    max_fresh_requests: int | None = None,
    redact_config: RedactionConfig | None = None,
) -> tuple[list[EnrichmentResult], int]:
    """For one (provider, ioc_type) pair, enrich each IOC cache-first with rate pacing.

    Returns ``(combined results including cache hits, cache_hit_count)``.
    Cache hits never consume rate-limiter tokens or fresh-request budget.
    """
    log_field = ioc_type if ioc_type in (IOC_TYPE_IP, IOC_TYPE_URL, IOC_TYPE_DOMAIN) else "sha256"
    limiter = rate_limiter if rate_limiter is not None else _build_rate_limiter(provider)
    results: list[EnrichmentResult] = []
    cache_hits = 0
    fresh_attempts = 0
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
        if max_fresh_requests is not None and fresh_attempts >= max_fresh_requests:
            logger.info(
                "provider_budget_reached",
                provider=provider_name,
                ioc_type=ioc_type,
                budget=max_fresh_requests,
                skipped=len(iocs) - index,
            )
            break
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

        if limiter is not None:
            await limiter.acquire()
        fresh_attempts += 1

        try:
            result = await _query_provider(provider, ioc_type, value)
            _set_cached(cache, provider_name, ioc_type, value, result)
            results.append(result)
            consecutive_rate_limits = 0
        except httpx.HTTPStatusError as exc:
            etype = _classify_http_error(exc.response.status_code)
            _record_error(errors, provider_name, etype, str(exc), redact_config=redact_config)
            _log_failure(etype, provider=provider_name, **{log_field: value})
            if etype == "rate_limit":
                consecutive_rate_limits += 1
                cumulative_rate_limits += 1
            elif etype == "auth_failed":
                auth_failures += 1
            else:
                consecutive_rate_limits = 0
        except httpx.TimeoutException:
            _record_error(
                errors,
                provider_name,
                "timeout",
                "request timed out",
                redact_config=redact_config,
            )
            _log_failure("timeout", provider=provider_name, **{log_field: value})
        except httpx.ConnectError as exc:
            _record_error(
                errors,
                provider_name,
                "network_error",
                str(exc),
                redact_config=redact_config,
            )
            _log_failure("network_error", provider=provider_name, **{log_field: value})
        except Exception as exc:
            _record_error(
                errors,
                provider_name,
                "unknown",
                repr(exc),
                redact_config=redact_config,
            )
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
    """Collapse a flat list of EnrichmentResult into a ``value -> merged data`` dict."""
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
    """Left-join enrichment columns onto ``df`` keyed by ``join_col``."""
    if df.is_empty() or not lookup or join_col not in df.columns:
        return df
    records = [{"_enrich_key": value, **data} for value, data in lookup.items()]
    enrich_df = pl.DataFrame(records)
    # Drop any already-present non-key enrichment columns from enrich_df? No,
    # avoid duplicate column name collisions (e.g. vt_status from both IP & hash)
    # by keeping existing columns on the left when already present.
    overlap = [c for c in enrich_df.columns if c != "_enrich_key" and c in df.columns]
    if overlap:
        enrich_df = enrich_df.drop(overlap)
    if len(enrich_df.columns) <= 1:
        return df
    return df.join(enrich_df, left_on=join_col, right_on="_enrich_key", how="left")


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


async def run_enrichment(
    target_date: date,
    cache_db_path: Path = CACHE_DB_PATH,
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
        infrastructure_hostnames=reporting.redact.infrastructure_hostnames,
    )

    cache = _init_cache(cache_db_path)
    errors: ErrorAccumulator = {}
    silver_rows: dict[str, int] = {}
    provider_stats: dict[str, dict[str, int]] = {}

    # Instantiate only configured providers — missing/empty keys skip cleanly
    # without firing 401 auth errors.
    providers: dict[str, _ProviderType] = {}
    if secrets.abuseipdb and secrets.abuseipdb.strip():
        providers["abuseipdb"] = AbuseIPDBProvider(secrets.abuseipdb.strip())
    else:
        logger.info("provider_disabled", provider="abuseipdb", reason="not_configured")

    if secrets.shodan and secrets.shodan.strip():
        providers["shodan"] = ShodanProvider(secrets.shodan.strip())
    else:
        logger.info("provider_disabled", provider="shodan", reason="not_configured")

    vt_key = (secrets.gti or "").strip() if secrets.gti_enabled and secrets.gti else ""
    if vt_key:
        providers["virustotal"] = VirusTotalProvider(vt_key, gti_enabled=True)
    elif secrets.virustotal and secrets.virustotal.strip():
        if secrets.gti_enabled:
            providers["virustotal"] = VirusTotalProvider(
                secrets.virustotal.strip(),
                gti_enabled=True,
            )
        else:
            providers["virustotal"] = VirusTotalProvider(secrets.virustotal.strip())
    else:
        logger.info("provider_disabled", provider="virustotal", reason="not_configured")

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
        outbound_urls: set[str] = set()
        outbound_c2_ips: set[str] = set()
        unique_hashes: set[str] = set()
        for ds_df in dfs.values():
            raw_ips.update(extract_ips(ds_df))
            unique_hashes.update(extract_hashes_from_bronze(ds_df))
            outbound_urls.update(extract_outbound_urls(ds_df, redact_config))
            outbound_c2_ips.update(extract_outbound_c2_ips(ds_df, redact_config))

        unique_ips = filter_internal_ips(raw_ips, redact_config)
        stager_domains = extract_stager_domains(outbound_urls, redact_config)

        if len(raw_ips) != len(unique_ips):
            logger.info("internal_ips_filtered", count=len(raw_ips) - len(unique_ips))
        logger.info("unique_iocs_found", ioc_type=IOC_TYPE_IP, count=len(unique_ips))
        logger.info("unique_iocs_found", ioc_type=IOC_TYPE_HASH, count=len(unique_hashes))
        if outbound_c2_ips or outbound_urls or stager_domains:
            logger.info(
                "durable_iocs_found",
                c2_ips=len(outbound_c2_ips),
                stager_urls=len(outbound_urls),
                stager_domains=len(stager_domains),
            )

        # Phase B: enrich each IOC type once with behavioral priority ranking
        provider_state = _load_provider_state(provider_state_path)
        event_counts = _compute_ip_event_counts(dfs)
        priority_map = _compute_ip_priority(dfs, c2_ips=outbound_c2_ips)
        all_target_ips = sorted(unique_ips | outbound_c2_ips)

        hash_results: list[EnrichmentResult] = []
        url_results: list[EnrichmentResult] = []
        ip_results: list[EnrichmentResult] = []

        # Phase B.1: Unified VirusTotal / GTI priority queue
        # Order: hashes -> outbound C2 IPs -> post-auth stager URLs -> stager domains -> inbound IPs
        vt_provider = providers.get("virustotal")
        vt_c2_done: set[str] = set()
        if vt_provider is not None and not _should_skip_provider(
            "virustotal", provider_state, target_date
        ):
            vt_gti = bool(getattr(vt_provider, "gti_enabled", False))
            vt_budget: int | None = None if vt_gti else VT_FREE_DAILY_REQUEST_BUDGET
            vt_limiter = _build_rate_limiter(vt_provider)

            def _vt_tripped() -> bool:
                return ("virustotal", "rate_limit") in errors or (
                    "virustotal",
                    "auth_failed",
                ) in errors

            async def _run_vt_stage(
                ioc_type: str,
                items: list[str],
                stat_key: str,
            ) -> list[EnrichmentResult]:
                nonlocal vt_budget
                if not items or _vt_tripped() or (vt_budget is not None and vt_budget <= 0):
                    return []
                stage_results, stage_hits = await _enrich_iocs_with_provider(
                    "virustotal",
                    vt_provider,
                    ioc_type,
                    items,
                    cache,
                    errors,
                    rate_limiter=vt_limiter,
                    max_fresh_requests=vt_budget,
                    redact_config=redact_config,
                )
                fresh = len(stage_results) - stage_hits
                if vt_budget is not None:
                    vt_budget = max(0, vt_budget - fresh)
                provider_stats[stat_key] = {
                    "enriched": len(stage_results),
                    "fresh": fresh,
                    "cache_hits": stage_hits,
                }
                logger.info(
                    "provider_done",
                    provider="virustotal",
                    ioc_type=ioc_type,
                    enriched=len(stage_results),
                    fresh=fresh,
                    cache_hits=stage_hits,
                )
                return stage_results

            hash_results = await _run_vt_stage(
                IOC_TYPE_HASH,
                sorted(unique_hashes),
                f"virustotal:{IOC_TYPE_HASH}",
            )
            c2_sorted = sorted(outbound_c2_ips)
            if c2_sorted:
                c2_vt_results = await _run_vt_stage(
                    IOC_TYPE_IP,
                    c2_sorted,
                    "virustotal:c2_ip",
                )
                ip_results.extend(c2_vt_results)
                vt_c2_done.update(c2_sorted)
            url_results = await _run_vt_stage(
                IOC_TYPE_URL,
                sorted(outbound_urls),
                f"virustotal:{IOC_TYPE_URL}",
            )
            await _run_vt_stage(
                IOC_TYPE_DOMAIN,
                sorted(stager_domains),
                f"virustotal:{IOC_TYPE_DOMAIN}",
            )

            inbound_vt_ips = _select_ips_for_provider(
                "virustotal",
                [ip for ip in all_target_ips if ip not in vt_c2_done],
                event_counts,
                priority_map=priority_map,
            )
            inbound_vt_results = await _run_vt_stage(
                IOC_TYPE_IP,
                inbound_vt_ips,
                f"virustotal:{IOC_TYPE_IP}",
            )
            ip_results.extend(inbound_vt_results)

            if ("virustotal", "rate_limit") in errors:
                provider_state.setdefault("virustotal", {})["last_rate_limited"] = (
                    target_date.isoformat()
                )

        # Phase B.2: Remaining IP providers (AbuseIPDB, Shodan, GreyNoise), behavioral-ranked
        for name, provider in providers.items():
            if name == "virustotal":
                continue
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

            selected_ips = _select_ips_for_provider(
                name,
                all_target_ips,
                event_counts,
                priority_map=priority_map,
            )
            if len(selected_ips) != len(all_target_ips):
                logger.info(
                    "provider_subsampled",
                    provider=name,
                    selected=len(selected_ips),
                    total=len(all_target_ips),
                )

            results, hits = await _enrich_iocs_with_provider(
                name,
                provider,
                IOC_TYPE_IP,
                selected_ips,
                cache,
                errors,
                redact_config=redact_config,
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

            if (name, "rate_limit") in errors:
                provider_state.setdefault(name, {})["last_rate_limited"] = target_date.isoformat()

        ip_lookup = _build_lookup(ip_results)
        hash_lookup = _build_lookup(hash_results)
        url_lookup = _build_lookup(url_results)

        # Phase C: per-dataset merge + normalise + redact + write.
        for dataset, df in dfs.items():
            try:
                enriched_df = _merge_lookup(df, "src_ip", ip_lookup)
                enriched_df = _ensure_ip_score_columns(enriched_df)
                if dataset in ("cowrie", "dionaea"):
                    enriched_df = _merge_lookup(enriched_df, "shasum", hash_lookup)
                if dataset == "cowrie" and url_lookup:
                    enriched_df = _merge_lookup(enriched_df, "url", url_lookup)

                normalized_df = normalize_dataset(enriched_df, dataset)
                if normalized_df.is_empty():
                    logger.info(
                        "silver_skipped_empty_after_normalize",
                        dataset=dataset,
                        reason="bronze_lacked_required_fields_or_normalize_returned_empty",
                    )
                    continue

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

                if "server" in redacted_df.columns:
                    redacted_df = redacted_df.with_columns(
                        pl.when(pl.col("server").is_null() | (pl.col("server").cast(pl.Utf8) == ""))
                        .then(pl.lit("unknown"))
                        .otherwise(pl.col("server").cast(pl.Utf8))
                        .alias("server")
                    )
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
                _record_error(
                    errors,
                    "pipeline",
                    "dataset_processing_failed",
                    repr(exc),
                    redact_config=redact_config,
                )

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
    target = args.date if args.date is not None else datetime.now(UTC).date() - timedelta(days=1)
    asyncio.run(run_enrichment(target))

"""Main enrichment orchestrator — reads bronze, enriches, writes silver.

Daily workflow:
1. Read previous day's bronze NDJSON (already geo-enriched by Vector)
2. Extract unique source IPs and file hashes
3. Check SQLite cache, skip recently enriched
4. Query providers: AbuseIPDB → GreyNoise → Shodan → VirusTotal
5. Merge enrichment back into events
6. Redact infrastructure IPs (OPSEC Layer 2)
7. Write silver Parquet
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import polars as pl
import structlog

from lantana.common.config import load_reporting, load_secrets
from lantana.common.datalake import read_bronze_ndjson, write_silver_partition
from lantana.common.redact import RedactionConfig, redact_infrastructure_ips, validate_no_leaks
from lantana.enrichment.providers.abuseipdb import AbuseIPDBProvider
from lantana.enrichment.providers.base import EnrichmentError, EnrichmentResult
from lantana.enrichment.providers.greynoise import GreyNoiseProvider
from lantana.enrichment.providers.phishstats import PhishStatsProvider
from lantana.enrichment.providers.shodan import ShodanProvider
from lantana.enrichment.providers.virustotal import VirusTotalProvider
from lantana.models.normalize import normalize_dataset

logger = structlog.get_logger()

CACHE_DB_PATH = Path("/var/lib/lantana/datalake/.enrichment_cache.db")
CACHE_TTL_DAYS = 7
ERRORS_PATH = Path(
    os.environ.get("LANTANA_ENRICHMENT_ERRORS", "/var/lib/lantana/datalake/enrichment_errors.json")
)

DATASETS = ["cowrie", "suricata", "nftables", "dionaea"]


def _init_cache(db_path: Path) -> sqlite3.Connection:
    """Initialize the SQLite enrichment cache."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache ("
        "  key TEXT PRIMARY KEY,"
        "  provider TEXT NOT NULL,"
        "  data TEXT NOT NULL,"
        "  queried_at TEXT NOT NULL"
        ")"
    )
    conn.commit()
    return conn


def _get_cached(conn: sqlite3.Connection, key: str) -> EnrichmentResult | None:
    """Return the cached EnrichmentResult for a key, or None if absent/expired.

    A malformed cached row (provider name or data JSON that no longer
    deserializes cleanly) is treated as a miss so one bad row cannot
    poison a whole batch.
    """
    cutoff = (datetime.now(tz=UTC) - timedelta(days=CACHE_TTL_DAYS)).isoformat()
    row = conn.execute(
        "SELECT provider, data, queried_at FROM cache WHERE key = ? AND queried_at > ?",
        (key, cutoff),
    ).fetchone()
    if row is None:
        return None
    provider_name, data_json, queried_at_str = row
    try:
        return EnrichmentResult(
            provider=provider_name,
            ip=key.split(":", 1)[1] if ":" in key else key,
            data=json.loads(data_json),
            queried_at=datetime.fromisoformat(queried_at_str),
        )
    except (ValueError, json.JSONDecodeError):
        return None


def _set_cached(conn: sqlite3.Connection, result: EnrichmentResult) -> None:
    """Store an enrichment result in the cache."""
    conn.execute(
        "INSERT OR REPLACE INTO cache (key, provider, data, queried_at) VALUES (?, ?, ?, ?)",
        (
            f"{result.provider}:{result.ip}",
            result.provider,
            json.dumps(result.data),
            result.queried_at.isoformat(),
        ),
    )
    conn.commit()


def _extract_unique_ips(df: pl.DataFrame) -> list[str]:
    """Extract unique source IP addresses from the DataFrame."""
    src_col = "src_ip" if "src_ip" in df.columns else None
    if src_col is None:
        return []
    return df.get_column(src_col).drop_nulls().unique().cast(pl.Utf8).to_list()


def _filter_internal_ips(ips: list[str], config: RedactionConfig) -> list[str]:
    """Drop operation-owned IPs before any provider call.

    OPSEC Layer-1.5: even if Vector's source-IP filter (Layer 1) lets
    something through, we must never send a honeypot's own WAN address
    to AbuseIPDB / Shodan / VirusTotal.
    """
    infra_set = set(config.infrastructure_ips)
    cidr_nets = [ipaddress.ip_network(cidr) for cidr in config.infrastructure_cidrs]
    kept: list[str] = []
    for ip in ips:
        if ip in infra_set:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            kept.append(ip)
            continue
        if any(addr in net for net in cidr_nets):
            continue
        kept.append(ip)
    return kept


def _extract_unique_hashes(df: pl.DataFrame, sensor_dir: Path) -> list[str]:
    """Scan artifact directories for file hashes to enrich."""
    download_dirs = list(sensor_dir.glob("*/downloads")) + list(sensor_dir.glob("*/binaries"))
    hashes: set[str] = set()
    for download_dir in download_dirs:
        for file_path in download_dir.iterdir():
            if file_path.is_file() and file_path.stat().st_size <= 100 * 1024 * 1024:
                sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
                hashes.add(sha256)
    return list(hashes)


def _merge_enrichments(
    df: pl.DataFrame,
    enrichments: dict[str, list[EnrichmentResult]],
) -> pl.DataFrame:
    """Merge enrichment results back into the event DataFrame by source IP."""
    if df.is_empty():
        return df

    src_col = "src_ip" if "src_ip" in df.columns else None
    if src_col is None:
        return df

    # Build a lookup: ip → merged enrichment fields
    ip_data: dict[str, dict[str, str | int | float | bool | None]] = {}
    for results in enrichments.values():
        for result in results:
            if result.ip not in ip_data:
                ip_data[result.ip] = {}
            ip_data[result.ip].update(result.data)

    if not ip_data:
        return df

    # Build enrichment DataFrame
    enrichment_records = [{"_enrich_ip": ip, **data} for ip, data in ip_data.items()]
    enrich_df = pl.DataFrame(enrichment_records)

    # Join on source IP
    return df.join(
        enrich_df,
        left_on=src_col,
        right_on="_enrich_ip",
        how="left",
    )


ErrorAccumulator = dict[tuple[str, str], EnrichmentError]


def _classify_http_error(status_code: int) -> str:
    """Map HTTP status code to an error type label."""
    if status_code == 429:
        return "rate_limit"
    if status_code in (401, 403):
        return "auth"
    if 400 <= status_code < 500:
        return "http_4xx"
    return "http_5xx"


def _record_error(
    errors: ErrorAccumulator,
    provider: str,
    error_type: str,
    message: str,
) -> None:
    """Accumulate an error, incrementing count for repeated (provider, error_type)."""
    key = (provider, error_type)
    if key in errors:
        errors[key].count += 1
        errors[key].error_message = message
    else:
        errors[key] = EnrichmentError(
            provider=provider,
            error_type=error_type,
            error_message=message,
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
            line = json.dumps({
                "date": target_date.isoformat(),
                "provider": error.provider,
                "error_type": error.error_type,
                "count": error.count,
                "message": error.error_message,
            })
            f.write(line + "\n")


_ProviderType = (
    AbuseIPDBProvider | GreyNoiseProvider | PhishStatsProvider | ShodanProvider | VirusTotalProvider
)


async def _enrich_ips_with_provider(
    provider_name: str,
    provider: _ProviderType,
    ips: list[str],
    cache: sqlite3.Connection,
    errors: ErrorAccumulator,
) -> tuple[list[EnrichmentResult], int]:
    """Enrich a list of IPs with a single provider, respecting cache.

    Returns the combined results (cached + freshly queried) and the count
    of cache hits, so the caller can log fresh vs cached separately.
    """
    results: list[EnrichmentResult] = []
    cache_hits = 0
    for ip in ips:
        cache_key = f"{provider_name}:{ip}"
        cached = _get_cached(cache, cache_key)
        if cached is not None:
            results.append(cached)
            cache_hits += 1
            continue
        try:
            result = await provider.enrich_ip(ip)
            _set_cached(cache, result)
            results.append(result)
        except httpx.HTTPStatusError as exc:
            etype = _classify_http_error(exc.response.status_code)
            _record_error(errors, provider_name, etype, str(exc))
            logger.warning("enrichment_failed", provider=provider_name, ip=ip, error_type=etype)
        except httpx.TimeoutException:
            _record_error(errors, provider_name, "timeout", "request timed out")
            logger.warning("enrichment_failed", provider=provider_name, ip=ip, error_type="timeout")
        except Exception as exc:
            _record_error(errors, provider_name, "unknown", str(exc))
            logger.warning("enrichment_failed", provider=provider_name, ip=ip, error_type="unknown")
    return results, cache_hits


async def run_enrichment(
    target_date: date,
    cache_db_path: Path = CACHE_DB_PATH,
    sensor_dir: Path = Path("/var/lib/lantana/sensor"),
    errors_path: Path = ERRORS_PATH,
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

    # Initialize providers. GreyNoise and PhishStats are skipped when the
    # vault key is absent (None); empty strings keep them enabled in their
    # unauthenticated modes.
    providers: dict[str, _ProviderType] = {
        "abuseipdb": AbuseIPDBProvider(secrets.abuseipdb),
        "shodan": ShodanProvider(secrets.shodan),
        "virustotal": VirusTotalProvider(secrets.virustotal),
    }
    if secrets.greynoise is not None:
        providers["greynoise"] = GreyNoiseProvider(secrets.greynoise)
    else:
        logger.info("provider_disabled", provider="greynoise", reason="not_configured")
    if secrets.phishstats is not None:
        providers["phishstats"] = PhishStatsProvider(secrets.phishstats)
    else:
        logger.info("provider_disabled", provider="phishstats", reason="not_configured")

    try:
        for dataset in DATASETS:
            logger.info("enrichment_start", dataset=dataset, date=target_date.isoformat())

            df = read_bronze_ndjson(target_date, dataset=dataset)
            if df.is_empty():
                logger.info("enrichment_skip_empty", dataset=dataset)
                continue

            # Extract unique IPs and filter out operation-owned addresses (OPSEC)
            raw_ips = _extract_unique_ips(df)
            unique_ips = _filter_internal_ips(raw_ips, redact_config)
            filtered = len(raw_ips) - len(unique_ips)
            if filtered:
                logger.info("internal_ips_filtered", dataset=dataset, count=filtered)
            logger.info("unique_ips_found", dataset=dataset, count=len(unique_ips))

            # Enrich with each provider (sequential to respect rate limits)
            enrichments: dict[str, list[EnrichmentResult]] = {}
            for name, provider in providers.items():
                results, cache_hits = await _enrich_ips_with_provider(
                    name, provider, unique_ips, cache, errors,
                )
                enrichments[name] = results
                logger.info(
                    "provider_done",
                    provider=name,
                    enriched=len(results),
                    fresh=len(results) - cache_hits,
                    cache_hits=cache_hits,
                )

            # Enrich file hashes with VirusTotal
            if dataset in ("cowrie", "dionaea"):
                hashes = _extract_unique_hashes(df, sensor_dir)
                vt = providers["virustotal"]
                assert isinstance(vt, VirusTotalProvider)
                for sha256 in hashes:
                    cache_key = f"virustotal:{sha256}"
                    if not _get_cached(cache, cache_key):
                        try:
                            result = await vt.enrich_hash(sha256)
                            _set_cached(cache, result)
                        except httpx.HTTPStatusError as exc:
                            etype = _classify_http_error(exc.response.status_code)
                            _record_error(errors, "virustotal", etype, str(exc))
                            logger.warning(
                                "hash_enrichment_failed", sha256=sha256, error_type=etype,
                            )
                        except httpx.TimeoutException:
                            _record_error(errors, "virustotal", "timeout", "request timed out")
                            logger.warning(
                                "hash_enrichment_failed", sha256=sha256, error_type="timeout",
                            )
                        except Exception as exc:
                            _record_error(errors, "virustotal", "unknown", str(exc))
                            logger.warning(
                                "hash_enrichment_failed", sha256=sha256, error_type="unknown",
                            )

            # Merge enrichment data into events
            enriched_df = _merge_enrichments(df, enrichments)

            # OCSF normalization: rename columns to OCSF schema
            normalized_df = normalize_dataset(enriched_df, dataset)

            # OPSEC Layer 2: redact infrastructure IPs
            redacted_df = redact_infrastructure_ips(normalized_df, redact_config)

            # Validate no leaks before writing
            validate_no_leaks(redacted_df, redact_config)

            # Extract server from data for partitioning
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

            logger.info("enrichment_done", dataset=dataset, rows=len(redacted_df))

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

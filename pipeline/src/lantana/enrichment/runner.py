"""Main enrichment orchestrator -- reads bronze, enriches, writes silver.

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

import asyncio
import hashlib
import sqlite3
from datetime import date, datetime, timedelta
from datetime import timezone as tz
from pathlib import Path

import polars as pl
import structlog

from lantana.common.config import load_reporting, load_secrets
from lantana.common.datalake import read_bronze_ndjson, write_silver_partition
from lantana.common.redact import RedactionConfig, redact_infrastructure_ips, validate_no_leaks
from lantana.enrichment.providers.abuseipdb import AbuseIPDBProvider
from lantana.enrichment.providers.base import EnrichmentResult
from lantana.enrichment.providers.greynoise import GreyNoiseProvider
from lantana.enrichment.providers.shodan import ShodanProvider
from lantana.enrichment.providers.virustotal import VirusTotalProvider
from lantana.models.normalize import normalize_dataset

logger = structlog.get_logger()

CACHE_DB_PATH = Path("/var/lib/lantana/datalake/.enrichment_cache.db")
CACHE_TTL_DAYS = 7

DATASETS = ["cowrie", "suricata", "nftables"]


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


def _get_cached(conn: sqlite3.Connection, key: str) -> bool:
    """Check if a key was enriched within the TTL."""
    cutoff = (datetime.now(tz=tz.utc) - timedelta(days=CACHE_TTL_DAYS)).isoformat()
    row = conn.execute(
        "SELECT 1 FROM cache WHERE key = ? AND queried_at > ?",
        (key, cutoff),
    ).fetchone()
    return row is not None


def _set_cached(conn: sqlite3.Connection, result: EnrichmentResult) -> None:
    """Store an enrichment result in the cache."""
    import json

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
    return (
        df.get_column(src_col)
        .drop_nulls()
        .unique()
        .cast(pl.Utf8)
        .to_list()
    )


def _extract_unique_hashes(df: pl.DataFrame, sensor_dir: Path) -> list[str]:
    """Scan artifact directories for file hashes to enrich."""
    download_dirs = list(sensor_dir.glob("*/downloads"))
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


async def _enrich_ips_with_provider(
    provider_name: str,
    provider: AbuseIPDBProvider | GreyNoiseProvider | ShodanProvider | VirusTotalProvider,
    ips: list[str],
    cache: sqlite3.Connection,
) -> list[EnrichmentResult]:
    """Enrich a list of IPs with a single provider, respecting cache."""
    results: list[EnrichmentResult] = []
    for ip in ips:
        cache_key = f"{provider_name}:{ip}"
        if _get_cached(cache, cache_key):
            continue
        try:
            result = await provider.enrich_ip(ip)
            _set_cached(cache, result)
            results.append(result)
        except Exception:
            logger.warning("enrichment_failed", provider=provider_name, ip=ip)
    return results


async def run_enrichment(
    target_date: date,
    cache_db_path: Path = CACHE_DB_PATH,
    sensor_dir: Path = Path("/var/lib/lantana/sensor"),
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

    # Initialize providers
    providers: dict[
        str,
        AbuseIPDBProvider | GreyNoiseProvider | ShodanProvider | VirusTotalProvider,
    ] = {
        "abuseipdb": AbuseIPDBProvider(secrets.abuseipdb),
        "greynoise": GreyNoiseProvider(secrets.greynoise),
        "shodan": ShodanProvider(secrets.shodan),
        "virustotal": VirusTotalProvider(secrets.virustotal),
    }

    try:
        for dataset in DATASETS:
            logger.info("enrichment_start", dataset=dataset, date=target_date.isoformat())

            df = read_bronze_ndjson(target_date, dataset=dataset)
            if df.is_empty():
                logger.info("enrichment_skip_empty", dataset=dataset)
                continue

            # Extract unique IPs
            unique_ips = _extract_unique_ips(df)
            logger.info("unique_ips_found", dataset=dataset, count=len(unique_ips))

            # Enrich with each provider (sequential to respect rate limits)
            enrichments: dict[str, list[EnrichmentResult]] = {}
            for name, provider in providers.items():
                results = await _enrich_ips_with_provider(name, provider, unique_ips, cache)
                enrichments[name] = results
                logger.info("provider_done", provider=name, enriched=len(results))

            # Enrich file hashes with VirusTotal
            if dataset == "cowrie":
                hashes = _extract_unique_hashes(df, sensor_dir)
                vt = providers["virustotal"]
                assert isinstance(vt, VirusTotalProvider)
                for sha256 in hashes:
                    cache_key = f"virustotal:{sha256}"
                    if not _get_cached(cache, cache_key):
                        try:
                            result = await vt.enrich_hash(sha256)
                            _set_cached(cache, result)
                        except Exception:
                            logger.warning("hash_enrichment_failed", sha256=sha256)

            # Merge enrichment data into events
            enriched_df = _merge_enrichments(df, enrichments)

            # OCSF normalization: rename columns to OCSF schema
            normalized_df = normalize_dataset(enriched_df, dataset)

            # OPSEC Layer 2: redact infrastructure IPs
            redacted_df = redact_infrastructure_ips(normalized_df, redact_config)

            # Validate no leaks before writing
            validate_no_leaks(redacted_df, redact_config)

            # Extract server from data for partitioning
            servers = redacted_df.get_column("server").unique().to_list() if "server" in redacted_df.columns else ["unknown"]
            for server in servers:
                server_df = redacted_df.filter(pl.col("server") == server) if len(servers) > 1 else redacted_df
                write_silver_partition(server_df, target_date, dataset, str(server))

            logger.info("enrichment_done", dataset=dataset, rows=len(redacted_df))

    finally:
        for provider in providers.values():
            await provider.close()
        cache.close()


def main() -> None:
    """CLI entry point for lantana-enrich."""
    yesterday = date.today() - timedelta(days=1)
    asyncio.run(run_enrichment(yesterday))

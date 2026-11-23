"""Gold metric computation functions.

Pure DataFrame transforms that aggregate silver-layer events into
intelligence-ready gold tables. Each function accepts a collected
DataFrame (not LazyFrame) and returns a new DataFrame with explicit
stable schemas.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import polars as pl

from lantana.common.redact import RedactionConfig
from lantana.enrichment.allowlist import (
    GTI_CORROBORATING_VERDICTS,
    VT_URL_MIN_MALICIOUS,
    evaluate_ioc_verification,
    parse_normalized_ip,
)
from lantana.enrichment.ioc import (
    extract_outbound_c2_ips,
    extract_outbound_urls,
    extract_ssh_public_keys,
    extract_stager_domains,
)
from lantana.models.ocsf import (
    CLASS_AUTHENTICATION,
    CLASS_DETECTION_FINDING,
    CLASS_FILE_ACTIVITY,
    CLASS_NETWORK_ACTIVITY,
    CLASS_PROCESS_ACTIVITY,
    STATUS_FAILURE,
    STATUS_SUCCESS,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from lantana.common.config import StixExportConfig

# Behavioral progression stage constants
STAGE_SCAN: int = 1
STAGE_CREDENTIAL: int = 2
STAGE_AUTHENTICATED: int = 3
STAGE_INTERACTIVE: int = 4

STAGE_LABELS: dict[int, str] = {
    STAGE_SCAN: "scan",
    STAGE_CREDENTIAL: "credential",
    STAGE_AUTHENTICATED: "authenticated",
    STAGE_INTERACTIVE: "interactive",
}

# Top-N limits
TOP_N: int = 10
DETECTION_FINDINGS_TOP_N: int = 100

# Suricata internal decoder/stream/app-layer-event noise SID range.
# Excluded from findings_detected, behavioral_risk_score, and detection_findings.
DECODER_SID_MIN: int = 2200000
DECODER_SID_MAX: int = 2260999

# Behavioral risk-score weights (sum to 100.0 max: 25 + 25 + 25 + 15 + 10).
BEHAVIORAL_AUTH_FACTOR: float = 25.0
BEHAVIORAL_COMMAND_FACTOR: float = 25.0
BEHAVIORAL_DOWNLOAD_FACTOR: float = 25.0
BEHAVIORAL_FINDING_FACTOR: float = 15.0
BEHAVIORAL_AUTH_ATTEMPT_CAP: float = 100.0
BEHAVIORAL_AUTH_ATTEMPT_WEIGHT: float = 0.1
SCANNER_ENRICHMENT_SCALE: float = 0.35

# Automated-actor heuristic thresholds (compute_behavioral_progression).
AUTOMATED_AUTH_ATTEMPTS_MIN: int = 10
AUTOMATED_UNIQUE_PASSWORDS_MIN: int = 5
AUTOMATED_WINDOW_SECONDS_MAX: int = 120

# Explicit Polars list schemas so empty days never write List(Null) Parquet.
_TOP_VALUE_LIST_DTYPE: pl.DataType = pl.List(pl.Struct({"value": pl.Utf8(), "count": pl.Int64()}))
_TOP_CRED_PAIR_LIST_DTYPE: pl.DataType = pl.List(
    pl.Struct({"username": pl.Utf8(), "password": pl.Utf8(), "count": pl.Int64()})
)
_UTF8_LIST_DTYPE: pl.DataType = pl.List(pl.Utf8())

EXTRACTED_IOCS_SCHEMA: dict[str, pl.DataType] = {
    "ioc_type": pl.Utf8(),
    "ioc_value": pl.Utf8(),
    "vhash": pl.Utf8(),
    "first_seen": pl.Datetime(time_unit="us", time_zone="UTC"),
    "last_seen": pl.Datetime(time_unit="us", time_zone="UTC"),
    "event_count": pl.Int64(),
    "unique_src_ips": pl.Int64(),
    "vt_status": pl.Utf8(),
    "vt_malicious": pl.Int64(),
    "gti_verdict": pl.Utf8(),
    "gti_score": pl.Int64(),
    "malware_family": pl.Utf8(),
    "actor_associations": pl.Utf8(),
    "verification_status": pl.Utf8(),
    "verification_reason": pl.Utf8(),
}

# Dataset-specific columns that gold aggregations reference.
_OPTIONAL_GOLD_COLUMNS: dict[str, pl.DataType] = {
    "session": pl.Utf8(),
    "user_name": pl.Utf8(),
    "unmapped_password": pl.Utf8(),
    "actor_process_cmd_line": pl.Utf8(),
    "file_url": pl.Utf8(),
    "file_path": pl.Utf8(),
    "file_hash_sha256": pl.Utf8(),
    "file_name": pl.Utf8(),
    "file_intent": pl.Utf8(),
    "finding_title": pl.Utf8(),
    "finding_uid": pl.Utf8(),
    "finding_category": pl.Utf8(),
    "flow_id": pl.Int64(),
}


def _ensure_gold_columns(silver: pl.DataFrame) -> pl.DataFrame:
    """Backfill optional gold columns as typed nulls when absent."""
    missing = [
        pl.lit(None, dtype=dtype).alias(name)
        for name, dtype in _OPTIONAL_GOLD_COLUMNS.items()
        if name not in silver.columns
    ]
    return silver.with_columns(missing) if missing else silver


def _optional_first(
    df: pl.DataFrame,
    col: str,
    alias: str,
    dtype: pl.DataType | None = None,
) -> pl.Expr:
    """Return first non-null value for a column, or a typed null literal if absent."""
    if col in df.columns:
        expr = pl.col(col).drop_nulls().first()
        if dtype is not None and df.schema.get(col) == pl.Null:
            expr = expr.cast(dtype)
        return expr.alias(alias)
    if dtype is not None:
        return pl.lit(None, dtype=dtype).alias(alias)
    return pl.lit(None).alias(alias)


def _is_real_finding_expr() -> pl.Expr:
    """True for Detection Finding rows outside Suricata's decoder SID range (2200000-2260999)."""
    sid_int = pl.col("finding_uid").cast(pl.Int64, strict=False)
    is_decoder = sid_int.is_between(DECODER_SID_MIN, DECODER_SID_MAX).fill_null(False)
    return (pl.col("class_uid") == CLASS_DETECTION_FINDING) & ~is_decoder


def _is_non_probe_download_expr() -> pl.Expr:
    """True for File Activity rows excluding probe writes (``file_intent == 'probe'``)."""
    return (pl.col("class_uid") == CLASS_FILE_ACTIVITY) & (
        pl.col("file_intent").fill_null("malware") != "probe"
    )


def _filter_valid_src_ip(silver: pl.DataFrame) -> pl.DataFrame:
    """Drop rows without a non-empty source IP (e.g. unattributed Dionaea disk captures)."""
    if "src_endpoint_ip" not in silver.columns:
        return silver.clear()
    return silver.filter(
        pl.col("src_endpoint_ip").is_not_null() & (pl.col("src_endpoint_ip").cast(pl.Utf8) != "")
    )


def _top_n(df: pl.DataFrame, col: str, n: int = TOP_N) -> list[dict[str, str | int]]:
    """Top-N most frequent non-null values + their event counts, ranked by count."""
    if col not in df.columns:
        return []
    return (
        df.select(col)
        .drop_nulls()
        .filter(pl.col(col) != "")
        .group_by(col)
        .len()
        .sort("len", descending=True)
        .head(n)
        .rename({col: "value", "len": "count"})
        .to_dicts()
    )


def _top_n_credential_pairs(df: pl.DataFrame, n: int = TOP_N) -> list[dict[str, str | int]]:
    """Top-N username/password pairs, ranked by event count."""
    if "user_name" not in df.columns or "unmapped_password" not in df.columns:
        return []
    return (
        df.filter(
            pl.col("user_name").is_not_null()
            & pl.col("unmapped_password").is_not_null()
            & (pl.col("user_name") != "")
            & (pl.col("unmapped_password") != "")
        )
        .group_by("user_name", "unmapped_password")
        .len()
        .sort("len", descending=True)
        .head(n)
        .rename({"user_name": "username", "unmapped_password": "password", "len": "count"})
        .to_dicts()
    )


def _top_n_countries_by_unique_ips(df: pl.DataFrame, n: int = TOP_N) -> list[dict[str, str | int]]:
    """Top-N source countries + unique-IP counts (null src IPs excluded)."""
    if "geo.country_code" not in df.columns or "src_endpoint_ip" not in df.columns:
        return []
    return (
        df.filter(
            pl.col("geo.country_code").is_not_null() & pl.col("src_endpoint_ip").is_not_null()
        )
        .group_by("geo.country_code")
        .agg(pl.col("src_endpoint_ip").n_unique().alias("count"))
        .sort("count", descending=True)
        .head(n)
        .rename({"geo.country_code": "value"})
        .to_dicts()
    )


def compute_daily_summary(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute daily summary statistics from silver-layer data.

    Excludes null ``src_endpoint_ip`` from ``unique_source_ips`` and excludes
    Suricata decoder SIDs (2200000-2260999) from ``findings_detected``.
    Pins explicit Polars struct-list schemas so empty lists never serialize
    as ``List(Null)``.
    """
    if silver.is_empty():
        return pl.DataFrame()

    silver = _ensure_gold_columns(silver)

    cls = pl.col("class_uid")
    sts = pl.col("status_id")
    real_finding = _is_real_finding_expr()

    scalars = silver.select(
        pl.len().alias("total_events"),
        pl.col("src_endpoint_ip").drop_nulls().n_unique().alias("unique_source_ips"),
        pl.col("session").drop_nulls().n_unique().alias("unique_sessions"),
        (cls == CLASS_AUTHENTICATION).sum().alias("auth_attempts"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS)).sum().alias("auth_successes"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_FAILURE)).sum().alias("auth_failures"),
        (cls == CLASS_PROCESS_ACTIVITY).sum().alias("commands_executed"),
        real_finding.sum().alias("findings_detected"),
        (cls == CLASS_NETWORK_ACTIVITY).sum().alias("network_events"),
        (cls == CLASS_FILE_ACTIVITY).sum().alias("downloads_captured"),
    )

    has_real_intent = (
        "file_intent" in silver.columns
        and silver.get_column("file_intent").null_count() < silver.height
    )
    if has_real_intent:
        malware_silver = silver.filter(pl.col("file_intent") == "malware")
    else:
        malware_silver = silver

    lists = pl.DataFrame(
        {
            "top_usernames": [_top_n(silver, "user_name")],
            "top_passwords": [_top_n(silver, "unmapped_password")],
            "top_credential_pairs": [_top_n_credential_pairs(silver)],
            "top_commands": [_top_n(silver, "actor_process_cmd_line")],
            "top_source_countries": [_top_n_countries_by_unique_ips(silver)],
            "top_source_ips": [_top_n(silver, "src_endpoint_ip")],
            "top_download_urls": [_top_n(malware_silver, "file_url")],
            "top_download_hashes": [_top_n(malware_silver, "file_hash_sha256")],
        },
        schema={
            "top_usernames": _TOP_VALUE_LIST_DTYPE,
            "top_passwords": _TOP_VALUE_LIST_DTYPE,
            "top_credential_pairs": _TOP_CRED_PAIR_LIST_DTYPE,
            "top_commands": _TOP_VALUE_LIST_DTYPE,
            "top_source_countries": _TOP_VALUE_LIST_DTYPE,
            "top_source_ips": _TOP_VALUE_LIST_DTYPE,
            "top_download_urls": _TOP_VALUE_LIST_DTYPE,
            "top_download_hashes": _TOP_VALUE_LIST_DTYPE,
        },
    )

    return pl.concat([scalars, lists], how="horizontal")


def compute_ip_reputation(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute per-IP reputation scores using the behavioral-anchored monotonic formula.

    Filters out null/empty ``src_endpoint_ip`` rows, excludes Suricata decoder
    SIDs (2200000-2260999) from ``findings_triggered``, and excludes
    ``file_intent == "probe"`` from download behavioral risk weight.

    Scoring (0..100, clipped):
    * ``behavioral_risk_score`` (0..100):
        +25 auth_successes > 0
        +25 commands_executed > 0
        +25 non-probe downloads > 0
        +15 real findings > 0
        +min(auth_attempts, 100) * 0.1
    * ``enrichment_risk_score`` (0..100 or null):
        horizontal mean of non-null per-provider scores
    * ``risk_score`` (monotonic behavioral-anchored composite):
        - Pure scan (``behavioral == 0``):
            ``0.0`` if RIOT or GreyNoise ``benign``,
            else ``enrichment.fill_null(0.0) * 0.35`` (capped at 35, never enters STIX)
        - Interactive / credential activity (``behavioral > 0``):
            ``behavioral / 2.0`` if RIOT or GreyNoise ``benign`` (FP brake),
            else ``max(behavioral, 0.5 * behavioral + 0.5 * enrichment)`` when
            enrichment is present, or ``behavioral`` when enrichment is null.
    """
    if silver.is_empty():
        return pl.DataFrame()

    silver = _filter_valid_src_ip(_ensure_gold_columns(silver))
    if silver.is_empty():
        return pl.DataFrame()

    cls = pl.col("class_uid")
    sts = pl.col("status_id")
    real_finding = _is_real_finding_expr()
    real_download = _is_non_probe_download_expr()

    core_aggs: list[pl.Expr] = [
        pl.len().alias("total_events"),
        pl.col("dataset").unique().alias("datasets"),
        (cls == CLASS_AUTHENTICATION).sum().alias("auth_attempts"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS)).sum().alias("auth_successes"),
        pl.col("user_name").drop_nulls().n_unique().alias("unique_usernames"),
        pl.col("unmapped_password").drop_nulls().n_unique().alias("unique_passwords"),
        (cls == CLASS_PROCESS_ACTIVITY).sum().alias("commands_executed"),
        real_finding.sum().alias("findings_triggered"),
        real_download.sum().alias("downloads"),
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
        _optional_first(silver, "geo.country_code", "geo_country", pl.Utf8()),
        _optional_first(silver, "geo.asn", "geo_asn"),
        _optional_first(silver, "geo.isp", "geo_isp", pl.Utf8()),
    ]

    optional: list[tuple[str, str, pl.DataType]] = [
        ("geo.city", "geo_city", pl.Utf8()),
        ("geo.latitude", "geo_latitude", pl.Float64()),
        ("geo.longitude", "geo_longitude", pl.Float64()),
        ("abuseipdb_confidence_score", "abuseipdb_score", pl.Int64()),
        ("abuseipdb_total_reports", "abuseipdb_reports", pl.Int64()),
        ("greynoise_classification", "greynoise_class", pl.Utf8()),
        ("greynoise_name", "greynoise_name", pl.Utf8()),
        ("greynoise_noise", "greynoise_noise", pl.Boolean()),
        ("greynoise_riot", "greynoise_riot", pl.Boolean()),
        ("shodan_ports", "shodan_ports", pl.Utf8()),
        ("shodan_os", "shodan_os", pl.Utf8()),
        ("shodan_vulns", "shodan_vulns", pl.Utf8()),
        ("shodan_org", "shodan_org", pl.Utf8()),
        ("vt_malicious_count", "vt_malicious", pl.Int64()),
        ("vt_ip_reputation", "vt_reputation", pl.Int64()),
        ("gti_verdict", "gti_verdict", pl.Utf8()),
        ("gti_score", "gti_score", pl.Int64()),
        ("gti_threat_actors", "gti_threat_actors", pl.Utf8()),
        ("abuseipdb_risk_score", "abuseipdb_risk_score", pl.Float64()),
        ("virustotal_risk_score", "virustotal_risk_score", pl.Float64()),
        ("shodan_risk_score", "shodan_risk_score", pl.Float64()),
        ("greynoise_risk_score", "greynoise_risk_score", pl.Float64()),
    ]
    enrichment_aggs = [_optional_first(silver, col, alias, dt) for col, alias, dt in optional]

    grouped = silver.group_by("src_endpoint_ip").agg(core_aggs + enrichment_aggs)

    behavioral_expr = (
        pl.when(pl.col("auth_successes") > 0).then(BEHAVIORAL_AUTH_FACTOR).otherwise(0.0)
        + pl.when(pl.col("commands_executed") > 0).then(BEHAVIORAL_COMMAND_FACTOR).otherwise(0.0)
        + pl.when(pl.col("findings_triggered") > 0).then(BEHAVIORAL_FINDING_FACTOR).otherwise(0.0)
        + pl.when(pl.col("downloads") > 0).then(BEHAVIORAL_DOWNLOAD_FACTOR).otherwise(0.0)
        + pl.min_horizontal(
            pl.col("auth_attempts").cast(pl.Float64),
            pl.lit(BEHAVIORAL_AUTH_ATTEMPT_CAP),
        )
        * BEHAVIORAL_AUTH_ATTEMPT_WEIGHT
    ).clip(0.0, 100.0)

    enrichment_expr = pl.mean_horizontal(
        pl.col("abuseipdb_risk_score").cast(pl.Float64).clip(0.0, 100.0),
        pl.col("virustotal_risk_score").cast(pl.Float64).clip(0.0, 100.0),
        pl.col("shodan_risk_score").cast(pl.Float64).clip(0.0, 100.0),
        pl.col("greynoise_risk_score").cast(pl.Float64).clip(0.0, 100.0),
    ).clip(0.0, 100.0)

    is_benign_or_riot = pl.col("greynoise_riot").fill_null(False) | (
        pl.col("greynoise_class").fill_null("") == "benign"
    )
    b = pl.col("behavioral_risk_score")
    e = pl.col("enrichment_risk_score")
    composite_expr = (
        pl.when(b <= 0.0)
        .then(
            pl.when(is_benign_or_riot)
            .then(pl.lit(0.0))
            .otherwise(e.fill_null(0.0) * SCANNER_ENRICHMENT_SCALE)
        )
        .when(is_benign_or_riot)
        .then(b / 2.0)
        .when(e.is_not_null())
        .then(pl.max_horizontal(b, 0.5 * b + 0.5 * e))
        .otherwise(b)
        .clip(0.0, 100.0)
    )

    result = grouped.with_columns(
        enrichment_expr.alias("enrichment_risk_score"),
        behavioral_expr.alias("behavioral_risk_score"),
    ).with_columns(composite_expr.alias("risk_score"))

    return result.sort(
        ["risk_score", "behavioral_risk_score", "enrichment_risk_score"],
        descending=[True, True, True],
        nulls_last=True,
    )


def compute_behavioral_progression(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute attacker behavioral progression metrics (excluding null source IPs)."""
    if silver.is_empty():
        return pl.DataFrame()

    silver = _filter_valid_src_ip(_ensure_gold_columns(silver))
    if silver.is_empty():
        return pl.DataFrame()

    cls = pl.col("class_uid")
    sts = pl.col("status_id")

    grouped = silver.group_by("src_endpoint_ip").agg(
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
        (cls == CLASS_NETWORK_ACTIVITY).sum().alias("scan_events"),
        (cls == CLASS_AUTHENTICATION).sum().alias("auth_attempts"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS)).sum().alias("auth_successes"),
        (cls == CLASS_PROCESS_ACTIVITY).sum().alias("commands_executed"),
        pl.col("session").drop_nulls().n_unique().alias("unique_sessions"),
        pl.col("unmapped_password").drop_nulls().n_unique().alias("unique_passwords"),
        pl.col("time").filter(cls == CLASS_AUTHENTICATION).min().alias("first_auth_time"),
        pl.col("time")
        .filter((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS))
        .min()
        .alias("first_success_time"),
        pl.col("time").filter(cls == CLASS_PROCESS_ACTIVITY).min().alias("first_command_time"),
        _optional_first(silver, "greynoise_noise", "greynoise_noise", pl.Boolean()),
    )

    result = grouped.with_columns(
        pl.when(pl.col("commands_executed") > 0)
        .then(pl.lit(STAGE_INTERACTIVE))
        .when(pl.col("auth_successes") > 0)
        .then(pl.lit(STAGE_AUTHENTICATED))
        .when(pl.col("auth_attempts") > 0)
        .then(pl.lit(STAGE_CREDENTIAL))
        .otherwise(pl.lit(STAGE_SCAN))
        .alias("max_stage"),
    )

    result = result.with_columns(
        pl.col("max_stage").replace_strict(STAGE_LABELS, default="unknown").alias("stage_label"),
    )

    result = result.with_columns(
        pl.when(pl.col("first_auth_time").is_not_null())
        .then((pl.col("first_auth_time") - pl.col("first_seen")).dt.total_seconds().cast(pl.Int64))
        .otherwise(pl.lit(None, dtype=pl.Int64))
        .alias("seconds_to_auth"),
        pl.when(
            pl.col("first_success_time").is_not_null() & pl.col("first_auth_time").is_not_null()
        )
        .then(
            (pl.col("first_success_time") - pl.col("first_auth_time"))
            .dt.total_seconds()
            .cast(pl.Int64)
        )
        .otherwise(pl.lit(None, dtype=pl.Int64))
        .alias("seconds_to_success"),
        pl.when(
            pl.col("first_command_time").is_not_null() & pl.col("first_success_time").is_not_null()
        )
        .then(
            (pl.col("first_command_time") - pl.col("first_success_time"))
            .dt.total_seconds()
            .cast(pl.Int64)
        )
        .otherwise(pl.lit(None, dtype=pl.Int64))
        .alias("seconds_to_command"),
    )

    time_window = (pl.col("last_seen") - pl.col("first_seen")).dt.total_seconds()
    result = result.with_columns(
        (
            (
                (pl.col("auth_attempts") > AUTOMATED_AUTH_ATTEMPTS_MIN)
                & (pl.col("unique_passwords") > AUTOMATED_UNIQUE_PASSWORDS_MIN)
                & (time_window <= AUTOMATED_WINDOW_SECONDS_MAX)
            )
            | (pl.col("greynoise_noise").fill_null(False))
        ).alias("is_automated"),
    )

    result = result.drop(
        "first_auth_time",
        "first_success_time",
        "first_command_time",
        "unique_passwords",
        "greynoise_noise",
    )

    return result.sort("max_stage", descending=True)


def compute_campaign_clusters(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute campaign clusters from shared credential pairs (>= 2 unique IPs)."""
    if silver.is_empty():
        return pl.DataFrame()

    silver = _filter_valid_src_ip(_ensure_gold_columns(silver))
    if silver.is_empty():
        return pl.DataFrame()

    auth = silver.filter(
        (pl.col("class_uid") == CLASS_AUTHENTICATION)
        & pl.col("user_name").is_not_null()
        & pl.col("unmapped_password").is_not_null()
        & (pl.col("user_name") != "")
        & (pl.col("unmapped_password") != "")
    )

    if auth.is_empty():
        return pl.DataFrame()

    clusters = auth.group_by("user_name", "unmapped_password").agg(
        pl.col("src_endpoint_ip").unique().alias("ips"),
        pl.col("src_endpoint_ip").n_unique().alias("ip_count"),
        pl.len().alias("total_events"),
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
    )

    clusters = clusters.filter(pl.col("ip_count") >= 2)
    if clusters.is_empty():
        return pl.DataFrame()

    clusters = clusters.with_columns(
        pl.struct("user_name", "unmapped_password")
        .map_elements(
            lambda row: hashlib.sha256(
                f"{row['user_name']}:{row['unmapped_password']}".encode()
            ).hexdigest()[:12],
            return_dtype=pl.Utf8,
        )
        .alias("cluster_id"),
    )

    clusters = clusters.rename(
        {
            "user_name": "shared_username",
            "unmapped_password": "shared_password",
        }
    )

    return clusters.select(
        "cluster_id",
        "shared_username",
        "shared_password",
        "ip_count",
        "ips",
        "total_events",
        "first_seen",
        "last_seen",
    ).sort("ip_count", descending=True)


def compute_geographic_summary(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute geographic distribution of attack origins with explicit Utf8 list schemas."""
    if silver.is_empty() or "geo.country_code" not in silver.columns:
        return pl.DataFrame()

    valid = _filter_valid_src_ip(silver)
    if valid.is_empty():
        return pl.DataFrame()

    countries = (
        valid.filter(pl.col("geo.country_code").is_not_null())
        .group_by("geo.country_code")
        .agg(
            pl.col("src_endpoint_ip").n_unique().alias("unique_ips"),
            pl.len().alias("total_events"),
        )
        .sort("unique_ips", descending=True)
        .head(TOP_N)
    )
    top_countries = (
        countries.select(
            pl.concat_str(
                [pl.col("geo.country_code"), pl.lit(":"), pl.col("unique_ips").cast(pl.Utf8)],
                separator="",
            ).alias("entry")
        )
        .get_column("entry")
        .to_list()
    )

    top_cities: list[str] = []
    if "geo.city" in valid.columns:
        city_group_cols = [
            c
            for c in ("geo.city", "geo.country_code", "geo.latitude", "geo.longitude")
            if c in valid.columns
        ]
        cities = (
            valid.filter(pl.col("geo.city").is_not_null() & (pl.col("geo.city") != ""))
            .group_by(city_group_cols)
            .agg(
                pl.col("src_endpoint_ip").n_unique().alias("unique_ips"),
                pl.len().alias("total_events"),
            )
            .sort("unique_ips", descending=True)
            .head(20)
        )
        top_cities = (
            cities.select(
                pl.concat_str(
                    [
                        pl.col("geo.city"),
                        pl.lit(","),
                        pl.col("geo.country_code"),
                        pl.lit(":"),
                        pl.col("unique_ips").cast(pl.Utf8),
                    ],
                    separator="",
                ).alias("entry")
            )
            .get_column("entry")
            .to_list()
        )

    top_asns: list[str] = []
    if "geo.asn" in valid.columns:
        if "geo.isp" not in valid.columns:
            valid = valid.with_columns(pl.lit(None, dtype=pl.Utf8).alias("geo.isp"))
        asns = (
            valid.filter(pl.col("geo.asn").is_not_null())
            .group_by("geo.asn", "geo.isp")
            .agg(
                pl.col("src_endpoint_ip").n_unique().alias("unique_ips"),
                pl.len().alias("total_events"),
            )
            .sort("unique_ips", descending=True)
            .head(TOP_N)
        )
        top_asns = (
            asns.select(
                pl.concat_str(
                    [
                        pl.col("geo.asn").cast(pl.Utf8),
                        pl.lit("|"),
                        pl.col("geo.isp").fill_null(""),
                        pl.lit(":"),
                        pl.col("unique_ips").cast(pl.Utf8),
                    ],
                    separator="",
                ).alias("entry")
            )
            .get_column("entry")
            .to_list()
        )

    return pl.DataFrame(
        {
            "top_countries": [top_countries],
            "top_cities": [top_cities],
            "top_asns": [top_asns],
        },
        schema={
            "top_countries": _UTF8_LIST_DTYPE,
            "top_cities": _UTF8_LIST_DTYPE,
            "top_asns": _UTF8_LIST_DTYPE,
        },
    )


def compute_detection_findings(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute detection finding statistics from Suricata alerts.

    Excludes Suricata stream/decoder SIDs (2200000-2260999), preserves
    ``finding_uid`` in gold, and retains up to 100 rules per day.
    """
    if silver.is_empty() or "finding_title" not in silver.columns:
        return pl.DataFrame()

    silver = _ensure_gold_columns(silver)
    findings = silver.filter(_is_real_finding_expr() & pl.col("finding_title").is_not_null())
    if findings.is_empty():
        return pl.DataFrame()

    aggs: list[pl.Expr] = [
        pl.col("finding_uid").drop_nulls().first().cast(pl.Utf8).alias("finding_uid"),
        pl.len().alias("event_count"),
        pl.col("src_endpoint_ip").drop_nulls().n_unique().alias("unique_ips"),
        pl.col("severity_id").mode().first().alias("severity_id"),
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
        pl.col("finding_category").drop_nulls().first().cast(pl.Utf8).alias("category"),
    ]

    result = findings.group_by("finding_title").agg(aggs)
    return result.sort("event_count", descending=True).head(DETECTION_FINDINGS_TOP_N)


def _ensure_utc_dt(value: object) -> datetime | None:
    """Normalize a timestamp value to UTC-aware datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return None


def _opt_str(val: object) -> str | None:
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def _opt_int(val: object) -> int | None:
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val)
    return None


def compute_extracted_iocs(
    silver: pl.DataFrame,
    *,
    redact_config: RedactionConfig | None = None,
    enrichment_lookup: Mapping[tuple[str, str], Mapping[str, object]] | None = None,
    stix_config: StixExportConfig | None = None,
) -> pl.DataFrame:
    """Build the 7th Gold table: one row per durable daily observable.

    Durable IOC types:
      * ``malware_hash``  — all non-probe, non-persistence SHA-256 captures
      * ``c2_ip``         — external outbound C2 / payload-staging IPs
      * ``stager_url``    — external post-auth stager URLs
      * ``stager_domain`` — external domain names from post-auth stager URLs
      * ``ssh_key``       — persistent OpenSSH public-key fingerprints

    Retains all raw non-infrastructure extractions for analyst visibility while
    tagging every row with ``verification_status`` (``verified`` | ``unverified``
    | ``suppressed``) and ``verification_reason`` to prevent STIX feed poisoning.
    """
    if silver.is_empty():
        return pl.DataFrame(schema=EXTRACTED_IOCS_SCHEMA)

    silver = _ensure_gold_columns(silver)
    cfg = redact_config if redact_config is not None else RedactionConfig()
    lookup = enrichment_lookup or {}
    allow_domains = stix_config.allowlist_domains if stix_config is not None else ()
    allow_ips = stix_config.allowlist_ips if stix_config is not None else ()

    # Accumulator keyed by (ioc_type, ioc_value)
    acc: dict[tuple[str, str], dict[str, object]] = {}

    def _touch(
        ioc_type: str,
        ioc_value: str,
        ts: datetime | None,
        src_ip: str | None,
        meta: Mapping[str, object] | None = None,
    ) -> None:
        key = (ioc_type, ioc_value)
        entry = acc.get(key)
        if entry is None:
            entry = {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "vhash": None,
                "first_seen": ts,
                "last_seen": ts,
                "event_count": 0,
                "src_ips": set(),
                "vt_status": None,
                "vt_malicious": None,
                "gti_verdict": None,
                "gti_score": None,
                "malware_family": None,
                "actor_associations": None,
            }
            acc[key] = entry
        prev_count = entry["event_count"]
        entry["event_count"] = (prev_count if isinstance(prev_count, int) else 0) + 1
        if ts is not None:
            fs = entry["first_seen"]
            ls = entry["last_seen"]
            if fs is None or (isinstance(fs, datetime) and ts < fs):
                entry["first_seen"] = ts
            if ls is None or (isinstance(ls, datetime) and ts > ls):
                entry["last_seen"] = ts
        if src_ip:
            ips_set = entry["src_ips"]
            if isinstance(ips_set, set):
                ips_set.add(src_ip)
        if meta:
            for field in (
                "vhash",
                "vt_status",
                "vt_malicious",
                "gti_verdict",
                "gti_score",
                "malware_family",
                "actor_associations",
            ):
                if entry.get(field) is None and meta.get(field) is not None:
                    entry[field] = meta[field]

    # 1. Malware hashes (all daily non-probe, non-persistence file captures)
    file_cols = [
        c
        for c in (
            "dataset",
            "class_uid",
            "activity_id",
            "file_intent",
            "file_hash_sha256",
            "file_url",
            "time",
            "src_endpoint_ip",
            "vt_file_vhash",
            "vt_status",
            "vt_file_malicious_count",
            "vt_file_family",
            "gti_verdict",
            "gti_score",
            "gti_malware_families",
            "gti_threat_actors",
        )
        if c in silver.columns
    ]
    malware_rows = silver.filter(
        (pl.col("class_uid") == CLASS_FILE_ACTIVITY)
        & pl.col("file_hash_sha256").is_not_null()
        & (pl.col("file_hash_sha256") != "")
        & (~pl.col("file_intent").fill_null("malware").is_in(["probe", "persistence"]))
    )
    # Track outbound download URLs and IP-literal hosts corroborated by an actual
    # non-upload malware download whose SHA-256 itself has VT/GTI corroboration.
    # Excludes inbound Dionaea HTTP/SMB uploads (dataset == "dionaea" / activity_id != 2)
    # so an unauthenticated attacker cannot forge captured_artifact=True via an
    # arbitrary POST request line.
    captured_urls: set[str] = set()
    captured_c2_ips: set[str] = set()
    for row in malware_rows.select(file_cols).iter_rows(named=True):
        sha = str(row["file_hash_sha256"])
        cached = lookup.get(("hash", sha), {})
        family = (
            _opt_str(row.get("vt_file_family"))
            or _opt_str(row.get("gti_malware_families"))
            or _opt_str(cached.get("vt_file_family"))
            or _opt_str(cached.get("gti_malware_families"))
        )
        file_vt_mal = (
            _opt_int(row.get("vt_file_malicious_count"))
            if row.get("vt_file_malicious_count") is not None
            else _opt_int(cached.get("vt_file_malicious_count"))
        )
        file_gti = _opt_str(row.get("gti_verdict")) or _opt_str(cached.get("gti_verdict"))
        meta = {
            "vhash": _opt_str(row.get("vt_file_vhash")) or _opt_str(cached.get("vt_file_vhash")),
            "vt_status": _opt_str(row.get("vt_status")) or _opt_str(cached.get("vt_status")),
            "vt_malicious": file_vt_mal,
            "gti_verdict": file_gti,
            "gti_score": (
                _opt_int(row.get("gti_score"))
                if row.get("gti_score") is not None
                else _opt_int(cached.get("gti_score"))
            ),
            "malware_family": family,
            "actor_associations": (
                _opt_str(row.get("gti_threat_actors")) or _opt_str(cached.get("gti_threat_actors"))
            ),
        }
        _touch(
            "malware_hash",
            sha,
            _ensure_utc_dt(row.get("time")),
            _opt_str(row.get("src_endpoint_ip")),
            meta,
        )

        # Corroborate the source download URL/IP only on outbound file downloads
        # (OCSF activity_id == 2, non-Dionaea) whose captured hash is itself
        # corroborated malicious by VT or GTI.
        row_dataset = _opt_str(row.get("dataset")) or ""
        row_activity = _opt_int(row.get("activity_id"))
        row_file_url = _opt_str(row.get("file_url"))
        hash_corroborated = (file_vt_mal is not None and file_vt_mal >= VT_URL_MIN_MALICIOUS) or (
            (file_gti or "").upper() in GTI_CORROBORATING_VERDICTS
        )
        if row_file_url and row_dataset != "dionaea" and row_activity == 2 and hash_corroborated:
            cap_frame = pl.DataFrame(
                {"file_url": [row_file_url], "file_intent": [row.get("file_intent")]},
                schema={"file_url": pl.Utf8, "file_intent": pl.Utf8},
            )
            for cap_url in extract_outbound_urls(cap_frame, cfg):
                captured_urls.add(cap_url)
                try:
                    cap_host = urlparse(cap_url).hostname
                except ValueError:
                    cap_host = None
                if cap_host:
                    cap_addr = parse_normalized_ip(cap_host)
                    if cap_addr is not None:
                        captured_c2_ips.add(str(cap_addr))

    # 2. Outbound URLs, stager domains, C2 IPs, and SSH public keys
    text_rows = silver.filter(
        pl.col("actor_process_cmd_line").is_not_null()
        | (
            pl.col("file_url").is_not_null()
            & (pl.col("file_intent").fill_null("malware") != "probe")
        )
    )
    text_cols = [
        c
        for c in (
            "time",
            "src_endpoint_ip",
            "actor_process_cmd_line",
            "file_url",
            "file_intent",
            "vt_url_malicious_count",
            "vt_status",
            "gti_verdict",
            "gti_score",
            "gti_malware_families",
            "gti_threat_actors",
        )
        if c in text_rows.columns
    ]
    for row in text_rows.select(text_cols).iter_rows(named=True):
        mini = pl.DataFrame(
            {
                "actor_process_cmd_line": [row.get("actor_process_cmd_line")],
                "file_url": [row.get("file_url")],
                "file_intent": [row.get("file_intent")],
            },
            schema={
                "actor_process_cmd_line": pl.Utf8,
                "file_url": pl.Utf8,
                "file_intent": pl.Utf8,
            },
        )
        ts = _ensure_utc_dt(row.get("time"))
        src_ip = _opt_str(row.get("src_endpoint_ip"))

        row_urls = extract_outbound_urls(mini, cfg)
        for url in sorted(row_urls):
            cached_u = lookup.get(("url", url), {})
            u_meta = {
                "vt_status": _opt_str(cached_u.get("vt_status")),
                "vt_malicious": (
                    _opt_int(cached_u.get("vt_url_malicious_count"))
                    if cached_u.get("vt_url_malicious_count") is not None
                    else _opt_int(row.get("vt_url_malicious_count"))
                ),
                "gti_verdict": _opt_str(cached_u.get("gti_verdict")),
                "gti_score": _opt_int(cached_u.get("gti_score")),
                "malware_family": _opt_str(cached_u.get("gti_malware_families")),
                "actor_associations": _opt_str(cached_u.get("gti_threat_actors")),
            }
            _touch("stager_url", url, ts, src_ip, u_meta)

        for domain in sorted(extract_stager_domains(row_urls, cfg)):
            cached_d = lookup.get(("domain", domain), {})
            d_meta = {
                "vt_status": _opt_str(cached_d.get("vt_status")),
                "vt_malicious": _opt_int(cached_d.get("vt_domain_malicious_count")),
                "gti_verdict": _opt_str(cached_d.get("gti_verdict")),
                "gti_score": _opt_int(cached_d.get("gti_score")),
                "malware_family": _opt_str(cached_d.get("gti_malware_families")),
                "actor_associations": _opt_str(cached_d.get("gti_threat_actors")),
            }
            _touch("stager_domain", domain, ts, src_ip, d_meta)

        for c2_ip in sorted(extract_outbound_c2_ips(mini, cfg)):
            try:
                ipaddress.ip_address(c2_ip)
            except ValueError:
                continue
            cached_ip = lookup.get(("ip", c2_ip), {})
            ip_meta = {
                "vt_status": _opt_str(cached_ip.get("vt_status")),
                "vt_malicious": _opt_int(cached_ip.get("vt_malicious_count")),
                "gti_verdict": _opt_str(cached_ip.get("gti_verdict")),
                "gti_score": _opt_int(cached_ip.get("gti_score")),
                "malware_family": _opt_str(cached_ip.get("gti_malware_families")),
                "actor_associations": _opt_str(cached_ip.get("gti_threat_actors")),
            }
            _touch("c2_ip", c2_ip, ts, src_ip, ip_meta)

        for ssh_fp in sorted(extract_ssh_public_keys(mini)):
            _touch("ssh_key", ssh_fp, ts, src_ip)

    if not acc:
        return pl.DataFrame(schema=EXTRACTED_IOCS_SCHEMA)

    rows: list[dict[str, object]] = []
    for entry in acc.values():
        ips_set = entry["src_ips"]
        unique_srcs = len(ips_set) if isinstance(ips_set, set) else 0
        ioc_type = str(entry["ioc_type"])
        ioc_value = str(entry["ioc_value"])

        # Hydrate IP-level GreyNoise / AbuseIPDB signals from enrichment cache
        # for outbound C2 IPs (and IP-literal stager URLs).
        ip_cache: Mapping[str, object] = {}
        if ioc_type == "c2_ip":
            norm_c2 = parse_normalized_ip(ioc_value)
            ip_cache = lookup.get(("ip", str(norm_c2) if norm_c2 is not None else ioc_value), {})
        elif ioc_type == "stager_url":
            try:
                url_host = urlparse(ioc_value).hostname
            except ValueError:
                url_host = None
            if url_host:
                url_addr = parse_normalized_ip(url_host)
                if url_addr is not None:
                    ip_cache = lookup.get(("ip", str(url_addr)), {})

        is_captured = (ioc_type == "stager_url" and ioc_value in captured_urls) or (
            ioc_type == "c2_ip" and ioc_value in captured_c2_ips
        )
        verif_status, verif_reason = evaluate_ioc_verification(
            ioc_type,
            ioc_value,
            vt_malicious=_opt_int(entry["vt_malicious"]),
            gti_verdict=_opt_str(entry["gti_verdict"]),
            captured_artifact=is_captured,
            greynoise_riot=bool(ip_cache.get("greynoise_riot") is True),
            greynoise_class=_opt_str(ip_cache.get("greynoise_classification")),
            abuseipdb_confidence=_opt_int(ip_cache.get("abuseipdb_confidence_score")),
            allowlist_domains=allow_domains,
            allowlist_ips=allow_ips,
        )

        rows.append(
            {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "vhash": entry["vhash"],
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
                "event_count": entry["event_count"],
                "unique_src_ips": unique_srcs,
                "vt_status": entry["vt_status"],
                "vt_malicious": entry["vt_malicious"],
                "gti_verdict": entry["gti_verdict"],
                "gti_score": entry["gti_score"],
                "malware_family": entry["malware_family"],
                "actor_associations": entry["actor_associations"],
                "verification_status": verif_status,
                "verification_reason": verif_reason,
            }
        )

    return pl.DataFrame(rows, schema=EXTRACTED_IOCS_SCHEMA).sort(
        ["ioc_type", "event_count", "ioc_value"],
        descending=[False, True, False],
    )

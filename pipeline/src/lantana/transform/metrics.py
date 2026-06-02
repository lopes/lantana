"""Gold metric computation functions.

Pure DataFrame transforms that aggregate silver-layer events into
intelligence-ready gold tables. Each function accepts a collected
DataFrame (not LazyFrame) and returns a new DataFrame.
"""

from __future__ import annotations

import hashlib
from datetime import date  # noqa: TC003 — used in function signature

import polars as pl

from lantana.models.ocsf import (
    CLASS_AUTHENTICATION,
    CLASS_DETECTION_FINDING,
    CLASS_FILE_ACTIVITY,
    CLASS_NETWORK_ACTIVITY,
    CLASS_PROCESS_ACTIVITY,
    STATUS_FAILURE,
    STATUS_SUCCESS,
)

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

# Top-N limit for summary lists
TOP_N: int = 10

# Behavioral risk-score factors (composite formula in docs/risk-scoring.md §Gold composite).
# Tuning any of these requires updating the doc and the regression tests in
# tests/test_transform/test_metrics.py::TestRiskScoreDecomposition.
BEHAVIORAL_AUTH_FACTOR: float = 20.0
BEHAVIORAL_COMMAND_FACTOR: float = 25.0
BEHAVIORAL_FINDING_FACTOR: float = 15.0
BEHAVIORAL_DOWNLOAD_FACTOR: float = 20.0
BEHAVIORAL_AUTH_ATTEMPT_CAP: float = 100.0
BEHAVIORAL_AUTH_ATTEMPT_WEIGHT: float = 0.1

# Automated-actor heuristic thresholds (compute_behavioral_progression).
AUTOMATED_AUTH_ATTEMPTS_MIN: int = 10
AUTOMATED_UNIQUE_PASSWORDS_MIN: int = 5
AUTOMATED_WINDOW_SECONDS_MAX: int = 120

# Dataset-specific columns that gold aggregations reference. The
# diagonal-concat in ``read_silver_partition`` produces a frame containing
# the UNION of columns across all datasets present that day; on days when
# a dataset's silver write failed (provider outage, normalize bug,
# defect-of-the-month), its contributed columns disappear, and aggregations
# that name them crash with ``ColumnNotFoundError``. This list pins them so
# ``_ensure_gold_columns`` can backfill typed nulls regardless.
_OPTIONAL_GOLD_COLUMNS: dict[str, pl.DataType] = {
    # Cowrie / Dionaea login + command + file-download fields
    "session": pl.Utf8(),
    "user_name": pl.Utf8(),
    "unmapped_password": pl.Utf8(),
    "actor_process_cmd_line": pl.Utf8(),
    "file_url": pl.Utf8(),
    "file_path": pl.Utf8(),
    "file_hash_sha256": pl.Utf8(),
    # Suricata detection metadata
    "finding_title": pl.Utf8(),
    "finding_uid": pl.Utf8(),
    "finding_category": pl.Utf8(),
    "flow_id": pl.Int64(),
}


def _ensure_gold_columns(silver: pl.DataFrame) -> pl.DataFrame:
    """Backfill optional gold columns as typed nulls when absent.

    Gold runs against the union of whichever datasets produced silver that
    day. When cowrie silver fails (defect #9, etc.) the column
    ``session`` simply isn't in the diagonal-concat; without this guard,
    ``compute_daily_summary`` crashes on ``pl.col("session")`` and the
    whole transform step dies — leaving operators with NO gold tables
    for that date despite suricata silver being healthy.
    """
    missing = [
        pl.lit(None, dtype=dtype).alias(name)
        for name, dtype in _OPTIONAL_GOLD_COLUMNS.items()
        if name not in silver.columns
    ]
    return silver.with_columns(missing) if missing else silver


def _optional_first(df: pl.DataFrame, col: str, alias: str) -> pl.Expr:
    """Return first() aggregation for a column, or null literal if column is absent."""
    if col in df.columns:
        return pl.col(col).first().alias(alias)
    return pl.lit(None).alias(alias)


def _top_n(df: pl.DataFrame, col: str, n: int = TOP_N) -> list[dict[str, str | int]]:
    """Top-N most frequent non-null values + their event counts, ranked by count.

    Returns `[{"value": str, "count": int}, ...]`, stored in gold as
    `list[struct[value, count]]`. Dashboard pages render this as
    `Rank | Value | Count`; the Discord report shows `value (count)`;
    STIX export extracts just the `value` field.
    """
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
    """Top-N username/password pairs, ranked by event count.

    Returns `[{"username": str, "password": str, "count": int}, ...]`, stored
    as `list[struct[username, password, count]]`. Useful on the Credentials
    page to surface which exact pairs attackers reuse most — a different
    signal from "top usernames" or "top passwords" alone (which can be
    misleading when the most-tried user and most-tried pass never appear
    together).
    """
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
    """Top-N source countries + unique-IP counts.

    Ranked by unique attacker IPs (not event count) to match `geographic_summary`.
    A single chatty IP from CH should not outrank a swarm of distinct US scanners.
    """
    if "geo.country_code" not in df.columns or "src_endpoint_ip" not in df.columns:
        return []
    return (
        df.filter(pl.col("geo.country_code").is_not_null())
        .group_by("geo.country_code")
        .agg(pl.col("src_endpoint_ip").n_unique().alias("count"))
        .sort("count", descending=True)
        .head(n)
        .rename({"geo.country_code": "value"})
        .to_dicts()
    )


def compute_daily_summary(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute daily summary statistics from silver-layer data.

    Returns a single-row DataFrame with aggregate counts and top-N lists.
    """
    if silver.is_empty():
        return pl.DataFrame()

    silver = _ensure_gold_columns(silver)

    cls = pl.col("class_uid")
    sts = pl.col("status_id")

    scalars = silver.select(
        pl.len().alias("total_events"),
        pl.col("src_endpoint_ip").n_unique().alias("unique_source_ips"),
        pl.col("session").drop_nulls().n_unique().alias("unique_sessions"),
        (cls == CLASS_AUTHENTICATION).sum().alias("auth_attempts"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS)).sum().alias("auth_successes"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_FAILURE)).sum().alias("auth_failures"),
        (cls == CLASS_PROCESS_ACTIVITY).sum().alias("commands_executed"),
        (cls == CLASS_DETECTION_FINDING).sum().alias("findings_detected"),
        (cls == CLASS_NETWORK_ACTIVITY).sum().alias("network_events"),
        (cls == CLASS_FILE_ACTIVITY).sum().alias("downloads_captured"),
    )

    # Top-N lists as list columns
    lists = pl.DataFrame(
        {
            "top_usernames": [_top_n(silver, "user_name")],
            "top_passwords": [_top_n(silver, "unmapped_password")],
            "top_credential_pairs": [_top_n_credential_pairs(silver)],
            "top_commands": [_top_n(silver, "actor_process_cmd_line")],
            "top_source_countries": [_top_n_countries_by_unique_ips(silver)],
            "top_source_ips": [_top_n(silver, "src_endpoint_ip")],
            "top_download_urls": [_top_n(silver, "file_url")],
            "top_download_hashes": [_top_n(silver, "file_hash_sha256")],
        }
    )

    return pl.concat([scalars, lists], how="horizontal")


def compute_ip_reputation(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute per-IP reputation scores from enrichment and behavioral data.

    Three risk scores per IP (all 0..100, clipped):

    * ``enrichment_risk_score`` — horizontal mean of the four per-provider
      scores that landed in silver (``abuseipdb_risk_score``,
      ``virustotal_risk_score``, ``shodan_risk_score``,
      ``greynoise_risk_score``), skipping nulls. If every provider was
      null for this IP, the mean is null and the composite below falls
      back to behavioral only.
    * ``behavioral_risk_score`` — derived purely from on-honeypot
      activity:
        +20 if auth_successes > 0
        +25 if commands_executed > 0
        +15 if findings_triggered > 0
        +20 if downloads > 0
        +min(auth_attempts, 100) * 0.1
    * ``risk_score`` — the single number every downstream consumer reads
      (STIX gate, dashboard buckets, Discord top-5, geography map):
        risk_score = (enrichment.fill_null(0) + behavioral) / 2
      Mean of two halves, each 0..100, so the composite is 0..100. The
      ``fill_null(0)`` is deliberate: an IP with zero enrichment data
      still attracts behavioral attention, just halved by the absent
      intel side.

    See docs/risk-scoring.md for the full formula + worked examples.
    """
    if silver.is_empty():
        return pl.DataFrame()

    silver = _ensure_gold_columns(silver)

    cls = pl.col("class_uid")
    sts = pl.col("status_id")

    # Core columns always present in silver (built by the normaliser, not
    # dependent on which providers ran).
    core_aggs: list[pl.Expr] = [
        pl.len().alias("total_events"),
        pl.col("dataset").unique().alias("datasets"),
        (cls == CLASS_AUTHENTICATION).sum().alias("auth_attempts"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS)).sum().alias("auth_successes"),
        pl.col("user_name").drop_nulls().n_unique().alias("unique_usernames"),
        pl.col("unmapped_password").drop_nulls().n_unique().alias("unique_passwords"),
        (cls == CLASS_PROCESS_ACTIVITY).sum().alias("commands_executed"),
        (cls == CLASS_DETECTION_FINDING).sum().alias("findings_triggered"),
        (cls == CLASS_FILE_ACTIVITY).sum().alias("downloads"),
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
        pl.col("geo.country_code").first().alias("geo_country"),
        pl.col("geo.asn").first().alias("geo_asn"),
        pl.col("geo.isp").first().alias("geo_isp"),
    ]

    # Optional enrichment columns — may be absent on any given day when a
    # provider was rate-limited, circuit-broken, or simply not configured.
    # _optional_first returns a typed null literal when the column is absent
    # so the group_by aggregation doesn't crash.
    optional = [
        ("geo.city", "geo_city"),
        ("geo.latitude", "geo_latitude"),
        ("geo.longitude", "geo_longitude"),
        ("abuseipdb_confidence_score", "abuseipdb_score"),
        ("abuseipdb_total_reports", "abuseipdb_reports"),
        ("greynoise_classification", "greynoise_class"),
        ("greynoise_name", "greynoise_name"),
        ("greynoise_noise", "greynoise_noise"),
        ("greynoise_riot", "greynoise_riot"),
        ("shodan_ports", "shodan_ports"),
        ("shodan_os", "shodan_os"),
        ("shodan_vulns", "shodan_vulns"),
        ("shodan_org", "shodan_org"),
        ("vt_malicious_count", "vt_malicious"),
        ("vt_ip_reputation", "vt_reputation"),
        # Per-provider risk_scores from Phase D.1 — pulled into gold for
        # the composite blend below. Each is a Float64 in [0, 100] or null
        # when the provider didn't contribute to this IP this run.
        ("abuseipdb_risk_score", "abuseipdb_risk_score"),
        ("virustotal_risk_score", "virustotal_risk_score"),
        ("shodan_risk_score", "shodan_risk_score"),
        ("greynoise_risk_score", "greynoise_risk_score"),
    ]
    enrichment_aggs = [_optional_first(silver, col, alias) for col, alias in optional]

    grouped = silver.group_by("src_endpoint_ip").agg(core_aggs + enrichment_aggs)

    # Phase D.2 composite. Three score columns in a single with_columns so
    # later expressions can reference the earlier aliases (polars resolves
    # within one with_columns left-to-right via the expression chain).
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
        pl.col("abuseipdb_risk_score").cast(pl.Float64),
        pl.col("virustotal_risk_score").cast(pl.Float64),
        pl.col("shodan_risk_score").cast(pl.Float64),
        pl.col("greynoise_risk_score").cast(pl.Float64),
    ).clip(0.0, 100.0)

    result = grouped.with_columns(
        enrichment_expr.alias("enrichment_risk_score"),
        behavioral_expr.alias("behavioral_risk_score"),
    ).with_columns(
        ((pl.col("enrichment_risk_score").fill_null(0.0) + pl.col("behavioral_risk_score")) / 2.0)
        .clip(0.0, 100.0)
        .alias("risk_score"),
    )

    return result.sort(
        ["risk_score", "enrichment_risk_score"],
        descending=[True, True],
        nulls_last=True,
    )


def compute_behavioral_progression(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute attacker behavioral progression metrics.

    Stages:
    1. SCAN — only network events
    2. CREDENTIAL — login attempts present
    3. AUTHENTICATED — at least one successful login
    4. INTERACTIVE — commands executed

    Automated heuristic: auth_attempts > 10 AND unique_passwords > 5
    within 120s window, OR greynoise_noise == true.
    """
    if silver.is_empty():
        return pl.DataFrame()

    silver = _ensure_gold_columns(silver)

    cls = pl.col("class_uid")
    sts = pl.col("status_id")

    # Per-IP aggregations
    grouped = silver.group_by("src_endpoint_ip").agg(
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
        (cls == CLASS_NETWORK_ACTIVITY).sum().alias("scan_events"),
        (cls == CLASS_AUTHENTICATION).sum().alias("auth_attempts"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS)).sum().alias("auth_successes"),
        (cls == CLASS_PROCESS_ACTIVITY).sum().alias("commands_executed"),
        pl.col("session").drop_nulls().n_unique().alias("unique_sessions"),
        pl.col("unmapped_password").drop_nulls().n_unique().alias("unique_passwords"),
        # Timing: first event of each type
        pl.col("time").filter(cls == CLASS_AUTHENTICATION).min().alias("first_auth_time"),
        pl.col("time")
        .filter((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS))
        .min()
        .alias("first_success_time"),
        pl.col("time").filter(cls == CLASS_PROCESS_ACTIVITY).min().alias("first_command_time"),
        # Automated detection inputs (greynoise_noise absent when the provider
        # didn't contribute to this date — fall back to false via fill_null below)
        _optional_first(silver, "greynoise_noise", "greynoise_noise"),
    )

    # Compute max_stage
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

    # Stage label
    result = result.with_columns(
        pl.col("max_stage").replace_strict(STAGE_LABELS, default="unknown").alias("stage_label"),
    )

    # Escalation timing (seconds)
    result = result.with_columns(
        # seconds from first_seen to first auth attempt
        pl.when(pl.col("first_auth_time").is_not_null())
        .then((pl.col("first_auth_time") - pl.col("first_seen")).dt.total_seconds().cast(pl.Int64))
        .otherwise(pl.lit(None))
        .alias("seconds_to_auth"),
        # seconds from first auth to first success
        pl.when(
            pl.col("first_success_time").is_not_null() & pl.col("first_auth_time").is_not_null()
        )
        .then(
            (pl.col("first_success_time") - pl.col("first_auth_time"))
            .dt.total_seconds()
            .cast(pl.Int64)
        )
        .otherwise(pl.lit(None))
        .alias("seconds_to_success"),
        # seconds from first success to first command
        pl.when(
            pl.col("first_command_time").is_not_null() & pl.col("first_success_time").is_not_null()
        )
        .then(
            (pl.col("first_command_time") - pl.col("first_success_time"))
            .dt.total_seconds()
            .cast(pl.Int64)
        )
        .otherwise(pl.lit(None))
        .alias("seconds_to_command"),
    )

    # Automated heuristic
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

    # Drop intermediate timing columns
    result = result.drop(
        "first_auth_time",
        "first_success_time",
        "first_command_time",
        "unique_passwords",
        "greynoise_noise",
    )

    return result.sort("max_stage", descending=True)


def compute_behavioral_progression_multiday(
    silver_frames: list[tuple[date, pl.DataFrame]],
) -> pl.DataFrame:
    """Compute cross-day behavioral progression for attacker IPs.

    Extends single-day progression by tracking IPs across a multi-day
    lookback window. Detects slow-burn escalation patterns where an IP
    scans on day 1, attempts credentials on day 3, and goes interactive
    on day 5.

    Args:
        silver_frames: List of (date, silver_df) tuples. Runner provides
            these by reading multiple days of silver data.

    Returns:
        DataFrame with one row per unique source IP, including cross-day
        metrics: first/last seen dates, active days, per-stage first dates,
        progression velocity, and slow-burn flag.
    """
    if not silver_frames:
        return pl.DataFrame()

    # Concatenate all frames with a report_date column
    parts: list[pl.DataFrame] = []
    for report_date, df in silver_frames:
        if not df.is_empty():
            parts.append(df.with_columns(pl.lit(report_date).alias("report_date")))

    if not parts:
        return pl.DataFrame()

    combined = pl.concat(parts, how="diagonal_relaxed")

    if combined.is_empty():
        return pl.DataFrame()

    combined = _ensure_gold_columns(combined)

    cls = pl.col("class_uid")
    sts = pl.col("status_id")

    # Per-IP aggregations across all days
    grouped = combined.group_by("src_endpoint_ip").agg(
        pl.col("report_date").min().alias("first_seen_date"),
        pl.col("report_date").max().alias("last_seen_date"),
        pl.col("report_date").n_unique().alias("active_days"),
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
        (cls == CLASS_NETWORK_ACTIVITY).sum().alias("scan_events"),
        (cls == CLASS_AUTHENTICATION).sum().alias("auth_attempts"),
        ((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS)).sum().alias("auth_successes"),
        (cls == CLASS_PROCESS_ACTIVITY).sum().alias("commands_executed"),
        # Per-stage first date (date of first event reaching that stage)
        pl.col("report_date")
        .filter(cls == CLASS_AUTHENTICATION)
        .min()
        .alias("credential_first_date"),
        pl.col("report_date")
        .filter((cls == CLASS_AUTHENTICATION) & (sts == STATUS_SUCCESS))
        .min()
        .alias("authenticated_first_date"),
        pl.col("report_date")
        .filter(cls == CLASS_PROCESS_ACTIVITY)
        .min()
        .alias("interactive_first_date"),
    )

    # Compute max_stage (reuse stage logic)
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

    # Stage label
    result = result.with_columns(
        pl.col("max_stage").replace_strict(STAGE_LABELS, default="unknown").alias("stage_label"),
    )

    # Max stage first date (when the highest stage was first reached)
    result = result.with_columns(
        pl.when(pl.col("max_stage") == STAGE_INTERACTIVE)
        .then(pl.col("interactive_first_date"))
        .when(pl.col("max_stage") == STAGE_AUTHENTICATED)
        .then(pl.col("authenticated_first_date"))
        .when(pl.col("max_stage") == STAGE_CREDENTIAL)
        .then(pl.col("credential_first_date"))
        .otherwise(pl.col("first_seen_date"))
        .alias("max_stage_first_date"),
    )

    # Progression velocity (days between first_seen_date and max_stage_first_date)
    result = result.with_columns(
        (pl.col("max_stage_first_date") - pl.col("first_seen_date"))
        .dt.total_days()
        .cast(pl.Int64)
        .alias("progression_velocity_days"),
    )

    # Slow burn flag: escalated across 2+ calendar days
    result = result.with_columns(
        (pl.col("progression_velocity_days") > 0).alias("is_slow_burn"),
    )

    # Drop intermediate column
    result = result.drop("max_stage_first_date")

    return result.sort("max_stage", descending=True)


def compute_campaign_clusters(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute campaign clusters from shared credential pairs.

    Groups IPs by (username, password) pairs. Only clusters with >= 2
    unique IPs are included.
    """
    if silver.is_empty():
        return pl.DataFrame()

    silver = _ensure_gold_columns(silver)

    # Filter to auth events with credentials
    auth = silver.filter(
        (pl.col("class_uid") == CLASS_AUTHENTICATION)
        & pl.col("user_name").is_not_null()
        & pl.col("unmapped_password").is_not_null()
        & (pl.col("user_name") != "")
        & (pl.col("unmapped_password") != "")
    )

    if auth.is_empty():
        return pl.DataFrame()

    # Group by credential pair
    clusters = auth.group_by("user_name", "unmapped_password").agg(
        pl.col("src_endpoint_ip").unique().alias("ips"),
        pl.col("src_endpoint_ip").n_unique().alias("ip_count"),
        pl.len().alias("total_events"),
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
    )

    # Only clusters with >= 2 IPs
    clusters = clusters.filter(pl.col("ip_count") >= 2)

    if clusters.is_empty():
        return pl.DataFrame()

    # Generate cluster_id from credential hash
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

    # Rename for clarity
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
    """Compute geographic distribution of attack origins.

    Returns a single-row DataFrame with top countries, cities, and ASNs
    encoded as list columns (same pattern as daily_summary).
    """
    if silver.is_empty() or "geo.country_code" not in silver.columns:
        return pl.DataFrame()

    # Top countries by unique IPs
    countries = (
        silver.filter(pl.col("geo.country_code").is_not_null())
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

    # Top cities by unique IPs (with lat/lon for mapping)
    top_cities: list[str] = []
    if "geo.city" in silver.columns:
        cities = (
            silver.filter(pl.col("geo.city").is_not_null() & (pl.col("geo.city") != ""))
            .group_by("geo.city", "geo.country_code", "geo.latitude", "geo.longitude")
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

    # Top ASNs by unique IPs
    top_asns: list[str] = []
    if "geo.asn" not in silver.columns:
        return pl.DataFrame(
            {
                "top_countries": [top_countries],
                "top_cities": [top_cities],
                "top_asns": [top_asns],
            }
        )

    # geo.asn is Int64 in production (MaxMind ASN MMDB returns int); is_not_null
    # is the only validity check needed. The previous `!= ""` comparison worked
    # only against string-typed test fixtures.
    asns = (
        silver.filter(pl.col("geo.asn").is_not_null())
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
        }
    )


def compute_detection_findings(silver: pl.DataFrame) -> pl.DataFrame:
    """Compute detection finding statistics from Suricata alerts.

    Returns one row per rule with event count, unique IPs, and severity.
    Top 20 rules by event count.
    """
    if silver.is_empty() or "finding_title" not in silver.columns:
        return pl.DataFrame()

    findings = silver.filter(pl.col("class_uid") == CLASS_DETECTION_FINDING)
    if findings.is_empty():
        return pl.DataFrame()

    # Group by finding_title
    aggs: list[pl.Expr] = [
        pl.len().alias("event_count"),
        pl.col("src_endpoint_ip").n_unique().alias("unique_ips"),
        pl.col("severity_id").mode().first().alias("severity_id"),
        pl.col("time").min().alias("first_seen"),
        pl.col("time").max().alias("last_seen"),
    ]
    if "finding_category" in findings.columns:
        aggs.append(pl.col("finding_category").first().alias("category"))

    result = findings.group_by("finding_title").agg(aggs)

    return result.sort("event_count", descending=True).head(20)

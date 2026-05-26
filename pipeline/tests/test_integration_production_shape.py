"""End-to-end integration test against production-shape bronze.

Mirrors what Vector ships on the VPS:
  - nested ``geo`` struct on every event
  - nested ``alert`` struct on Suricata alerts
  - raw ``message`` strings for nftables (Vector doesn't parse the
    kernel log yet — Issue A in PLAN.md)
  - optional enrichment columns missing on some IPs (rate-limit
    / sparse-200 days)
  - the honeypot's own WAN address appearing as source on some
    Suricata flow rows

Pipes the fixtures through ``run_enrichment`` (all four providers mocked
in the runner namespace) and then ``run_transform`` against the resulting
silver. Asserts that every dataset either produces silver or logs a clean
skip, every gold table either produces a result or is empty, and no leaks
make it past the redaction layer.

This is the load-bearing regression harness for the
"bronze didn't match the shape the code assumed" class of defect
that surfaced eight times in sequence on 2026-05-20.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx
import polars as pl
import pytest

import lantana.common.datalake as datalake_mod
import lantana.enrichment.runner as runner_mod
from lantana.common.config import (
    OperationConfig,
    OperatorConfig,
    RedactConfig,
    ReportingConfig,
    SecretsConfig,
    SharingConfig,
)
from lantana.enrichment.providers.base import EnrichmentResult
from lantana.enrichment.runner import run_enrichment
from lantana.transform.runner import run_transform

FIXTURE_DATE = date(2026, 5, 19)
HONEYPOT_WAN = "192.0.2.100"
ATTACKER_FULL = "203.0.113.10"  # all four providers return populated data
ATTACKER_RATE_LIMITED = "203.0.113.20"  # all four providers return 429
ATTACKER_SPARSE = "198.51.100.50"  # all four providers return empty {} (sparse 200)
FILE_DOWNLOAD_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

PROD_BRONZE_FIXTURES = Path(__file__).parent / "fixtures" / "production_shape" / "bronze"

# Enrichment data mirroring what each provider returns for the "full" attacker.
# Each provider's ``*_risk_score`` is the value that ``compute_risk_score``
# would produce for the surrounding raw fields; the fixture pre-computes it so
# the integration test mirrors production silver exactly.
_FULL_ENRICHMENT: dict[str, dict[str, Any]] = {
    "abuseipdb": {
        "abuseipdb_confidence_score": 88,
        "abuseipdb_total_reports": 247,
        "abuseipdb_risk_score": 88.0,  # = confidence
    },
    "shodan": {
        "shodan_ports": "22,80,443",
        "shodan_os": "Linux",
        "shodan_org": "Example Telecom BR",
        "shodan_vulns": "",
        "shodan_risk_score": 25.0,  # ports present, no vulns
    },
    "virustotal": {
        "vt_malicious_count": 5,
        "vt_ip_reputation": -10,
        "virustotal_risk_score": 50.0,  # bucket 3-5 → 50
    },
    "greynoise": {
        "greynoise_classification": "malicious",
        "greynoise_noise": True,
        "greynoise_riot": False,
        "greynoise_name": "Mass Scanner",
        "greynoise_risk_score": 75.0,  # classification=malicious
    },
}

_VT_HASH_DATA: dict[str, Any] = {
    "vt_file_malicious_count": 42,
    "vt_file_first_seen": "2026-05-15T00:00:00Z",
    "vt_file_type": "Bourne-Again shell script",
}


def _make_429() -> httpx.HTTPStatusError:
    req = httpx.Request("GET", "https://api.test")
    resp = httpx.Response(status_code=429, request=req)
    return httpx.HTTPStatusError("429 Too Many Requests", request=req, response=resp)


def _make_ip_provider_class(provider_name: str, data_for_full: dict[str, Any]) -> type:
    """Build a real class so the runner's ``isinstance(provider, ...)`` checks
    pass. Patching the runner-namespace symbol to a lambda would break the
    ``isinstance(provider, VirusTotalProvider)`` dispatch inside _query_provider.

    Per-IP behaviour:
      ATTACKER_FULL          → populated data
      ATTACKER_RATE_LIMITED  → HTTPStatusError 429
      ATTACKER_SPARSE / etc. → empty dict (sparse 200 response)
    """

    class _FakeIpProvider:
        def __init__(self, _key: str | None = None) -> None:  # pragma: no cover
            pass

        async def enrich_ip(self, ip: str) -> EnrichmentResult:
            if ip == ATTACKER_RATE_LIMITED:
                raise _make_429()
            data = data_for_full if ip == ATTACKER_FULL else {}
            return EnrichmentResult(
                provider=provider_name,
                ip=ip,
                data=dict(data),
                queried_at=datetime.now(tz=UTC),
            )

        async def close(self) -> None:
            return None

    _FakeIpProvider.__name__ = f"_Fake{provider_name.title()}Provider"
    return _FakeIpProvider


def _make_vt_provider_class() -> type:
    """VT mock provides both enrich_ip and enrich_hash."""

    class _FakeVirusTotalProvider:
        def __init__(self, _key: str | None = None) -> None:  # pragma: no cover
            pass

        async def enrich_ip(self, ip: str) -> EnrichmentResult:
            if ip == ATTACKER_RATE_LIMITED:
                raise _make_429()
            data = _FULL_ENRICHMENT["virustotal"] if ip == ATTACKER_FULL else {}
            return EnrichmentResult(
                provider="virustotal",
                ip=ip,
                data=dict(data),
                queried_at=datetime.now(tz=UTC),
            )

        async def enrich_hash(self, sha256: str) -> EnrichmentResult:
            data = _VT_HASH_DATA if sha256 == FILE_DOWNLOAD_SHA else {}
            return EnrichmentResult(
                provider="virustotal",
                ip=sha256,
                data=dict(data),
                queried_at=datetime.now(tz=UTC),
            )

        async def close(self) -> None:
            return None

    return _FakeVirusTotalProvider


def _stub_secrets() -> SecretsConfig:
    return SecretsConfig.model_validate({
        "vault_apikey_virustotal": "test-vt",
        "vault_apikey_shodan": "test-shodan",
        "vault_apikey_abuseipdb": "test-abuseipdb",
        "vault_apikey_greynoise": "test-greynoise",
    })


def _stub_reporting() -> ReportingConfig:
    return ReportingConfig(
        operator=OperatorConfig(
            name="Test Operator",
            handle="test_handle",
            contact="https://test.example.com",
            pgp_fingerprint="AABBCCDD",
        ),
        sharing=SharingConfig(
            tlp="GREEN",
            community="Test Community",
            discord_channel="test-intel",
        ),
        operation=OperationConfig(
            name="Test Operation",
            description="Production-shape integration test",
            sector="Test",
            region="Test",
            start_date="2026-05-01",
        ),
        redact=RedactConfig(
            infrastructure_ips=[HONEYPOT_WAN, "10.50.99.100"],
            infrastructure_cidrs=["10.50.99.0/24"],
            pseudonym_map={
                HONEYPOT_WAN: "honeypot-wan",
                "10.50.99.100": "honeypot-sensor",
            },
        ),
    )


def _copy_bronze_fixtures(
    target_root: Path,
    include_datasets: frozenset[str] | None = None,
) -> None:
    """Copy the on-disk fixture tree into a writeable tmp root.

    `read_bronze_ndjson` reads NDJSON from a Hive-partitioned tree. The
    fixture is committed under a stable path; we copy it into tmp_path
    so the test never mutates the checked-in files.

    When ``include_datasets`` is set, only those datasets' partitions are
    copied — used by the data-presence regression test to simulate an
    operation that doesn't deploy every honeypot.
    """
    for src in PROD_BRONZE_FIXTURES.rglob("events.json"):
        rel = src.relative_to(PROD_BRONZE_FIXTURES)
        if include_datasets is not None:
            # First path component is ``dataset=<name>``.
            dataset_part = rel.parts[0]
            dataset_name = dataset_part.removeprefix("dataset=")
            if dataset_name not in include_datasets:
                continue
        dest = target_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())


@pytest.fixture()
def prod_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    """Set up the full enrichment + transform pipeline against production-shape bronze.

    Returns a dict of resolved paths so tests can introspect silver / gold /
    errors output after the run completes.
    """
    bronze_root = tmp_path / "bronze"
    silver_root = tmp_path / "silver"
    gold_root = tmp_path / "gold"
    cache_db = tmp_path / "cache.db"
    sensor_dir = tmp_path / "sensor"  # empty — no on-disk hashes
    errors_path = tmp_path / "enrichment_errors.json"

    sensor_dir.mkdir()
    _copy_bronze_fixtures(bronze_root)

    monkeypatch.setattr(datalake_mod, "BRONZE_ROOT", bronze_root)
    monkeypatch.setattr(datalake_mod, "SILVER_ROOT", silver_root)
    monkeypatch.setattr(datalake_mod, "GOLD_ROOT", gold_root)

    real_read_bronze = datalake_mod.read_bronze_ndjson
    real_write_silver = datalake_mod.write_silver_partition

    def _read_bronze(
        target_date: date,
        dataset: str | None = None,
        bronze_root: Path = bronze_root,
    ) -> pl.DataFrame:
        return real_read_bronze(target_date, dataset=dataset, bronze_root=bronze_root)

    def _write_silver(
        df: pl.DataFrame,
        target_date: date,
        dataset: str,
        server: str,
        silver_root: Path = silver_root,
    ) -> Path:
        return real_write_silver(df, target_date, dataset, server, silver_root=silver_root)

    monkeypatch.setattr(runner_mod, "read_bronze_ndjson", _read_bronze)
    monkeypatch.setattr(runner_mod, "write_silver_partition", _write_silver)

    monkeypatch.setattr(runner_mod, "load_secrets", _stub_secrets)
    monkeypatch.setattr(runner_mod, "load_reporting", _stub_reporting)

    monkeypatch.setattr(
        runner_mod, "AbuseIPDBProvider",
        _make_ip_provider_class("abuseipdb", _FULL_ENRICHMENT["abuseipdb"]),
    )
    monkeypatch.setattr(
        runner_mod, "ShodanProvider",
        _make_ip_provider_class("shodan", _FULL_ENRICHMENT["shodan"]),
    )
    monkeypatch.setattr(runner_mod, "VirusTotalProvider", _make_vt_provider_class())
    monkeypatch.setattr(
        runner_mod, "GreyNoiseProvider",
        _make_ip_provider_class("greynoise", _FULL_ENRICHMENT["greynoise"]),
    )

    return {
        "bronze": bronze_root,
        "silver": silver_root,
        "gold": gold_root,
        "cache": cache_db,
        "sensor": sensor_dir,
        "errors": errors_path,
        "provider_state": tmp_path / "provider_state.json",
    }


@pytest.mark.asyncio()
async def test_end_to_end_pipeline_against_production_shape(
    prod_pipeline: dict[str, Path],
) -> None:
    """Run the full bronze → silver → gold pipeline against production-shape bronze.

    A single journey: any of the eight defect classes from 2026-05-20 would
    fail one of the assertions below.
    """
    # --- Phase A+B+C: enrichment ---
    await run_enrichment(
        target_date=FIXTURE_DATE,
        cache_db_path=prod_pipeline["cache"],
        sensor_dir=prod_pipeline["sensor"],
        errors_path=prod_pipeline["errors"],
        provider_state_path=prod_pipeline["provider_state"],
    )

    silver_root = prod_pipeline["silver"]

    date_str = FIXTURE_DATE.isoformat()

    def _silver_parquet(dataset: str) -> Path:
        return (
            silver_root / f"dataset={dataset}" / f"date={date_str}"
            / "server=sn-01" / "events.parquet"
        )

    def _gold_parquet(table: str) -> Path:
        return prod_pipeline["gold"] / table / f"date={date_str}" / "summary.parquet"

    # Silver written for all four datasets — Phase 2 added the Vector parser
    # that turns raw nftables kernel logs into structured action/src_ip/etc.
    # The defensive `silver_skipped_empty_after_normalize` path is still
    # exercised by tests/test_models/test_normalize.py for the legacy
    # raw-message shape.
    for dataset in ("cowrie", "suricata", "dionaea", "nftables"):
        assert _silver_parquet(dataset).exists(), f"silver missing for {dataset}"

    # --- Silver schema invariants ---
    cowrie_silver = pl.read_parquet(_silver_parquet("cowrie"))

    # Geo struct flattened to flat dotted columns
    geo_subs = (
        "country_code", "region_code", "city", "latitude",
        "longitude", "timezone", "asn", "isp",
    )
    for sub in geo_subs:
        assert f"geo.{sub}" in cowrie_silver.columns, f"cowrie silver missing geo.{sub}"
    assert "geo" not in cowrie_silver.columns, "raw `geo` struct should be dropped"

    # Suricata alert struct flattened — finding_title etc. exist; raw `alert` is gone.
    suricata_silver = pl.read_parquet(_silver_parquet("suricata"))
    assert "finding_title" in suricata_silver.columns
    assert "finding_uid" in suricata_silver.columns
    assert "severity_id" in suricata_silver.columns
    assert "alert" not in suricata_silver.columns

    # WAN-source row was dropped by drop_infrastructure_source_rows
    src_ips_in_suricata = set(suricata_silver.get_column("src_endpoint_ip").to_list())
    assert HONEYPOT_WAN not in src_ips_in_suricata, (
        "Layer-2 redact should have dropped the WAN-source row"
    )

    # Nftables silver carries the Vector-parsed structured fields, OCSF-mapped:
    # action=drop  → activity_id=5 (Refuse), connection_info_protocol_name set.
    nftables_silver = pl.read_parquet(_silver_parquet("nftables"))
    assert nftables_silver.height >= 3, "Phase 2 parser must produce nftables silver rows"
    assert "src_endpoint_ip" in nftables_silver.columns
    assert "connection_info_protocol_name" in nftables_silver.columns
    assert set(nftables_silver.get_column("activity_id").to_list()) == {5}
    nftables_src = set(nftables_silver.get_column("src_endpoint_ip").to_list())
    assert {ATTACKER_FULL, ATTACKER_RATE_LIMITED, ATTACKER_SPARSE}.issubset(nftables_src)

    # Enrichment columns present for the full attacker; nulls for rate-limited / sparse.
    # ATTACKER_FULL got data from all four providers.
    full_rows = cowrie_silver.filter(pl.col("src_endpoint_ip") == ATTACKER_FULL)
    assert full_rows.height > 0
    assert "abuseipdb_confidence_score" in cowrie_silver.columns, (
        "abuseipdb_confidence_score must materialise as a real column when at "
        "least one IP got that provider's data"
    )
    full_scores = full_rows.get_column("abuseipdb_confidence_score").drop_nulls().to_list()
    assert 88 in full_scores

    # ATTACKER_SPARSE got empty data — enrichment columns should be null, not crash.
    sparse_rows = cowrie_silver.filter(pl.col("src_endpoint_ip") == ATTACKER_SPARSE)
    assert sparse_rows.height > 0
    sparse_scores = sparse_rows.get_column("abuseipdb_confidence_score").to_list()
    assert all(s is None for s in sparse_scores), (
        "Sparse-200 IP should have null enrichment columns, not crash"
    )

    # File-hash enrichment landed on the file_download row
    file_dl_rows = cowrie_silver.filter(pl.col("file_hash_sha256") == FILE_DOWNLOAD_SHA)
    assert file_dl_rows.height == 1
    if "vt_file_malicious_count" in cowrie_silver.columns:
        assert file_dl_rows.get_column("vt_file_malicious_count").to_list()[0] == 42

    # OPSEC: no WAN IP anywhere in cowrie silver. The fixture includes an
    # attacker who SSH-bruteforced with the WAN IP as the password attempt
    # (real defect #9 from op_alpha 2026-05-20). The previous validator
    # caught this in `unmapped_password` and aborted the whole batch; the
    # new contract pseudonymizes content columns upstream so silver lands
    # safely AND publishable intel never carries the WAN address.
    for col in cowrie_silver.columns:
        if cowrie_silver.schema[col] != pl.Utf8:
            continue
        values = cowrie_silver.get_column(col).drop_nulls().to_list()
        for val in values:
            assert HONEYPOT_WAN not in val, (
                f"WAN leak in cowrie silver column {col!r}: {val!r}"
            )

    # Specifically: the WAN-as-password attacker row must have its
    # `unmapped_password` rewritten to the pseudonym.
    wan_as_password_rows = cowrie_silver.filter(
        pl.col("unmapped_password") == "honeypot-wan"
    )
    assert wan_as_password_rows.height == 1, (
        "WAN-as-password attacker must be pseudonymized, not dropped"
    )

    # --- Phase D: gold transform ---
    run_transform(
        target_date=FIXTURE_DATE,
        silver_root=silver_root,
        gold_root=prod_pipeline["gold"],
    )

    expected_tables = (
        "daily_summary",
        "ip_reputation",
        "behavioral_progression",
        "geographic_summary",
        "detection_findings",
        "behavioral_progression_multiday",
    )
    for table in expected_tables:
        parquet = _gold_parquet(table)
        assert parquet.exists(), f"gold table {table} not produced"
        df = pl.read_parquet(parquet)
        assert not df.is_empty(), f"gold table {table} is empty"

    # campaign_clusters: ATTACKER_FULL (admin/admin123 success) + ATTACKER_SPARSE
    # (admin/admin123 failed) share a credential pair → one cluster should form.
    clusters_path = _gold_parquet("campaign_clusters")
    assert clusters_path.exists(), "campaign_clusters should form for shared creds"
    clusters = pl.read_parquet(clusters_path)
    assert clusters.height >= 1

    # ip_reputation tolerates the schema-divergent inputs: row for the rate-limited
    # IP has nulls for the enrichment columns, no crash on optional providers.
    rep = pl.read_parquet(_gold_parquet("ip_reputation"))
    rep_ips = set(rep.get_column("src_endpoint_ip").to_list())
    assert ATTACKER_FULL in rep_ips
    assert ATTACKER_RATE_LIMITED in rep_ips
    assert ATTACKER_SPARSE in rep_ips

    # geographic_summary used the flat geo.country_code column — non-empty top_countries
    geo = pl.read_parquet(_gold_parquet("geographic_summary"))
    top_countries = geo.get_column("top_countries").to_list()[0]
    assert any("BR:" in entry for entry in top_countries), (
        "geo.country_code flat column must reach gold layer"
    )

    # detection_findings: the WAN-source alert was dropped; the two attacker alerts remain.
    findings = pl.read_parquet(_gold_parquet("detection_findings"))
    finding_titles = set(findings.get_column("finding_title").to_list())
    assert "ET SCAN Potential SSH Scan" in finding_titles
    assert "ET EXPLOIT Possible CVE-2021-44228" in finding_titles
    # The WAN-source alert (SURICATA TCPv4 invalid checksum) must NOT survive — it
    # would only be present if drop_infrastructure_source_rows failed.
    assert "SURICATA TCPv4 invalid checksum" not in finding_titles


@pytest.mark.asyncio()
async def test_errors_logged_for_rate_limited_ips(
    prod_pipeline: dict[str, Path],
) -> None:
    """The 429-returning attacker IP must surface in enrichment_errors.json.

    Silence is not success: every provider failure produces a structured
    row, otherwise rate-limit budget exhaustion goes undiagnosed.
    """
    await run_enrichment(
        target_date=FIXTURE_DATE,
        cache_db_path=prod_pipeline["cache"],
        sensor_dir=prod_pipeline["sensor"],
        errors_path=prod_pipeline["errors"],
        provider_state_path=prod_pipeline["provider_state"],
    )

    errors_path = prod_pipeline["errors"]
    assert errors_path.exists(), "rate-limit errors must be recorded"

    import json as _json

    lines = errors_path.read_text(encoding="utf-8").strip().splitlines()
    parsed = [_json.loads(line) for line in lines]
    error_types = {entry["error_type"] for entry in parsed}
    providers = {entry["provider"] for entry in parsed}

    assert "rate_limit" in error_types
    # All four providers see the rate-limited IP at least once → all four records.
    assert {"abuseipdb", "shodan", "virustotal", "greynoise"}.issubset(providers)
    # Nothing should be classified as "unknown" — that would mean an exception
    # leaked past our typed handlers (the bug that defect #2 codified).
    assert "unknown" not in error_types


@pytest.mark.asyncio()
async def test_riot_signal_survives_bronze_to_gold(
    prod_pipeline: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase D.5 load-bearing integration test for the GreyNoise RIOT
    short-circuit.

    The unit test in tests/test_transform/test_metrics.py
    (TestRiskScoreDecomposition.test_riot_with_hot_other_providers)
    pins the composite math at the gold layer. THIS test pins the *data
    flow*: that ``greynoise_riot=True`` and ``greynoise_risk_score=0``
    actually survive bronze → silver → gold through the runner's
    ``_build_lookup`` + ``_merge_lookup``, the normaliser, and the gold
    ``optional`` list in ``compute_ip_reputation``.

    A future refactor that drops ``greynoise_riot`` from any of those
    stages would pass the unit test (it builds silver in-memory) but fail
    here.
    """
    # Override the GreyNoise provider with RIOT-flavoured data. The
    # prod_pipeline fixture's default uses _FULL_ENRICHMENT["greynoise"]
    # with riot=False — we replace it for this test only via monkeypatch.
    riot_data: dict[str, Any] = {
        "greynoise_classification": "malicious",
        "greynoise_noise": True,
        "greynoise_riot": True,            # ← the load-bearing flag
        "greynoise_name": "Censys",
        "greynoise_risk_score": 0.0,        # ← RIOT short-circuit value
    }
    monkeypatch.setattr(
        runner_mod, "GreyNoiseProvider",
        _make_ip_provider_class("greynoise", riot_data),
    )

    # Drive the full pipeline.
    await run_enrichment(
        target_date=FIXTURE_DATE,
        cache_db_path=prod_pipeline["cache"],
        sensor_dir=prod_pipeline["sensor"],
        errors_path=prod_pipeline["errors"],
        provider_state_path=prod_pipeline["provider_state"],
    )
    run_transform(
        target_date=FIXTURE_DATE,
        silver_root=prod_pipeline["silver"],
        gold_root=prod_pipeline["gold"],
    )

    date_str = FIXTURE_DATE.isoformat()

    # --- Silver carries the RIOT signal for the full attacker ---
    cowrie_silver = pl.read_parquet(
        prod_pipeline["silver"] / "dataset=cowrie" / f"date={date_str}"
        / "server=sn-01" / "events.parquet"
    )
    attacker_rows = cowrie_silver.filter(pl.col("src_endpoint_ip") == ATTACKER_FULL)
    assert attacker_rows.height > 0, (
        f"fixture must include events for ATTACKER_FULL ({ATTACKER_FULL})"
    )

    riot_values = attacker_rows.get_column("greynoise_riot").to_list()
    assert all(r is True for r in riot_values), (
        f"greynoise_riot must survive silver write, got {riot_values}. "
        "A failure here means _build_lookup or _merge_lookup is dropping "
        "the boolean column."
    )

    gn_scores = attacker_rows.get_column("greynoise_risk_score").to_list()
    assert all(s == 0.0 for s in gn_scores), (
        f"RIOT must short-circuit greynoise_risk_score to 0 in silver, got {gn_scores}"
    )

    # --- Gold ip_reputation reflects the RIOT pull-down ---
    rep = pl.read_parquet(
        prod_pipeline["gold"] / "ip_reputation" / f"date={date_str}" / "summary.parquet"
    )
    attacker_row = rep.filter(pl.col("src_endpoint_ip") == ATTACKER_FULL).row(0, named=True)

    # The riot bool flag survives the group_by aggregation.
    assert attacker_row["greynoise_riot"] is True, (
        "greynoise_riot dropped between silver and gold — "
        "check compute_ip_reputation's `optional` list"
    )
    assert attacker_row["greynoise_risk_score"] == 0.0

    # The other providers' scores reach gold unchanged.
    assert attacker_row["abuseipdb_risk_score"] == 88.0
    assert attacker_row["virustotal_risk_score"] == 50.0
    assert attacker_row["shodan_risk_score"] == 25.0

    # enrichment_risk_score = mean of all four populated providers, including
    # the RIOT-zero. = (88 + 50 + 25 + 0) / 4 = 40.75.
    # The 0 is included in the mean (it's a real score, not null); without
    # the RIOT short-circuit, GreyNoise would contribute 75 and the mean
    # would be (88 + 50 + 25 + 75) / 4 = 59.5. The 18.75-point gap is
    # exactly what RIOT pulls down.
    assert attacker_row["enrichment_risk_score"] == pytest.approx(40.75)


# ---------------------------------------------------------------------------
# Data-presence regression: pipeline must survive a missing honeypot dataset
# ---------------------------------------------------------------------------


@pytest.fixture()
def prod_pipeline_no_cowrie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    """Same setup as ``prod_pipeline`` but copies only suricata + nftables bronze.

    Simulates an operation that deploys the honeywall + IDS stack without
    any honeypot — cowrie + dionaea partitions are absent. The pipeline
    must produce a coherent brief regardless: data-presence-aware sections
    skip silently, honeywall-driven sections render normally.
    """
    bronze_root = tmp_path / "bronze"
    silver_root = tmp_path / "silver"
    gold_root = tmp_path / "gold"
    cache_db = tmp_path / "cache.db"
    sensor_dir = tmp_path / "sensor"
    errors_path = tmp_path / "enrichment_errors.json"

    sensor_dir.mkdir()
    _copy_bronze_fixtures(bronze_root, include_datasets=frozenset({"suricata", "nftables"}))

    monkeypatch.setattr(datalake_mod, "BRONZE_ROOT", bronze_root)
    monkeypatch.setattr(datalake_mod, "SILVER_ROOT", silver_root)
    monkeypatch.setattr(datalake_mod, "GOLD_ROOT", gold_root)

    real_read_bronze = datalake_mod.read_bronze_ndjson
    real_write_silver = datalake_mod.write_silver_partition

    def _read_bronze(
        target_date: date,
        dataset: str | None = None,
        bronze_root: Path = bronze_root,
    ) -> pl.DataFrame:
        return real_read_bronze(target_date, dataset=dataset, bronze_root=bronze_root)

    def _write_silver(
        df: pl.DataFrame,
        target_date: date,
        dataset: str,
        server: str,
        silver_root: Path = silver_root,
    ) -> Path:
        return real_write_silver(df, target_date, dataset, server, silver_root=silver_root)

    monkeypatch.setattr(runner_mod, "read_bronze_ndjson", _read_bronze)
    monkeypatch.setattr(runner_mod, "write_silver_partition", _write_silver)

    monkeypatch.setattr(runner_mod, "load_secrets", _stub_secrets)
    monkeypatch.setattr(runner_mod, "load_reporting", _stub_reporting)

    monkeypatch.setattr(
        runner_mod, "AbuseIPDBProvider",
        _make_ip_provider_class("abuseipdb", _FULL_ENRICHMENT["abuseipdb"]),
    )
    monkeypatch.setattr(
        runner_mod, "ShodanProvider",
        _make_ip_provider_class("shodan", _FULL_ENRICHMENT["shodan"]),
    )
    monkeypatch.setattr(runner_mod, "VirusTotalProvider", _make_vt_provider_class())
    monkeypatch.setattr(
        runner_mod, "GreyNoiseProvider",
        _make_ip_provider_class("greynoise", _FULL_ENRICHMENT["greynoise"]),
    )

    return {
        "bronze": bronze_root,
        "silver": silver_root,
        "gold": gold_root,
        "cache": cache_db,
        "sensor": sensor_dir,
        "errors": errors_path,
        "provider_state": tmp_path / "provider_state.json",
    }


@pytest.mark.asyncio()
async def test_pipeline_and_brief_survive_missing_cowrie(
    prod_pipeline_no_cowrie: dict[str, Path],
) -> None:
    """When cowrie isn't deployed, the pipeline still produces a valid brief.

    Cowrie-specific gold columns (``top_usernames``/``top_passwords``/
    ``top_commands``/``top_download_*``) end up either absent from the
    summary row or empty lists. The brief must:

    * not crash trying to read those columns,
    * omit the Top Credentials / Top Commands / Malware Captured sections,
    * still render honeywall/suricata-driven sections (Geographic,
      Top Attackers, Findings, Pipeline Health).

    This is the load-bearing regression test for the data-presence rule
    documented in CLAUDE.md ``Pipeline fail-safe principles §3``.
    """
    from lantana.notify.alerts import ErrorBuckets
    from lantana.notify.report import generate_daily_brief

    await run_enrichment(
        target_date=FIXTURE_DATE,
        cache_db_path=prod_pipeline_no_cowrie["cache"],
        sensor_dir=prod_pipeline_no_cowrie["sensor"],
        errors_path=prod_pipeline_no_cowrie["errors"],
        provider_state_path=prod_pipeline_no_cowrie["provider_state"],
    )

    silver_root = prod_pipeline_no_cowrie["silver"]
    gold_root = prod_pipeline_no_cowrie["gold"]
    date_str = FIXTURE_DATE.isoformat()

    # No cowrie/dionaea silver — only the honeywall datasets.
    assert not (silver_root / "dataset=cowrie").exists(), (
        "cowrie silver must not exist when bronze partition is absent"
    )
    assert (silver_root / "dataset=suricata" / f"date={date_str}").exists()
    assert (silver_root / "dataset=nftables" / f"date={date_str}").exists()

    run_transform(
        target_date=FIXTURE_DATE,
        silver_root=silver_root,
        gold_root=gold_root,
    )

    def _gold_parquet(table: str) -> Path:
        return gold_root / table / f"date={date_str}" / "summary.parquet"

    # Honeywall-driven gold tables still produced.
    for table in ("daily_summary", "ip_reputation", "geographic_summary", "detection_findings"):
        path = _gold_parquet(table)
        assert path.exists(), f"{table} should still be produced without cowrie"

    summary = pl.read_parquet(_gold_parquet("daily_summary"))
    reputation = pl.read_parquet(_gold_parquet("ip_reputation"))
    progression_path = _gold_parquet("behavioral_progression")
    progression = (
        pl.read_parquet(progression_path) if progression_path.exists() else pl.DataFrame()
    )
    clusters_path = _gold_parquet("campaign_clusters")
    clusters = (
        pl.read_parquet(clusters_path) if clusters_path.exists() else pl.DataFrame()
    )
    geographic = pl.read_parquet(_gold_parquet("geographic_summary"))
    detection = pl.read_parquet(_gold_parquet("detection_findings"))

    # Sanity: cowrie-specific summary fields are either absent or empty.
    row = summary.row(0, named=True)
    for cowrie_field in ("top_usernames", "top_passwords", "top_commands",
                          "top_download_urls", "top_download_hashes"):
        value = row.get(cowrie_field)
        assert value is None or value == [], (
            f"{cowrie_field} should be absent / empty without cowrie, got {value!r}"
        )
    assert row.get("downloads_captured", 0) in (0, None)
    assert row.get("commands_executed", 0) in (0, None)

    # Generate the brief. Must not raise.
    brief = generate_daily_brief(
        FIXTURE_DATE,
        summary,
        reputation,
        progression,
        clusters,
        "Test Op (no-cowrie)",
        geographic=geographic,
        detection=detection,
        buckets=ErrorBuckets(critical=[], warning=[]),
    )

    # Cowrie-specific sections silently omitted.
    assert "## Top Credentials" not in brief
    assert "## Top Commands" not in brief
    assert "## Malware Captured" not in brief

    # Honeywall-driven sections still present.
    assert "## Key Metrics" in brief
    assert "## Pipeline Health" in brief
    assert "## Geographic Origin" in brief or "## Top Attackers" in brief
    # Detection highlights should land (suricata bronze had alerts).
    assert "## Detection Highlights" in brief

    # IOC inventory: pass the all-dataset silver and check that the IPs block
    # renders without crashing on missing cowrie columns. Hashes/URLs blocks
    # must NOT render — no cowrie partition = no file_hash_sha256 column.
    all_silver = pl.concat(
        [
            pl.read_parquet(silver_root / "dataset=suricata" / f"date={date_str}"
                            / "server=sn-01" / "events.parquet"),
            pl.read_parquet(silver_root / "dataset=nftables" / f"date={date_str}"
                            / "server=sn-01" / "events.parquet"),
        ],
        how="diagonal",
    )
    brief_with_silver = generate_daily_brief(
        FIXTURE_DATE,
        summary,
        reputation,
        progression,
        clusters,
        "Test Op (no-cowrie)",
        geographic=geographic,
        detection=detection,
        buckets=ErrorBuckets(critical=[], warning=[]),
        silver=all_silver,
    )
    # Phase 0: IOC inventory moved to the dashboard's STIX Export page.
    # The brief carries only a pointer line — none of the legacy inline
    # H2 sections must appear, regardless of which silver datasets are
    # present.
    assert "## IP Addresses" not in brief_with_silver
    assert "## File Hashes" not in brief_with_silver
    assert "## Download URLs" not in brief_with_silver
    assert "STIX Export" in brief_with_silver

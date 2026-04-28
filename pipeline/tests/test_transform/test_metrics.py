"""Tests for gold-layer metric computation functions."""

from __future__ import annotations

from datetime import UTC, date, datetime

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
    compute_behavioral_progression_multiday,
    compute_campaign_clusters,
    compute_daily_summary,
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
        rows.append({
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
            "geo.asn": "4134",
            "geo.isp": "ChinaNet",
            "abuseipdb_confidence_score": 85,
            "greynoise_classification": "malicious",
            "greynoise_noise": True,
        })

    # --- attacker-1: auth attempts (2 fail, 1 success) ---
    for i, (user, pw, status) in enumerate([
        ("root", "admin", STATUS_FAILURE),
        ("root", "password", STATUS_FAILURE),
        ("root", "admin", STATUS_SUCCESS),
    ]):
        rows.append({
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
            "geo.asn": "4134",
            "geo.isp": "ChinaNet",
            "abuseipdb_confidence_score": 85,
            "greynoise_classification": "malicious",
            "greynoise_noise": True,
        })

    # --- attacker-1: commands executed ---
    for i, cmd in enumerate(["uname -a", "cat /etc/passwd"]):
        rows.append({
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
            "geo.asn": "4134",
            "geo.isp": "ChinaNet",
            "abuseipdb_confidence_score": 85,
            "greynoise_classification": "malicious",
            "greynoise_noise": True,
        })

    # --- attacker-1: file download (malware) ---
    rows.append({
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
        "geo.asn": "4134",
        "geo.isp": "ChinaNet",
        "abuseipdb_confidence_score": 85,
        "greynoise_classification": "malicious",
        "greynoise_noise": True,
    })

    # --- attacker-1: suricata alert ---
    rows.append({
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
        "geo.asn": "4134",
        "geo.isp": "ChinaNet",
        "abuseipdb_confidence_score": 85,
        "greynoise_classification": "malicious",
        "greynoise_noise": True,
    })

    # --- attacker-2: credential stuffing (15 auth failures, shared creds) ---
    creds = [
        ("root", "admin"), ("root", "password"), ("root", "123456"),
        ("admin", "admin"), ("admin", "password"), ("test", "test"),
        ("root", "root"), ("user", "user"), ("root", "toor"),
        ("admin", "123456"), ("root", "admin"), ("root", "password"),
        ("admin", "admin"), ("root", "admin"), ("root", "letmein"),
    ]
    for i, (user, pw) in enumerate(creds):
        rows.append({
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
            "geo.asn": "12389",
            "geo.isp": "Rostelecom",
            "abuseipdb_confidence_score": 42,
            "greynoise_classification": "benign",
            "greynoise_noise": False,
        })

    # --- attacker-3: scanner only (nftables) ---
    for i in range(3):
        rows.append({
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
            "geo.asn": "15169",
            "geo.isp": "Google",
            "abuseipdb_confidence_score": 10,
            "greynoise_classification": "benign",
            "greynoise_noise": False,
        })

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
        """Top-N lists populated from silver data."""
        result = compute_daily_summary(silver_df)
        row = result.row(0, named=True)
        assert "root" in row["top_usernames"]
        assert "admin" in row["top_passwords"]
        assert "uname -a" in row["top_commands"]
        assert "CN" in row["top_source_countries"]

    def test_empty_dataframe(self) -> None:
        """Empty silver returns empty summary."""
        result = compute_daily_summary(pl.DataFrame())
        assert result.is_empty()


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
        """Attacker-1 (full escalation) has high risk score."""
        result = compute_ip_reputation(silver_df)
        a1 = result.filter(pl.col("src_endpoint_ip") == "203.0.113.50")
        row = a1.row(0, named=True)
        assert row["total_events"] == 9
        assert row["auth_attempts"] == 3
        assert row["auth_successes"] == 1
        assert row["commands_executed"] == 2
        assert row["findings_triggered"] == 1
        assert row["downloads"] == 1
        # Has auth success (+20), commands (+25), findings (+15), downloads (+20),
        # abuseipdb 85*0.3=25.5, volume min(3,100)*0.1=0.3 -> capped at 100
        assert row["risk_score"] >= 95

    def test_scanner_low_risk(self, silver_df: pl.DataFrame) -> None:
        """Scanner-only IP has lower risk score."""
        result = compute_ip_reputation(silver_df)
        a3 = result.filter(pl.col("src_endpoint_ip") == "192.0.2.99")
        row = a3.row(0, named=True)
        assert row["auth_attempts"] == 0
        assert row["commands_executed"] == 0
        # Only abuseipdb 10*0.3=3.0 + volume -> low
        assert row["risk_score"] < 20

    def test_enrichment_columns_present(self, silver_df: pl.DataFrame) -> None:
        """GeoIP and enrichment data carried through."""
        result = compute_ip_reputation(silver_df)
        assert "geo_country" in result.columns
        assert "abuseipdb_score" in result.columns
        assert "greynoise_class" in result.columns

    def test_datasets_tracked(self, silver_df: pl.DataFrame) -> None:
        """Datasets list shows which datasets the IP appeared in."""
        result = compute_ip_reputation(silver_df)
        a1 = result.filter(pl.col("src_endpoint_ip") == "203.0.113.50")
        datasets = set(a1.get_column("datasets").to_list()[0])
        assert datasets == {"cowrie", "nftables", "suricata"}


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
        "geo.asn": "4134",
        "geo.isp": "ChinaNet",
        "abuseipdb_confidence_score": 50,
        "greynoise_classification": "malicious",
        "greynoise_noise": False,
    }


@pytest.fixture()
def multi_day_silver_frames() -> list[tuple[date, pl.DataFrame]]:
    """Build silver frames spanning multiple days for one IP.

    IP 203.0.113.50 ("slow-burn"):
      Day 1 (Apr 20): network scan only -> stage 1
      Day 3 (Apr 22): credential attempts -> stage 2
      Day 5 (Apr 24): successful login + commands -> stage 4
    """
    day1 = date(2026, 4, 20)
    day3 = date(2026, 4, 22)
    day5 = date(2026, 4, 24)

    ip = "203.0.113.50"

    df1 = pl.DataFrame([
        _make_silver_row(ip, CLASS_NETWORK_ACTIVITY, datetime(2026, 4, 20, 10, 0, tzinfo=UTC)),
        _make_silver_row(ip, CLASS_NETWORK_ACTIVITY, datetime(2026, 4, 20, 10, 1, tzinfo=UTC)),
    ])

    df3 = pl.DataFrame([
        _make_silver_row(
            ip, CLASS_AUTHENTICATION, datetime(2026, 4, 22, 14, 0, tzinfo=UTC),
            status_id=STATUS_FAILURE, user_name="root", unmapped_password="admin",
        ),
        _make_silver_row(
            ip, CLASS_AUTHENTICATION, datetime(2026, 4, 22, 14, 1, tzinfo=UTC),
            status_id=STATUS_FAILURE, user_name="root", unmapped_password="password",
        ),
    ])

    df5 = pl.DataFrame([
        _make_silver_row(
            ip, CLASS_AUTHENTICATION, datetime(2026, 4, 24, 8, 0, tzinfo=UTC),
            status_id=STATUS_SUCCESS, user_name="root", unmapped_password="admin",
        ),
        _make_silver_row(
            ip, CLASS_PROCESS_ACTIVITY, datetime(2026, 4, 24, 8, 1, tzinfo=UTC),
            actor_process_cmd_line="uname -a",
        ),
    ])

    return [(day1, df1), (day3, df3), (day5, df5)]


class TestMultiDayBehavioralProgression:
    def test_ip_tracked_across_days(
        self, multi_day_silver_frames: list[tuple[date, pl.DataFrame]]
    ) -> None:
        """IP appears in the multi-day output."""
        result = compute_behavioral_progression_multiday(multi_day_silver_frames)
        assert result.height == 1
        assert result.get_column("src_endpoint_ip").to_list() == ["203.0.113.50"]

    def test_first_last_seen_span_days(
        self, multi_day_silver_frames: list[tuple[date, pl.DataFrame]]
    ) -> None:
        """first_seen_date and last_seen_date span the full range."""
        result = compute_behavioral_progression_multiday(multi_day_silver_frames)
        row = result.row(0, named=True)
        assert row["first_seen_date"] == date(2026, 4, 20)
        assert row["last_seen_date"] == date(2026, 4, 24)

    def test_stage_escalation_across_days(
        self, multi_day_silver_frames: list[tuple[date, pl.DataFrame]]
    ) -> None:
        """IP reaches stage 4 (interactive) across the multi-day window."""
        result = compute_behavioral_progression_multiday(multi_day_silver_frames)
        row = result.row(0, named=True)
        assert row["max_stage"] == 4
        assert row["stage_label"] == "interactive"

    def test_progression_velocity(
        self, multi_day_silver_frames: list[tuple[date, pl.DataFrame]]
    ) -> None:
        """Progression velocity is days between first_seen and max stage."""
        result = compute_behavioral_progression_multiday(multi_day_silver_frames)
        row = result.row(0, named=True)
        # First seen Apr 20, interactive stage reached Apr 24 -> 4 days
        assert row["progression_velocity_days"] == 4

    def test_is_slow_burn(
        self, multi_day_silver_frames: list[tuple[date, pl.DataFrame]]
    ) -> None:
        """IP that escalates across days is flagged as slow burn."""
        result = compute_behavioral_progression_multiday(multi_day_silver_frames)
        row = result.row(0, named=True)
        assert row["is_slow_burn"] is True

    def test_active_days(
        self, multi_day_silver_frames: list[tuple[date, pl.DataFrame]]
    ) -> None:
        """active_days counts distinct calendar days with events."""
        result = compute_behavioral_progression_multiday(multi_day_silver_frames)
        row = result.row(0, named=True)
        assert row["active_days"] == 3

    def test_single_day_not_slow_burn(self, silver_df: pl.DataFrame) -> None:
        """Single-day data produces is_slow_burn=False."""
        frames = [(date(2026, 4, 25), silver_df)]
        result = compute_behavioral_progression_multiday(frames)
        # All IPs active on single day only
        slow_burn = result.filter(pl.col("is_slow_burn"))
        assert slow_burn.height == 0

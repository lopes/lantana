"""End-to-end tests for the air-gapped Vigil dashboard server, routes, windows, and exports."""

from __future__ import annotations

import gzip
import json
import re
import threading
import urllib.error
import urllib.request
from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING

import polars as pl
import pytest

from lantana.common.datalake import write_gold_table, write_silver_partition
from lantana.dashboard.app import create_server
from lantana.dashboard.queries import (
    aggregate_campaign_clusters,
    aggregate_detection_findings,
    build_window_raw_ioc_csv_gz,
    resolve_window,
)
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

FORBIDDEN_EXTERNAL_REFS = (
    "lopes.id",
    "cdn.plot.ly",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "unpkg.com",
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
)


def _seed_datalake(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Create a 2-day synthetic Gold + Silver datalake and reporting.json."""
    gold_root = tmp_path / "gold"
    silver_root = tmp_path / "silver"
    reporting_path = tmp_path / "reporting.json"

    reporting_path.write_text(
        json.dumps(
            {
                "operator": {
                    "name": "Test Op",
                    "handle": "test_op",
                    "contact": "test@example.com",
                    "pgp_fingerprint": "",
                },
                "sharing": {
                    "tlp": "GREEN",
                    "community": "Test",
                    "discord_channel": "lantana-test",
                },
                "operation": {
                    "name": "Op Vigil",
                    "description": "Synthetic test operation",
                    "sector": "technology",
                    "region": "EU",
                    "start_date": "2026-07-01",
                    "expected_datasets": ["cowrie", "suricata"],
                },
                "redact": {
                    "infrastructure_ips": ["192.0.2.10"],
                    "infrastructure_cidrs": ["10.50.99.0/24"],
                    "pseudonym_map": {"192.0.2.10": "honeypot-wan"},
                    "infrastructure_hostnames": ["vps-hidden.example.net"],
                },
            }
        ),
        encoding="utf-8",
    )

    d1 = date(2026, 7, 10)
    d2 = date(2026, 7, 11)
    t1 = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 7, 11, 14, 0, 0, tzinfo=UTC)
    sha1 = "a" * 64

    for d, ts, ip_extra in ((d1, t1, "198.51.100.20"), (d2, t2, "198.51.100.30")):
        write_gold_table(
            pl.DataFrame(
                {
                    "total_events": [120],
                    "unique_source_ips": [2],
                    "auth_attempts": [40],
                    "auth_successes": [5],
                    "auth_failures": [35],
                    "commands_executed": [8],
                    "findings_detected": [12],
                    "network_events": [58],
                    "downloads_captured": [2],
                    "top_usernames": [[{"value": "root", "count": 30}]],
                    "top_passwords": [[{"value": "123456", "count": 20}]],
                    "top_credential_pairs": [
                        [{"username": "root", "password": "123456", "count": 20}]
                    ],
                    "top_commands": [[{"value": "uname -a", "count": 8}]],
                    "top_source_countries": [[{"value": "BR", "count": 2}]],
                    "top_download_hashes": [[{"value": sha1, "count": 2}]],
                }
            ),
            "daily_summary",
            d,
            gold_root=gold_root,
        )
        write_gold_table(
            pl.DataFrame(
                {
                    "src_endpoint_ip": ["203.0.113.50", ip_extra],
                    "risk_score": [82.5, 18.0],
                    "enrichment_risk_score": [90.0, 50.0],
                    "behavioral_risk_score": [75.0, 0.0],
                    "total_events": [90, 30],
                    "auth_attempts": [35, 0],
                    "auth_successes": [5, 0],
                    "commands_executed": [8, 0],
                    "downloads": [2, 0],
                    "findings_triggered": [10, 2],
                    "geo_country": ["BR", "DE"],
                    "geo_city": ["Sao Paulo", "Frankfurt"],
                    "geo_latitude": [-23.55, 50.11],
                    "geo_longitude": [-46.63, 8.68],
                    "geo_asn": [64500, 64501],
                    "geo_isp": ["Example Net", "Scanner ISP"],
                    "greynoise_class": ["malicious", "benign"],
                    "greynoise_name": ["Mirai", "Censys"],
                    "greynoise_riot": [False, False],
                    "shodan_org": ["Example Cloud", "Scanner Org"],
                    "datasets": [["cowrie", "suricata"], ["suricata"]],
                    "first_seen": [ts, ts],
                    "last_seen": [ts, ts],
                }
            ),
            "ip_reputation",
            d,
            gold_root=gold_root,
        )
        write_gold_table(
            pl.DataFrame(
                {
                    "src_endpoint_ip": ["203.0.113.50", ip_extra],
                    "max_stage": [4, 1],
                    "stage_label": ["interactive", "scan"],
                    "is_automated": [False, True],
                    "scan_events": [10, 30],
                    "auth_attempts": [35, 0],
                    "auth_successes": [5, 0],
                    "commands_executed": [8, 0],
                    "seconds_to_auth": [1.5, None],
                    "seconds_to_success": [2.0, None],
                    "seconds_to_command": [5.0, None],
                    "first_seen": [ts, ts],
                    "last_seen": [ts, ts],
                }
            ),
            "behavioral_progression",
            d,
            gold_root=gold_root,
        )
        write_gold_table(
            pl.DataFrame(
                {
                    "cluster_id": ["c1"],
                    "shared_username": ["root"],
                    "shared_password": ["123456"],
                    "ip_count": [2],
                    "ips": [["203.0.113.50", ip_extra]],
                    "total_events": [20],
                    "first_seen": [ts],
                    "last_seen": [ts],
                }
            ),
            "campaign_clusters",
            d,
            gold_root=gold_root,
        )
        write_gold_table(
            pl.DataFrame(
                {
                    "finding_title": ["ET SCAN Potential SSH Scan"],
                    "finding_uid": ["2001219"],
                    "event_count": [12],
                    "unique_ips": [2],
                    "severity_id": [3],
                    "category": ["Attempted Information Leak"],
                    "first_seen": [ts],
                    "last_seen": [ts],
                }
            ),
            "detection_findings",
            d,
            gold_root=gold_root,
        )
        write_gold_table(
            pl.DataFrame(
                {
                    "ioc_type": [
                        "malware_hash",
                        "c2_ip",
                        "stager_url",
                        "stager_domain",
                        "ssh_key",
                        "c2_ip",
                        "stager_domain",
                    ],
                    "ioc_value": [
                        sha1,
                        "203.0.113.88",
                        "http://drop.example.org/bot.elf",
                        "drop.example.org",
                        "ssh-ed25519 SHA256:SyntheticTestFingerprint0000000000000",
                        "1.1.1.1",
                        "raw.githubusercontent.com",
                    ],
                    "vhash": ["vhash123456", None, None, None, None, None, None],
                    "first_seen": [ts, ts, ts, ts, ts, ts, ts],
                    "last_seen": [ts, ts, ts, ts, ts, ts, ts],
                    "event_count": [2, 1, 1, 1, 1, 1, 1],
                    "unique_src_ips": [1, 1, 1, 1, 1, 1, 1],
                    "vt_status": [
                        "found",
                        "found",
                        "found",
                        "found",
                        None,
                        None,
                        None,
                    ],
                    "vt_malicious": [42, 10, 3, 5, None, None, None],
                    "gti_verdict": ["VERDICT_MALICIOUS", None, None, None, None, None, None],
                    "gti_score": [95, None, None, None, None, None, None],
                    "malware_family": ["Mirai", None, None, None, None, None, None],
                    "actor_associations": ["UNC0000", None, None, None, None, None, None],
                    "verification_status": [
                        "verified",
                        "verified",
                        "verified",
                        "verified",
                        "verified",
                        "suppressed",
                        "suppressed",
                    ],
                    "verification_reason": [
                        "captured_artifact",
                        "vt_malicious",
                        "vt_malicious",
                        "vt_malicious",
                        "captured_artifact",
                        "benign_resolver_ip",
                        "shared_hosting_domain",
                    ],
                }
            ),
            "extracted_iocs",
            d,
            gold_root=gold_root,
        )

        # Minimal Silver partition for incremental Raw IOC .csv.gz export
        write_silver_partition(
            pl.DataFrame(
                {
                    "src_endpoint_ip": ["203.0.113.50", ip_extra],
                    "dataset": ["cowrie", "suricata"],
                    "time": [ts, ts],
                    "file_hash_sha256": [sha1, None],
                    "file_url": ["http://drop.example.org/bot.elf", None],
                }
            ),
            d,
            "cowrie",
            "sn-test",
            silver_root=silver_root,
        )

    return gold_root, silver_root, reporting_path


@pytest.fixture()
def live_dashboard(tmp_path: Path) -> Iterator[str]:
    gold_root, silver_root, reporting_path = _seed_datalake(tmp_path)
    server = create_server(
        host="127.0.0.1",
        port=0,
        gold_root=gold_root,
        silver_root=silver_root,
        reporting_path=reporting_path,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _fetch(url: str) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.read()
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, headers, exc.read()


class TestWindowResolutionAndRollups:
    def test_resolve_window_all_five_modes(self) -> None:
        dates = [date(2026, 7, 1) + timedelta(days=i) for i in range(34)]
        w_latest = resolve_window(dates, mode="latest")
        assert w_latest.dates == [date(2026, 8, 3)]

        w_7d = resolve_window(dates, mode="7d")
        assert len(w_7d.dates) == 7
        assert w_7d.dates[-1] == date(2026, 8, 3)

        w_30d = resolve_window(dates, mode="30d")
        assert len(w_30d.dates) == 30

        w_all = resolve_window(dates, mode="all")
        assert len(w_all.dates) == 34

        # Reversed custom dates are normalized cleanly
        w_custom = resolve_window(dates, mode="custom", start="2026-07-10", end="2026-07-05")
        assert w_custom.dates[0] == date(2026, 7, 5)
        assert w_custom.dates[-1] == date(2026, 7, 10)

    def test_multiday_cluster_ip_union_and_findings_ip_days(self, tmp_path: Path) -> None:
        gold_root, silver_root, _ = _seed_datalake(tmp_path)
        dates = [date(2026, 7, 10), date(2026, 7, 11)]

        clusters = aggregate_campaign_clusters(dates, gold_root=gold_root)
        assert clusters.height == 1
        row = clusters.row(0, named=True)
        # Union across day 1 (.50, .20) and day 2 (.50, .30) == 3 distinct IPs
        assert row["ip_count"] == 3
        assert sorted(row["ips"]) == ["198.51.100.20", "198.51.100.30", "203.0.113.50"]

        findings = aggregate_detection_findings(dates, gold_root=gold_root)
        assert findings.height == 1
        frow = findings.row(0, named=True)
        assert frow["finding_uid"] == "2001219"
        assert frow["event_count"] == 24
        assert frow["unique_ips"] == 4  # honest IP-days sum across 2 days

        exported = build_window_raw_ioc_csv_gz(dates, silver_root=silver_root, gold_root=gold_root)
        assert exported is not None
        gz_bytes, count = exported
        assert count >= 5  # 3 IPs + 1 hash + 1 URL
        csv_text = gzip.decompress(gz_bytes).decode("utf-8")
        assert "203.0.113.50" in csv_text
        assert "http://drop.example.org/bot.elf" in csv_text


class TestAirGappedVigilServer:
    @pytest.mark.parametrize(
        "route",
        [
            "/overview",
            "/attackers",
            "/behavior",
            "/intel",
            "/health",
        ],
    )
    def test_all_views_render_200_and_are_strictly_air_gapped(
        self, live_dashboard: str, route: str
    ) -> None:
        for mode in ("latest", "7d", "30d", "all"):
            status, headers, raw = _fetch(f"{live_dashboard}{route}?window={mode}")
            assert status == 200, f"{route}?window={mode} returned {status}"
            body = raw.decode("utf-8")
            assert "/static/vigil.css" in body
            assert "/static/plotly.min.js" in body
            assert "connect-src 'none'" in headers.get("content-security-policy", "")
            assert headers.get("x-frame-options") == "DENY"

            # Air-gap invariant: zero references to lopes.id, CDNs, or Google Fonts
            lowered = body.lower()
            for forbidden in FORBIDDEN_EXTERNAL_REFS:
                assert forbidden not in lowered, f"External ref {forbidden} leaked in {route}"
            # No external <link href="http..."> or <script src="http...">
            assert not re.search(
                r"""<(?:script|link)[^>]+(?:src|href)=["']https?://""",
                body,
                re.IGNORECASE,
            )

        # Custom date range works cleanly too
        status, _, raw = _fetch(
            f"{live_dashboard}{route}?window=custom&start=2026-07-10&end=2026-07-11"
        )
        assert status == 200
        assert "2026-07-10" in raw.decode("utf-8")

    @pytest.mark.parametrize(
        ("legacy_route", "expected_target"),
        [
            ("/ips", "/attackers?window=7d"),
            ("/geography", "/attackers?window=7d#geo-origins"),
            ("/progression", "/behavior?window=7d#prog-funnel"),
            ("/credentials", "/behavior?window=7d#cred-lists"),
            ("/findings", "/behavior?window=7d#find-summary"),
            ("/iocs", "/intel?window=7d#ioc-summary"),
            ("/stix", "/intel?window=7d#stix-export"),
        ],
    )
    def test_legacy_routes_302_redirect_preserving_query_and_anchor(
        self,
        live_dashboard: str,
        legacy_route: str,
        expected_target: str,
    ) -> None:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                req: urllib.request.Request,
                fp: object,
                code: int,
                msg: str,
                headers: object,
                newurl: str,
            ) -> None:
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            opener.open(f"{live_dashboard}{legacy_route}?window=7d", timeout=5)
        assert exc_info.value.code == 302
        assert exc_info.value.headers.get("Location") == expected_target

    def test_legacy_redirect_sanitizes_query_against_header_injection(
        self, live_dashboard: str
    ) -> None:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                req: urllib.request.Request,
                fp: object,
                code: int,
                msg: str,
                headers: object,
                newurl: str,
            ) -> None:
                return None

        opener = urllib.request.build_opener(_NoRedirect)

        # Valid custom date window params are preserved cleanly
        with pytest.raises(urllib.error.HTTPError) as valid_exc:
            opener.open(
                f"{live_dashboard}/stix?window=custom&start=2026-07-10&end=2026-07-11",
                timeout=5,
            )
        assert valid_exc.value.code == 302
        assert (
            valid_exc.value.headers.get("Location")
            == "/intel?window=custom&start=2026-07-10&end=2026-07-11#stix-export"
        )

        # CRLF injection and unknown/invalid parameters are stripped completely
        with pytest.raises(urllib.error.HTTPError) as evil_exc:
            opener.open(
                f"{live_dashboard}/ips?window=7d%0d%0aX-Injected:1&start=bad&evil=1",
                timeout=5,
            )
        assert evil_exc.value.code == 302
        location = evil_exc.value.headers.get("Location") or ""
        assert location == "/attackers"
        assert "\r" not in location and "\n" not in location
        assert "X-Injected" not in location
        assert "evil" not in location

    def test_static_assets_and_vigil_tokens_are_self_contained(self, live_dashboard: str) -> None:
        status_css, headers_css, css_bytes = _fetch(f"{live_dashboard}/static/vigil.css")
        assert status_css == 200
        assert "text/css" in headers_css["content-type"]
        css = css_bytes.decode("utf-8")
        assert "--w-bg:" in css
        assert 'html[data-theme="dark"]' in css
        assert "border-radius: 0 !important;" in css
        for forbidden in FORBIDDEN_EXTERNAL_REFS:
            assert forbidden not in css.lower()
        assert "@import" not in css.lower()

        status_js, headers_js, js_bytes = _fetch(f"{live_dashboard}/static/plotly.min.js")
        assert status_js == 200
        assert "javascript" in headers_js["content-type"]
        assert "immutable" in headers_js.get("cache-control", "")
        assert len(js_bytes) > 100_000

    def test_downloads_stix_and_raw_iocs_csv_gz(self, live_dashboard: str) -> None:
        st_status, st_headers, st_bytes = _fetch(f"{live_dashboard}/download/stix?window=all")
        assert st_status == 200
        assert "attachment" in st_headers.get("content-disposition", "")
        bundle = json.loads(st_bytes.decode("utf-8"))
        assert bundle["type"] == "bundle"
        serialized = json.dumps(bundle)
        assert "http-request-ext" not in serialized
        assert "203.0.113.88" in serialized
        assert "drop.example.org" in serialized
        assert "1.1.1.1" not in serialized
        assert "raw.githubusercontent.com" not in serialized
        assert "192.0.2.10" not in serialized
        assert "vps-hidden.example.net" not in serialized

        # /intel view still shows suppressed IOCs in Observable Inventory with badges/reasons
        intel_status, _, intel_raw = _fetch(f"{live_dashboard}/intel?window=all")
        assert intel_status == 200
        intel_html = intel_raw.decode("utf-8")
        assert "benign_resolver_ip" in intel_html
        assert "shared_hosting_domain" in intel_html
        assert "suppressed" in intel_html

        csv_status, csv_headers, gz_bytes = _fetch(
            f"{live_dashboard}/download/iocs.csv.gz?window=all"
        )
        assert csv_status == 200
        assert "gzip" in csv_headers["content-type"]
        csv_text = gzip.decompress(gz_bytes).decode("utf-8")
        assert "203.0.113.50" in csv_text
        assert "198.51.100.30" in csv_text

    def test_explanations_registry_renders_in_help_blocks(self, live_dashboard: str) -> None:
        import html as html_lib

        status, _, raw = _fetch(f"{live_dashboard}/overview?window=latest")
        assert status == 200
        body = html_lib.unescape(raw.decode("utf-8"))
        assert BRIEF_SECTIONS["Key Metrics"].what in body
        assert METRICS["Total Events"].what in body
        assert METRICS["Malware Uploaded"].what in body

    def test_unknown_route_returns_404(self, live_dashboard: str) -> None:
        status, _, raw = _fetch(f"{live_dashboard}/nonexistent-route")
        assert status == 404
        assert "404" in raw.decode("utf-8")


def test_safe_json_for_script_blocks_html5_double_escape() -> None:
    """Attacker strings with <!--<script> or </script> must be escaped as unicode escapes."""
    from lantana.dashboard.html import safe_json_for_script

    encoded = safe_json_for_script({"payload": "<!--<script>alert(1)</script>"})
    assert "<" not in encoded
    assert ">" not in encoded
    assert "\\u003c" in encoded
    assert "\\u003e" in encoded
    assert json.loads(encoded)["payload"] == "<!--<script>alert(1)</script>"


def test_geography_world_map_is_fully_airgapped_without_scattergeo(live_dashboard: str) -> None:
    """World map on /attackers uses local Cartesian landmass polygons (zero scattergeo XHRs)."""
    status, _, raw = _fetch(f"{live_dashboard}/attackers?window=all")
    assert status == 200
    body = raw.decode("utf-8")
    assert '"scattergeo"' not in body.lower()
    assert '"world-land"' in body
    assert "cdn.plot.ly" not in body.lower()


def test_stix_export_fails_closed_when_reporting_config_missing(tmp_path: Path) -> None:
    """OPSEC: missing/corrupt reporting.json disables STIX export on /intel and returns HTTP 503."""
    gold_root, silver_root, reporting_path = _seed_datalake(tmp_path)
    reporting_path.unlink()  # Remove reporting.json so OPSEC redaction rules cannot load

    server = create_server(
        host="127.0.0.1",
        port=0,
        gold_root=gold_root,
        silver_root=silver_root,
        reporting_path=reporting_path,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        st_status, _, st_raw = _fetch(f"{base}/intel?window=all")
        assert st_status == 200
        st_html = st_raw.decode("utf-8")
        assert "OPSEC Guard" in st_html
        assert "/download/stix" not in st_html

        dl_status, _, _ = _fetch(f"{base}/download/stix?window=all")
        assert dl_status == 503
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_geography_shows_helpful_callout_when_maxmind_geo_is_null(tmp_path: Path) -> None:
    """When MaxMind GeoIP is unconfigured, show a clear callout instead of blank axes."""
    gold_root, silver_root, reporting_path = _seed_datalake(tmp_path)
    d = date(2026, 7, 11)
    ts = datetime(2026, 7, 11, 14, 0, 0, tzinfo=UTC)
    write_gold_table(
        pl.DataFrame(
            {
                "src_endpoint_ip": ["203.0.113.50"],
                "risk_score": [60.0],
                "enrichment_risk_score": [None],
                "behavioral_risk_score": [60.0],
                "total_events": [25],
                "auth_attempts": [10],
                "auth_successes": [2],
                "commands_executed": [3],
                "downloads": [0],
                "findings_triggered": [1],
                "geo_country": [None],
                "geo_city": [None],
                "geo_latitude": [None],
                "geo_longitude": [None],
                "geo_asn": [None],
                "geo_isp": [None],
                "greynoise_class": [None],
                "greynoise_name": [None],
                "greynoise_riot": [None],
                "shodan_org": [None],
                "datasets": [["cowrie"]],
                "first_seen": [ts],
                "last_seen": [ts],
            },
            schema_overrides={
                "enrichment_risk_score": pl.Float64,
                "geo_country": pl.Utf8,
                "geo_city": pl.Utf8,
                "geo_latitude": pl.Float64,
                "geo_longitude": pl.Float64,
                "geo_asn": pl.Int64,
                "geo_isp": pl.Utf8,
                "greynoise_class": pl.Utf8,
                "greynoise_name": pl.Utf8,
                "greynoise_riot": pl.Boolean,
                "shodan_org": pl.Utf8,
            },
        ),
        "ip_reputation",
        d,
        gold_root=gold_root,
    )

    server = create_server(
        host="127.0.0.1",
        port=0,
        gold_root=gold_root,
        silver_root=silver_root,
        reporting_path=reporting_path,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, raw = _fetch(f"http://127.0.0.1:{port}/attackers?window=latest")
        assert status == 200
        body = raw.decode("utf-8")
        assert "vault_apikey_maxmind" in body
        assert "/health" in body
        assert 'id="world-map"' not in body
        assert 'id="top-countries-bar"' not in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_health_dashboard_surfaces_integrations_errors_storage_and_never_leaks_secrets(
    tmp_path: Path,
) -> None:
    """/health surfaces API config, last-run status, storage, liveness, and 0 secrets."""
    gold_root, silver_root, reporting_path = _seed_datalake(tmp_path)
    secrets_path = tmp_path / "secrets.json"
    synthetic_vt = "SYNTHETIC_TEST_VT_SECRET_000000"
    synthetic_abuse = "SYNTHETIC_TEST_ABUSE_SECRET_000000"
    synthetic_discord = "https://discord.example.com/api/webhooks/000000/SYNTHETIC_WEBHOOK_TOKEN"
    secrets_path.write_text(
        json.dumps(
            {
                "vault_apikey_virustotal": synthetic_vt,
                "vault_apikey_abuseipdb": synthetic_abuse,
                "vault_apikey_shodan": None,
                "vault_apikey_greynoise": "",
                "vault_apikey_gti": None,
                "gti_enabled": False,
                "vault_apikey_maxmind": None,
                "vault_webhook_discord": synthetic_discord,
            }
        ),
        encoding="utf-8",
    )

    errors_path = tmp_path / "enrichment_errors.json"
    errors_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "date": "2026-07-11",
                        "provider": "virustotal",
                        "error_type": "auth_failed",
                        "count": 1,
                        "message": "HTTP 401 Unauthorized",
                    }
                ),
                json.dumps(
                    {
                        "date": "2026-07-11",
                        "provider": "greynoise",
                        "error_type": "rate_limit",
                        "count": 5,
                        "message": "HTTP 429 Too Many Requests",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    provider_state_path = tmp_path / ".provider_state.json"
    provider_state_path.write_text(
        json.dumps({"greynoise": {"last_rate_limited": "2026-07-11"}}),
        encoding="utf-8",
    )

    geoip_dir = tmp_path / "geoip"
    geoip_dir.mkdir()

    server = create_server(
        host="127.0.0.1",
        port=0,
        gold_root=gold_root,
        silver_root=silver_root,
        reporting_path=reporting_path,
        secrets_path=secrets_path,
        datalake_root=tmp_path,
        geoip_dir=geoip_dir,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers, raw = _fetch(f"http://127.0.0.1:{port}/health?window=latest")
        assert status == 200
        assert "connect-src 'none'" in headers.get("content-security-policy", "")
        body = raw.decode("utf-8")

        # Integrations & last-run statuses
        assert "AbuseIPDB" in body
        assert "VirusTotal" in body
        assert "Shodan" in body
        assert "GreyNoise" in body
        assert "MaxMind GeoLite2" in body
        assert "Discord Webhook" in body
        assert "Not Configured" in body
        assert "Rate Limit" in body
        assert "1 provider error" in body
        assert "1 rate-limited" in body
        assert METRICS["Overall Status"].what in body
        assert "auth_failed" in body
        assert "HTTP 401 Unauthorized" in body

        # Storage & liveness sections
        assert "Usable Disk" in body
        assert "Bronze" in body
        assert "Silver" in body
        assert "Gold" in body
        assert "cowrie" in body
        assert "suricata" in body

        # OPSEC: zero secret values ever rendered into HTML
        assert synthetic_vt not in body
        assert synthetic_abuse not in body
        assert synthetic_discord not in body
        assert "SYNTHETIC_TEST_" not in body
        assert "SYNTHETIC_WEBHOOK_TOKEN" not in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_health_dashboard_surfaces_sensor_egress_violation_without_wan_ip_leak(
    tmp_path: Path,
) -> None:
    """/health flags non-canary sensor egress drops as Critical and never renders host WAN IP."""
    gold_root, silver_root, reporting_path = _seed_datalake(tmp_path)
    firewall_log = tmp_path / "firewall.log"
    synthetic_wan = "192.0.2.10"
    firewall_log.write_text(
        f"Jul 11 04:15:00 sn-test kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] IN= OUT=enp2s0 "
        f"SRC={synthetic_wan} DST=198.51.100.77 LEN=60 PROTO=TCP SPT=51000 DPT=443 SYN\n"
        "Jul 11 04:16:00 sn-test kernel: [LANTANA_OUTPUT_DROP_SENSOR_LO] IN= OUT=lo "
        "SRC=127.0.0.1 DST=127.0.0.1 LEN=60 PROTO=TCP SPT=51001 DPT=8501 SYN\n",
        encoding="utf-8",
    )

    server = create_server(
        host="127.0.0.1",
        port=0,
        gold_root=gold_root,
        silver_root=silver_root,
        reporting_path=reporting_path,
        datalake_root=tmp_path,
        firewall_log_path=firewall_log,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, raw = _fetch(f"http://127.0.0.1:{port}/health?window=latest")
        assert status == 200
        body = raw.decode("utf-8")
        assert "Sensor Egress" in body
        assert "sensor_egress_blocked" in body
        assert "Critical" in body
        assert synthetic_wan not in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_health_dashboard_surfaces_live_same_day_egress_drop(tmp_path: Path) -> None:
    """Same-day UTC egress drops surface immediately on /health even when Gold is D-1."""
    gold_root, silver_root, reporting_path = _seed_datalake(tmp_path)
    egress_log = tmp_path / "sensor-egress.log"
    today_iso = datetime.now(tz=UTC).date().isoformat()
    egress_log.write_text(
        f"{today_iso}T02:30:00Z sn-test kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] "
        "IN= OUT=enp2s0 SRC=192.0.2.10 DST=198.51.100.77 LEN=60 PROTO=TCP SPT=51000 DPT=443 SYN\n",
        encoding="utf-8",
    )

    server = create_server(
        host="127.0.0.1",
        port=0,
        gold_root=gold_root,
        silver_root=silver_root,
        reporting_path=reporting_path,
        datalake_root=tmp_path,
        firewall_log_path=egress_log,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, raw = _fetch(f"http://127.0.0.1:{port}/health?window=latest")
        assert status == 200
        body = raw.decode("utf-8")
        assert "1 Blocked" in body
        assert "sensor_egress_blocked" in body
        assert "Critical" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_stix_composition_and_multiday_verification_status_precedence(tmp_path: Path) -> None:
    """count_stix_composition mirrors the STIX anti-poisoning gate, and multi-day
    rollups enforce suppressed > verified > unverified status precedence."""
    from lantana.common.config import StixExportConfig
    from lantana.dashboard.queries import aggregate_extracted_iocs, count_stix_composition

    gold_root = tmp_path / "gold"
    d1, d2 = date(2026, 7, 10), date(2026, 7, 11)
    t1 = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 7, 11, 12, 0, 0, tzinfo=UTC)

    # Day 1: unverified URL + verified C2 IP + unverified C2 IP
    write_gold_table(
        pl.DataFrame(
            {
                "ioc_type": ["stager_url", "c2_ip", "c2_ip"],
                "ioc_value": [
                    "http://drop.example.org/stage.sh",
                    "198.51.100.55",
                    "198.51.100.77",
                ],
                "vhash": [None, None, None],
                "first_seen": [t1, t1, t1],
                "last_seen": [t1, t1, t1],
                "event_count": [1, 1, 1],
                "unique_src_ips": [1, 1, 1],
                "vt_status": ["not_found", "found", None],
                "vt_malicious": [None, 5, None],
                "gti_verdict": [None, None, None],
                "gti_score": [None, None, None],
                "malware_family": [None, None, None],
                "actor_associations": [None, None, None],
                "verification_status": ["unverified", "verified", "unverified"],
                "verification_reason": ["uncorroborated", "vt_malicious", "uncorroborated"],
            }
        ),
        "extracted_iocs",
        d1,
        gold_root=gold_root,
    )
    # Day 2: URL becomes verified; .55 becomes suppressed (GreyNoise RIOT); .77 stays unverified
    write_gold_table(
        pl.DataFrame(
            {
                "ioc_type": ["stager_url", "c2_ip", "c2_ip"],
                "ioc_value": [
                    "http://drop.example.org/stage.sh",
                    "198.51.100.55",
                    "198.51.100.77",
                ],
                "vhash": [None, None, None],
                "first_seen": [t2, t2, t2],
                "last_seen": [t2, t2, t2],
                "event_count": [2, 1, 1],
                "unique_src_ips": [1, 1, 1],
                "vt_status": ["found", "found", None],
                "vt_malicious": [3, 5, None],
                "gti_verdict": [None, None, None],
                "gti_score": [None, None, None],
                "malware_family": [None, None, None],
                "actor_associations": [None, None, None],
                "verification_status": ["verified", "suppressed", "unverified"],
                "verification_reason": ["vt_malicious", "greynoise_riot", "uncorroborated"],
            }
        ),
        "extracted_iocs",
        d2,
        gold_root=gold_root,
    )

    rolled = aggregate_extracted_iocs([d1, d2], gold_root=gold_root)
    by_val = {r["ioc_value"]: r for r in rolled.iter_rows(named=True)}
    assert by_val["http://drop.example.org/stage.sh"]["verification_status"] == "verified"
    assert by_val["http://drop.example.org/stage.sh"]["verification_reason"] == "vt_malicious"
    assert by_val["198.51.100.55"]["verification_status"] == "suppressed"
    assert by_val["198.51.100.55"]["verification_reason"] == "greynoise_riot"
    assert by_val["198.51.100.77"]["verification_status"] == "unverified"

    comp_default = count_stix_composition(pl.DataFrame(), pl.DataFrame(), rolled)
    assert comp_default["stager_urls"] == 1
    assert comp_default["c2_ips"] == 0

    comp_opt_in = count_stix_composition(
        pl.DataFrame(),
        pl.DataFrame(),
        rolled,
        stix_config=StixExportConfig(include_unverified_outbound=True),
    )
    assert comp_opt_in["stager_urls"] == 1
    assert comp_opt_in["c2_ips"] == 1

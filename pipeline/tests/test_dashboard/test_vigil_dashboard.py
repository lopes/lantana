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
                    ],
                    "ioc_value": [
                        sha1,
                        "203.0.113.88",
                        "http://drop.example.org/bot.elf",
                        "drop.example.org",
                        "ssh-ed25519 SHA256:SyntheticTestFingerprint0000000000000",
                    ],
                    "vhash": ["vhash123456", None, None, None, None],
                    "first_seen": [ts, ts, ts, ts, ts],
                    "last_seen": [ts, ts, ts, ts, ts],
                    "event_count": [2, 1, 1, 1, 1],
                    "unique_src_ips": [1, 1, 1, 1, 1],
                    "vt_status": ["found", "found", "not_found", "not_found", None],
                    "vt_malicious": [42, 10, None, None, None],
                    "gti_verdict": ["VERDICT_MALICIOUS", None, None, None, None],
                    "gti_score": [95, None, None, None, None],
                    "malware_family": ["Mirai", None, None, None, None],
                    "actor_associations": ["UNC0000", None, None, None, None],
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
            "/iocs",
            "/ips",
            "/geography",
            "/credentials",
            "/progression",
            "/findings",
            "/stix",
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
        assert "192.0.2.10" not in serialized
        assert "vps-hidden.example.net" not in serialized

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
    """World map uses local Cartesian landmass polygons (zero scattergeo / cdn.plot.ly XHRs)."""
    status, _, raw = _fetch(f"{live_dashboard}/geography?window=all")
    assert status == 200
    body = raw.decode("utf-8")
    assert '"scattergeo"' not in body.lower()
    assert '"world-land"' in body
    assert "cdn.plot.ly" not in body.lower()


def test_stix_export_fails_closed_when_reporting_config_missing(tmp_path: Path) -> None:
    """OPSEC: missing/corrupt reporting.json disables /stix and returns HTTP 503."""
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
        st_status, _, st_raw = _fetch(f"{base}/stix?window=all")
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

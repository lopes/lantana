"""Tests for OPSEC-safe sensor egress drop log parsing (lantana.notify.egress)."""

from __future__ import annotations

import gzip
from datetime import date
from pathlib import Path  # noqa: TC003 — used at runtime in tmp_path fixtures

from lantana.notify.egress import (
    SensorEgressSummary,
    collect_sensor_egress_summary,
    evaluate_sensor_egress_alerts,
)


class TestCollectSensorEgressSummary:
    def test_returns_none_when_firewall_log_absent(self, tmp_path: Path) -> None:
        """Multi-node collectors have no local honeywall firewall.log -> None."""
        assert (
            collect_sensor_egress_summary(
                date(2026, 7, 16),
                firewall_log_path=tmp_path / "missing.log",
            )
            is None
        )

    def test_parses_wan_local_forward_and_separates_canary_without_leaking_src_ip(
        self, tmp_path: Path
    ) -> None:
        log_path = tmp_path / "firewall.log"
        rotated_path = tmp_path / "firewall.log.1"

        # Synthetic WAN IP that must NEVER appear in the parsed summary or alerts
        synthetic_wan = "203.0.113.42"

        log_path.write_text(
            "\n".join(
                [
                    # Target date: WAN drop (non-canary -> real violation)
                    "Jul 16 03:12:01 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] "
                    f"IN= OUT=enp2s0 SRC={synthetic_wan} DST=198.51.100.77 "
                    "LEN=60 PROTO=TCP SPT=51234 DPT=443 SYN",
                    # Target date: Loopback Vigil probe (non-canary -> real violation)
                    "Jul 16 03:12:05 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_LO] "
                    "IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 "
                    "LEN=60 PROTO=TCP SPT=51235 DPT=8501 SYN",
                    # Target date: RFC 5737 canary WAN probe -> counted as canary only
                    "Jul 16 03:13:00 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] "
                    f"IN= OUT=enp2s0 SRC={synthetic_wan} DST=198.51.100.250 "
                    "LEN=60 PROTO=UDP SPT=51236 DPT=53",
                    # Target date: loopback canary port 1 -> counted as canary only
                    "Jul 16 03:13:01 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_LO] "
                    "IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 "
                    "LEN=60 PROTO=TCP SPT=51237 DPT=1 SYN",
                    # Unrelated INPUT drop -> must be ignored
                    "Jul 16 03:14:00 sn-01 kernel: [LANTANA_INPUT_DROP] "
                    f"IN=enp2s0 OUT= SRC=192.0.2.99 DST={synthetic_wan} "
                    "LEN=40 PROTO=TCP SPT=12345 DPT=9999 SYN",
                    # Different date -> must be ignored
                    "Jul 15 23:59:59 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] "
                    f"IN= OUT=enp2s0 SRC={synthetic_wan} DST=198.51.100.88 "
                    "LEN=60 PROTO=TCP SPT=50000 DPT=443 SYN",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        # Rotated .1 file holds an earlier target-date multi-node FORWARD_DROP_EGRESS line
        rotated_path.write_text(
            "Jul 16 00:05:10 hw-01 kernel: [LANTANA_FORWARD_DROP_EGRESS] IN=ens4 OUT=enp2s0 "
            "SRC=10.50.99.100 DST=198.51.100.77 LEN=60 PROTO=UDP SPT=45000 DPT=53\n",
            encoding="utf-8",
        )

        summary = collect_sensor_egress_summary(
            date(2026, 7, 16),
            firewall_log_path=log_path,
        )
        assert isinstance(summary, SensorEgressSummary)
        assert summary.wan_drops == 2  # OUTPUT_DROP_SENSOR_WAN + FORWARD_DROP_EGRESS
        assert summary.local_drops == 1  # OUTPUT_DROP_SENSOR_LO (port 8501)
        assert summary.canary_drops == 2  # 198.51.100.250 + loopback port 1
        assert summary.total_violations == 3
        assert ("tcp", 443) in summary.top_targets
        assert ("tcp", 8501) in summary.top_targets
        assert ("udp", 53) in summary.top_targets

        alerts = evaluate_sensor_egress_alerts(date(2026, 7, 16), summary)
        assert len(alerts) == 1
        row = alerts[0]
        assert row["error_type"] == "sensor_egress_blocked"
        assert row["provider"] == "firewall"
        assert row["count"] == 3
        msg = str(row["message"])
        assert "2 WAN" in msg
        assert "1 local/loopback" in msg
        assert synthetic_wan not in msg
        assert "10.50.99.100" not in msg

    def test_canary_only_drops_emit_zero_alerts(self, tmp_path: Path) -> None:
        log_path = tmp_path / "firewall.log"
        log_path.write_text(
            "Jul 16 03:13:00 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] IN= OUT=enp2s0 "
            "SRC=203.0.113.42 DST=198.51.100.250 LEN=60 PROTO=TCP SPT=51236 DPT=443\n",
            encoding="utf-8",
        )
        summary = collect_sensor_egress_summary(date(2026, 7, 16), firewall_log_path=log_path)
        assert summary is not None
        assert summary.canary_drops == 1
        assert summary.total_violations == 0
        assert evaluate_sensor_egress_alerts(date(2026, 7, 16), summary) == []

    def test_single_digit_day_syslog_padding_matches_target_date(self, tmp_path: Path) -> None:
        log_path = tmp_path / "sensor-egress.log"
        # Syslog pads days 1..9 with two spaces: "Jul  5 01:00:00"
        log_path.write_text(
            "Jul  5 01:00:00 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] IN= OUT=enp2s0 "
            "SRC=203.0.113.42 DST=192.0.2.55 LEN=60 PROTO=TCP SPT=51236 DPT=443\n",
            encoding="utf-8",
        )
        summary = collect_sensor_egress_summary(date(2026, 7, 5), firewall_log_path=log_path)
        assert summary is not None
        assert summary.wan_drops == 1

    def test_ltn0_port_1_not_masked_as_canary_and_proto_is_sanitized_and_gz_read(
        self, tmp_path: Path
    ) -> None:
        log_path = tmp_path / "sensor-egress.log"
        gz_path = tmp_path / "sensor-egress.log.2.gz"

        # 10.50.99.10:1 over ltn0 must NOT be treated as a loopback canary, and
        # crafted PROTO= values must be sanitized to "unknown".
        log_path.write_text(
            "Jul 16 05:00:00 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_LO] "
            "IN= OUT=ltn0 SRC=10.50.99.100 DST=10.50.99.10 LEN=60 "
            "PROTO=TCP SPT=51234 DPT=1 SYN\n"
            "Jul 16 05:01:00 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] "
            "IN= OUT=enp2s0 SRC=203.0.113.42 DST=198.51.100.77 LEN=60 "
            "PROTO=[bad](https://evil.example) SPT=51235 DPT=443 SYN\n",
            encoding="utf-8",
        )
        with gzip.open(gz_path, "wt", encoding="utf-8") as fh:
            fh.write(
                "Jul 17 01:00:00 sn-01 kernel: [LANTANA_OUTPUT_DROP_SENSOR_WAN] "
                "IN= OUT=enp2s0 SRC=203.0.113.42 DST=198.51.100.99 LEN=60 "
                "PROTO=UDP SPT=55555 DPT=53\n"
            )

        summary = collect_sensor_egress_summary(
            date(2026, 7, 16),
            firewall_log_path=log_path,
            extra_dates=[date(2026, 7, 17)],
        )
        assert summary is not None
        assert summary.canary_drops == 0
        assert summary.local_drops == 1
        assert summary.wan_drops == 2
        assert ("tcp", 1) in summary.top_targets
        assert ("unknown", 443) in summary.top_targets
        assert ("udp", 53) in summary.top_targets
        alerts = evaluate_sensor_egress_alerts(date(2026, 7, 16), summary)
        assert "evil.example" not in alerts[0]["message"]

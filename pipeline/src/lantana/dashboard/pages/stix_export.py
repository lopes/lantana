"""STIX Export page — generate, preview, and download daily IOC artifacts.

Two artifacts share this page:

- **STIX 2.1 bundle** — curated indicators (IPs above the risk threshold,
  file hashes from captured malware, broad-rule detection findings),
  Malware/Campaign SDOs, and Relationships. Suitable for OpenCTI/MISP.
- **Raw IOC export (.csv.gz)** — every silver IOC observed on the date,
  with risk_score, dataset, count, and seen-timestamps. Same OPSEC
  redaction as silver; covers the long tail STIX intentionally drops.

Domain indicators are not yet emitted — Suricata HTTP enrichment is
deferred per ``enrichment/ioc.py``.
"""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table, read_silver_partition
from lantana.intel.stix import RISK_THRESHOLD


def _ip_indicator_count(reputation: pl.DataFrame) -> int:
    """Match the filter ``_make_indicators`` applies in intel/stix.py."""
    if reputation.is_empty():
        return 0
    return reputation.filter(pl.col("risk_score") >= RISK_THRESHOLD).height


def _hash_indicator_count(summary: pl.DataFrame) -> int:
    """Match ``_make_malware_indicators`` — one indicator per top hash."""
    if summary.is_empty():
        return 0
    hashes = summary.row(0, named=True).get("top_download_hashes") or []
    return len(hashes)


def _network_rule_indicator_count(detection: pl.DataFrame) -> int:
    """Match ``_make_finding_indicators`` — rules with unique_ips >= 5."""
    if detection.is_empty():
        return 0
    return detection.filter(pl.col("unique_ips") >= 5).height


def render(selected_date: date) -> None:
    """Render the STIX export page for the selected date."""
    st.header(f"STIX Export — {selected_date.isoformat()}")
    st.caption(
        "Curated indicators ready for OpenCTI / MISP, plus a long-tail raw "
        "IOC dump for retro-hunting and lake correlation."
    )

    summary = read_gold_table("daily_summary", selected_date)
    reputation = read_gold_table("ip_reputation", selected_date)
    progression = read_gold_table("behavioral_progression", selected_date)
    clusters = read_gold_table("campaign_clusters", selected_date)
    detection = read_gold_table("detection_findings", selected_date)

    if summary.is_empty():
        st.info("No data available for this date.")
        return

    # --- Bundle composition preview ---
    st.subheader("Bundle Composition")
    st.caption(
        "What the STIX 2.1 bundle will contain when generated. Counts mirror "
        f"the filters in ``intel/stix.py``: IP indicators apply ``risk_score "
        f"≥ {RISK_THRESHOLD:.0f}``; network-rule indicators apply "
        "``unique_ips ≥ 5``."
    )

    ip_n = _ip_indicator_count(reputation)
    hash_n = _hash_indicator_count(summary)
    rule_n = _network_rule_indicator_count(detection)
    campaign_n = clusters.height if not clusters.is_empty() else 0

    cols = st.columns(4)
    cols[0].metric(
        "IP Indicators", ip_n,
        help=(
            f"Attacker IPs with risk_score ≥ {RISK_THRESHOLD:.0f} that become "
            "STIX `[ipv4-addr:value = …]` Indicator objects. Drives the "
            "Discord top-N and the OpenCTI feed."
        ),
    )
    cols[1].metric(
        "Hash Indicators", hash_n,
        help=(
            "File SHA256s captured from cowrie downloads. Each emits a "
            "STIX `[file:hashes.'SHA-256' = …]` Indicator plus a matching "
            "Malware SDO."
        ),
    )
    cols[2].metric(
        "Network-rule Indicators", rule_n,
        help=(
            "Suricata rules triggered by ≥ 5 unique source IPs — broad enough "
            "to be worth sharing as intel. Each emits one STIX Indicator "
            "with a `network-traffic` pattern."
        ),
    )
    cols[3].metric(
        "Campaigns", campaign_n,
        help=(
            "Credential-stuffing clusters: distinct username:password pairs "
            "reused by ≥ 2 source IPs. Become STIX Campaign SDOs."
        ),
    )

    st.caption(
        "_Domain indicators are not yet emitted — deferred until Suricata "
        "HTTP fields surface in bronze (see ``enrichment/ioc.py``)._"
    )

    st.divider()

    # --- STIX bundle generation + download ---
    st.subheader("Generate STIX 2.1 Bundle")
    if st.button("Generate STIX 2.1 Bundle"):
        try:
            from lantana.common.config import load_reporting
            from lantana.intel.stix import generate_bundle

            reporting = load_reporting()
            bundle = generate_bundle(
                selected_date,
                reporting,
                reputation,
                progression,
                clusters,
                summary=summary,
                detection=detection,
            )
            json_str = bundle.serialize(pretty=True)

            st.success(f"Bundle generated: {len(bundle.objects)} objects")
            st.download_button(
                label="Download STIX Bundle (.json)",
                data=json_str,
                file_name=f"lantana-stix-{selected_date.isoformat()}.json",
                mime="application/json",
            )
            with st.expander("Preview JSON"):
                st.code(json_str[:5000], language="json")

        except FileNotFoundError:
            st.error("reporting.json not found. Deploy config first.")
        except Exception as e:
            st.error(f"Bundle generation failed: {e}")

    st.divider()

    # --- Raw IOC export ---
    st.subheader("Raw IOC Export")
    st.caption(
        "Every IP / hash / URL observed on the date — including the long "
        "tail STIX drops. Use for retro-hunting, IDS rule seeding, and lake "
        "correlation. Output is gzipped CSV."
    )

    from lantana.intel.iocs import build_raw_ioc_export

    silver = read_silver_partition(selected_date)
    csv_gz = build_raw_ioc_export(silver, reputation)
    if csv_gz is None:
        st.info("No silver IOCs available for this date.")
    else:
        data, count = csv_gz
        st.metric("IOCs available", count)
        st.download_button(
            label="Download Raw IOCs (.csv.gz)",
            data=data,
            file_name=f"lantana-iocs-{selected_date.isoformat()}.csv.gz",
            mime="application/gzip",
        )

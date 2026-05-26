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
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS


def _metric_help(name: str) -> str | None:
    triplet = METRICS.get(name)
    return triplet.tooltip() if triplet is not None else None


def _section_caption(name: str) -> str | None:
    triplet = BRIEF_SECTIONS.get(name)
    return triplet.tooltip() if triplet is not None else None


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
    page_caption = _section_caption("STIX Export")
    if page_caption:
        st.caption(page_caption)

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
    bundle_caption = _section_caption("Bundle Composition")
    if bundle_caption:
        st.caption(bundle_caption)

    ip_n = _ip_indicator_count(reputation)
    hash_n = _hash_indicator_count(summary)
    rule_n = _network_rule_indicator_count(detection)
    campaign_n = clusters.height if not clusters.is_empty() else 0

    cols = st.columns(4)
    cols[0].metric("IP Indicators", ip_n, help=_metric_help("IP Indicators"))
    cols[1].metric("Hash Indicators", hash_n, help=_metric_help("Hash Indicators"))
    cols[2].metric(
        "Network-rule Indicators", rule_n,
        help=_metric_help("Network-rule Indicators"),
    )
    cols[3].metric("Campaigns", campaign_n, help=_metric_help("Campaigns"))

    # Domain-indicator footnote stays inline — it's a defer-status note,
    # not an explanation of an existing widget. References enrichment/ioc.py
    # so promoting it to the registry would lose the file pointer.
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
    raw_caption = _section_caption("Raw IOC Export")
    if raw_caption:
        st.caption(raw_caption)

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

"""STIX Export page — generate and download STIX 2.1 bundles."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import streamlit as st

from lantana.common.datalake import read_gold_table


def render(selected_date: date) -> None:
    """Render the STIX export page for the selected date."""
    st.header(f"STIX Export — {selected_date.isoformat()}")

    summary = read_gold_table("daily_summary", selected_date)
    reputation = read_gold_table("ip_reputation", selected_date)
    progression = read_gold_table("behavioral_progression", selected_date)
    clusters = read_gold_table("campaign_clusters", selected_date)

    if summary.is_empty():
        st.info("No data available for this date.")
        return

    row = summary.row(0, named=True)

    st.subheader("Bundle Preview")

    cols = st.columns(3)
    cols[0].metric("Indicators (IPs)", row["unique_source_ips"])
    cols[1].metric("Campaigns", clusters.height if not clusters.is_empty() else 0)
    cols[2].metric("Detection Findings", row["findings_detected"])

    if not reputation.is_empty():
        from lantana.intel.stix import RISK_THRESHOLD

        above = reputation.filter(reputation["risk_score"] >= RISK_THRESHOLD).height
        st.metric(f"IPs above risk threshold ({RISK_THRESHOLD})", above)

    st.divider()

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

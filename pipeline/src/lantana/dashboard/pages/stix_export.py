"""STIX Export page -- preview and download placeholder."""

from __future__ import annotations

from datetime import date  # noqa: TC003 -- runtime parameter type

import streamlit as st

from lantana.common.datalake import read_gold_table


def render(selected_date: date) -> None:
    """Render the STIX export page for the selected date."""
    st.header(f"STIX Export -- {selected_date.isoformat()}")

    summary = read_gold_table("daily_summary", selected_date)
    reputation = read_gold_table("ip_reputation", selected_date)

    if summary.is_empty():
        st.info("No data available for this date.")
        return

    row = summary.row(0, named=True)

    st.subheader("Export Preview")
    st.caption("Summary of objects that would be included in a STIX 2.1 bundle.")

    cols = st.columns(3)
    cols[0].metric("Indicators (IPs)", row["unique_source_ips"])
    cols[1].metric("Attack Patterns", row["commands_executed"])
    cols[2].metric("Detection Findings", row["findings_detected"])

    if not reputation.is_empty():
        high_risk = reputation.filter(reputation["risk_score"] >= 70).height
        st.metric("High-Risk Indicators", high_risk)

    st.divider()
    st.info("STIX 2.1 bundle generation will be available in a future release (task 1.11).")

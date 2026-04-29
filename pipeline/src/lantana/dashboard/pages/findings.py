"""Detection Findings page — Suricata and IDS detection summaries."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import streamlit as st

from lantana.common.datalake import read_gold_table


def render(selected_date: date) -> None:
    """Render the detection findings page for the selected date."""
    st.header(f"Detection Findings — {selected_date.isoformat()}")

    df = read_gold_table("detection_findings", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    # Summary metrics
    cols = st.columns(3)
    cols[0].metric("Total Rules", len(df))
    cols[1].metric("Total Events", f"{df['event_count'].sum():,}")
    cols[2].metric("Total Unique IPs", f"{df['unique_ips'].sum():,}")

    st.divider()

    # Bar chart of top rules by event_count
    st.subheader("Top Rules by Event Count")
    top_rules = df.sort("event_count", descending=True).head(20)
    st.bar_chart(
        top_rules.to_pandas(),
        x="event_count",
        y="finding_title",
        horizontal=True,
    )

    st.divider()

    # Detail table
    st.subheader("All Findings")
    display_cols = [
        "finding_title",
        "event_count",
        "unique_ips",
        "severity_id",
        "category",
        "first_seen",
        "last_seen",
    ]
    available_cols = [c for c in display_cols if c in df.columns]

    st.dataframe(
        df.select(available_cols).to_pandas(),
        hide_index=True,
        use_container_width=True,
    )

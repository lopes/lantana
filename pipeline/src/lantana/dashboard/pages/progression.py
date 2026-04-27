"""Behavioral Progression page -- escalation analysis."""

from __future__ import annotations

from datetime import date  # noqa: TC003 -- runtime parameter type

import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table


def render(selected_date: date) -> None:
    """Render the behavioral progression page for the selected date."""
    st.header(f"Behavioral Progression -- {selected_date.isoformat()}")

    df = read_gold_table("behavioral_progression", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    # Stage funnel metrics
    st.subheader("Escalation Funnel")
    cols = st.columns(4)
    for i, (stage, label) in enumerate([
        (1, "Scan"),
        (2, "Credential"),
        (3, "Authenticated"),
        (4, "Interactive"),
    ]):
        count = df.filter(pl.col("max_stage") >= stage).height
        cols[i].metric(label, count)

    st.divider()

    # Automated vs manual breakdown
    auto_count = df.filter(pl.col("is_automated")).height
    manual_count = len(df) - auto_count
    a_col, m_col, _ = st.columns(3)
    a_col.metric("Automated Bots", auto_count)
    m_col.metric("Manual / Unknown", manual_count)

    st.divider()

    # Stage scatter plot (stage vs first_seen, colored by automated)
    st.subheader("Stage vs Time")
    if "first_seen" in df.columns and "max_stage" in df.columns:
        chart_df = df.select(
            pl.col("first_seen").cast(pl.Utf8).alias("First Seen"),
            pl.col("max_stage").alias("Stage"),
            pl.col("is_automated")
            .map_elements(lambda x: "Automated" if x else "Manual", return_dtype=pl.Utf8)
            .alias("Type"),
        ).to_pandas()
        st.scatter_chart(chart_df, x="First Seen", y="Stage", color="Type")

    st.divider()

    # Detailed table
    st.subheader("IP Progression Details")

    display_cols = [
        "src_endpoint_ip",
        "max_stage",
        "stage_label",
        "is_automated",
        "scan_events",
        "auth_attempts",
        "auth_successes",
        "commands_executed",
        "seconds_to_auth",
        "seconds_to_success",
        "seconds_to_command",
        "first_seen",
        "last_seen",
    ]
    available_cols = [c for c in display_cols if c in df.columns]

    # Stage filter
    min_stage = st.selectbox("Minimum stage", [1, 2, 3, 4], index=0)
    filtered = df.filter(pl.col("max_stage") >= min_stage)

    st.dataframe(
        filtered.select(available_cols).to_pandas(),
        hide_index=True,
        use_container_width=True,
    )

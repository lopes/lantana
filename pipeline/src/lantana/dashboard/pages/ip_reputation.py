"""IP Reputation page — risk scores and enrichment details."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table


def _risk_label(score: float) -> str:
    """Map risk score to human-readable label."""
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def render(selected_date: date) -> None:
    """Render the IP reputation page for the selected date."""
    st.header(f"IP Reputation — {selected_date.isoformat()}")

    df = read_gold_table("ip_reputation", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    # Summary metrics
    cols = st.columns(4)
    cols[0].metric("Total IPs", len(df))
    high = df.filter(pl.col("risk_score") >= 70).height
    med = df.filter((pl.col("risk_score") >= 40) & (pl.col("risk_score") < 70)).height
    low = df.filter(pl.col("risk_score") < 40).height
    cols[1].metric("High Risk", high)
    cols[2].metric("Medium Risk", med)
    cols[3].metric("Low Risk", low)

    st.divider()

    # Risk distribution
    st.subheader("Risk Score Distribution")
    st.bar_chart(
        df.select("risk_score").to_pandas(),
        x=None,
        y="risk_score",
    )

    st.divider()

    # IP table with risk labels
    st.subheader("IP Details")

    display_df = df.with_columns(
        pl.col("risk_score").map_elements(_risk_label, return_dtype=pl.Utf8).alias("risk_level"),
    )

    # Select columns for display
    display_cols = [
        "src_endpoint_ip",
        "risk_score",
        "risk_level",
        "total_events",
        "geo_country",
        "auth_attempts",
        "auth_successes",
        "commands_executed",
        "findings_triggered",
        "abuseipdb_score",
        "greynoise_class",
    ]
    available_cols = [c for c in display_cols if c in display_df.columns]

    # Min risk filter
    min_risk = st.slider("Minimum risk score", 0, 100, 0)
    filtered = display_df.filter(pl.col("risk_score") >= min_risk)

    st.dataframe(
        filtered.select(available_cols).to_pandas(),
        hide_index=True,
        use_container_width=True,
    )

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

    # Risk distribution — composite + Phase D.2 decomposition side-by-side
    st.subheader("Risk Score Distribution")
    if "enrichment_risk_score" in df.columns and "behavioral_risk_score" in df.columns:
        chart_cols = st.columns(3)
        chart_cols[0].caption("Composite (final risk_score)")
        chart_cols[0].bar_chart(df.select("risk_score").to_pandas(), y="risk_score")
        chart_cols[1].caption("Enrichment half (mean of populated providers)")
        chart_cols[1].bar_chart(
            df.select("enrichment_risk_score").to_pandas(), y="enrichment_risk_score",
        )
        chart_cols[2].caption("Behavioral half (auth + commands + downloads + ...)")
        chart_cols[2].bar_chart(
            df.select("behavioral_risk_score").to_pandas(), y="behavioral_risk_score",
        )
    else:
        # Pre-Phase-D.2 gold partition fallback.
        st.bar_chart(df.select("risk_score").to_pandas(), y="risk_score")

    st.divider()

    # IP table with risk labels
    st.subheader("IP Details")

    display_df = df.with_columns(
        pl.col("risk_score").map_elements(_risk_label, return_dtype=pl.Utf8).alias("risk_level"),
    )

    # Select columns for display. Per-provider risk_scores sit immediately
    # after the composite + breakdown so the relationship is scannable.
    display_cols = [
        "src_endpoint_ip",
        "risk_score",
        "risk_level",
        "enrichment_risk_score",
        "behavioral_risk_score",
        "abuseipdb_risk_score",
        "virustotal_risk_score",
        "shodan_risk_score",
        "greynoise_risk_score",
        "total_events",
        "geo_country",
        "geo_city",
        "auth_attempts",
        "auth_successes",
        "commands_executed",
        "findings_triggered",
        "abuseipdb_score",
        "abuseipdb_reports",
        "greynoise_class",
        "greynoise_name",
        "greynoise_riot",
        "vt_malicious",
        "shodan_ports",
        "shodan_os",
        "shodan_vulns",
        "shodan_org",
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

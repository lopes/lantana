"""Behavioral Progression page — escalation funnel + multi-day rollup."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import plotly.express as px
import plotly.graph_objects as go
import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS

_STAGE_LABELS_BY_NUM: dict[int, str] = {
    1: "Scan",
    2: "Credential",
    3: "Authenticated",
    4: "Interactive",
}


def _metric_help(name: str) -> str | None:
    triplet = METRICS.get(name)
    return triplet.tooltip() if triplet is not None else None


def _section_caption(name: str) -> str | None:
    triplet = BRIEF_SECTIONS.get(name)
    return triplet.tooltip() if triplet is not None else None


def _stage_scatter(df: pl.DataFrame) -> go.Figure:
    """Per-IP scatter: x = first_seen, y = labeled stage, colour = automation.

    Plotly upgrade over the previous ``st.scatter_chart`` — categorical
    y-axis with stage names instead of bare 1-4 numbers, rich hover
    showing IP / stage_label / event count, and an Automated/Manual
    colour split that survives Streamlit's dark theme.
    """
    chart_df = (
        df.select(
            "src_endpoint_ip",
            "first_seen",
            pl.col("max_stage").alias("StageNum"),
            "stage_label",
            "is_automated",
            # behavioral_progression gold table doesn't carry a pre-summed
            # total — derive it. auth_successes is a subset of auth_attempts,
            # so adding it would double-count.
            (pl.col("scan_events") + pl.col("auth_attempts") + pl.col("commands_executed")).alias(
                "total_events"
            ),
        )
        .with_columns(
            pl.col("is_automated")
            .map_elements(
                lambda x: "Automated" if x else "Manual",
                return_dtype=pl.Utf8,
            )
            .alias("Type"),
            pl.col("StageNum")
            .map_elements(
                lambda n: _STAGE_LABELS_BY_NUM.get(int(n), str(n)),
                return_dtype=pl.Utf8,
            )
            .alias("Stage"),
        )
        .to_pandas()
    )
    fig = px.scatter(
        chart_df,
        x="first_seen",
        y="Stage",
        color="Type",
        category_orders={
            "Stage": ["Scan", "Credential", "Authenticated", "Interactive"],
        },
        color_discrete_map={"Automated": "#d62728", "Manual": "#1f77b4"},
        hover_data={
            "src_endpoint_ip": True,
            "stage_label": True,
            "total_events": ":,",
            "first_seen": True,
            "Type": False,
            "Stage": False,
            "StageNum": False,
        },
        labels={
            "first_seen": "First seen (UTC)",
            "Stage": "Max stage reached",
        },
        height=420,
    )
    fig.update_traces(marker={"size": 8, "opacity": 0.75})
    fig.update_layout(
        margin={"l": 10, "r": 10, "t": 10, "b": 40},
        legend={"orientation": "h", "y": -0.15, "title": ""},
    )
    return fig


def _velocity_histogram(velocity_df: pl.DataFrame) -> go.Figure:
    """Distribution of progression_velocity_days.

    Plotly upgrade over ``st.bar_chart``: explicit binning by integer
    day (one bin per distinct value), tooltips, and a more readable
    aspect ratio for skewed distributions.
    """
    pdf = velocity_df.to_pandas()
    max_days = int(pdf["Days"].max()) if not pdf.empty else 1
    nbins = max(max_days, 2)
    fig = px.histogram(
        pdf,
        x="Days",
        nbins=nbins,
        labels={"Days": "Days to max stage", "count": "IPs"},
        height=350,
    )
    fig.update_traces(marker_color="indianred")
    fig.update_layout(
        margin={"l": 10, "r": 10, "t": 10, "b": 40},
        bargap=0.1,
        yaxis={"title": "IPs"},
    )
    return fig


def render(selected_date: date) -> None:
    """Render the behavioral progression page for the selected date."""
    st.header(f"Behavioral Progression — {selected_date.isoformat()}")
    page_caption = _section_caption("Escalation Funnel")
    if page_caption:
        st.caption(page_caption)

    df = read_gold_table("behavioral_progression", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    # --- Single-day funnel ---
    st.subheader("Escalation Funnel")
    cols = st.columns(4)
    for i, (stage, label, metric_key) in enumerate(
        [
            (1, "Scan", "Stage Scan"),
            (2, "Credential", "Stage Credential"),
            (3, "Authenticated", "Stage Authenticated"),
            (4, "Interactive", "Stage Interactive"),
        ]
    ):
        count = df.filter(pl.col("max_stage") >= stage).height
        cols[i].metric(label, count, help=_metric_help(metric_key))

    st.divider()

    # Automated vs manual breakdown
    auto_count = df.filter(pl.col("is_automated")).height
    manual_count = len(df) - auto_count
    a_col, m_col, _ = st.columns(3)
    a_col.metric(
        "Automated Bots",
        auto_count,
        help=_metric_help("Automated Bots"),
    )
    m_col.metric(
        "Manual / Unknown",
        manual_count,
        help=_metric_help("Manual or Unknown"),
    )

    st.divider()

    # Stage scatter plot (stage vs first_seen, colored by automated).
    # The caption is the load-bearing explanation here — without it the
    # axes encode three dimensions but read as a blob of dots.
    st.subheader("Stage vs Time")
    scatter_caption = _section_caption("Stage vs Time")
    if scatter_caption:
        st.caption(scatter_caption)
    if "first_seen" in df.columns and "max_stage" in df.columns:
        st.plotly_chart(_stage_scatter(df), width="stretch")

    st.divider()

    # Detailed table
    st.subheader("IP Progression Details")
    st.caption(
        "Per-IP escalation row. `seconds_to_*` columns surface how fast each "
        "stage was reached — fast = automated, slow = manual / staged."
    )

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

    min_stage = st.selectbox(
        "Minimum stage",
        [1, 2, 3, 4],
        index=0,
        help=(
            "Filter the table to IPs that reached at least this stage. "
            "1=Scan · 2=Credential · 3=Authenticated · 4=Interactive."
        ),
    )
    filtered = df.filter(pl.col("max_stage") >= min_stage)

    st.dataframe(
        filtered.select(available_cols).to_pandas(),
        hide_index=True,
        width="stretch",
    )

    # --- Multi-day rollup (7-day lookback) ---
    st.divider()
    st.header("Multi-Day Progression (7-day lookback)")
    md_caption = _section_caption("Multi-Day Progression")
    if md_caption:
        st.caption(md_caption)

    multiday = read_gold_table("behavioral_progression_multiday", selected_date)
    if multiday.is_empty():
        st.info("No multi-day progression data available for this date.")
        return

    slow_burn = multiday.filter(pl.col("is_slow_burn"))
    sb_col, total_col, _ = st.columns(3)
    sb_col.metric(
        "Slow-Burn IPs",
        slow_burn.height,
        help=_metric_help("Slow-Burn IPs"),
    )
    total_col.metric(
        "Total IPs (7-day)",
        multiday.height,
        help=_metric_help("Total Multi-Day IPs"),
    )

    st.divider()

    # Velocity distribution
    if "progression_velocity_days" in multiday.columns:
        st.subheader("Progression Velocity (days to max stage)")
        velocity_caption = _section_caption("Progression Velocity")
        if velocity_caption:
            st.caption(velocity_caption)
        velocity_df = multiday.filter(pl.col("progression_velocity_days") > 0).select(
            pl.col("progression_velocity_days").alias("Days"),
        )
        if not velocity_df.is_empty():
            st.plotly_chart(_velocity_histogram(velocity_df), width="stretch")

    st.divider()

    # Slow-burn details table
    if not slow_burn.is_empty():
        st.subheader("Slow-Burn Attackers")
        slow_burn_caption = _section_caption("Slow-Burn Attackers")
        if slow_burn_caption:
            st.caption(slow_burn_caption)
        multiday_cols = [
            "src_endpoint_ip",
            "max_stage",
            "stage_label",
            "first_seen_date",
            "last_seen_date",
            "active_days",
            "progression_velocity_days",
        ]
        available = [c for c in multiday_cols if c in slow_burn.columns]
        st.dataframe(
            slow_burn.select(available)
            .sort("progression_velocity_days", descending=True)
            .to_pandas(),
            hide_index=True,
            width="stretch",
        )

"""Detection Findings page — Suricata and IDS detection summaries.

Two complementary lenses on the same data:

- **Top Rules by Event Count** — horizontal bar with full rule names
  visible, colour-encoded by unique-IP breadth. Answers "what fired?".
- **Rule Concentration** — Pareto chart (bars + cumulative %) over the
  top-50 rules. Answers "how concentrated is today's traffic — a few
  dominant rules or a broad spray?".

Both feed off ``gold_table('detection_findings')``; neither depends on
silver. Plotly is preferred over Streamlit native charts here because
Suricata rule titles are long and need ``automargin`` to render legibly.
"""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type
from typing import TYPE_CHECKING

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from lantana.common.datalake import read_gold_table
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS

if TYPE_CHECKING:
    import polars as pl


def _metric_help(name: str) -> str | None:
    triplet = METRICS.get(name)
    return triplet.tooltip() if triplet is not None else None


_PARETO_LIMIT: int = 50
_TOP_BAR_LIMIT: int = 20


def _top_rules_bar(df: pl.DataFrame) -> go.Figure:
    """Horizontal bar of top-N rules by event_count.

    Colour encodes ``unique_ips`` (darker = broader attacker base). Long
    Suricata titles stay legible thanks to ``yaxis.automargin=True``.
    Y-axis is reversed so the highest-count rule sits at the top, which
    matches how readers scan a ranked list.
    """
    top = df.sort("event_count", descending=True).head(_TOP_BAR_LIMIT).to_pandas()
    hover_cols: dict[str, bool] = {"unique_ips": True}
    if "category" in top.columns:
        hover_cols["category"] = True

    fig = px.bar(
        top,
        x="event_count",
        y="finding_title",
        orientation="h",
        color="unique_ips",
        color_continuous_scale="Reds",
        labels={
            "event_count": "Events",
            "finding_title": "Rule",
            "unique_ips": "Unique IPs",
        },
        hover_data=hover_cols,
        height=max(400, 30 * len(top)),
    )
    fig.update_layout(
        yaxis={"automargin": True, "autorange": "reversed", "title": ""},
        margin={"l": 10, "r": 10, "t": 10, "b": 40},
        coloraxis_colorbar={"title": "Unique<br>IPs"},
    )
    return fig


def _pareto_concentration(df: pl.DataFrame) -> go.Figure:
    """Pareto chart: bars (event_count per rule, sorted) + cumulative %
    line. The 80% gridline is a visual anchor — if it sits to the left of
    rank ~10, today's IDS noise is dominated by a small handful of
    signatures (worth investigating individually); if it sits far right,
    the traffic is a broad spray.

    Capped at ``_PARETO_LIMIT`` ranks so the chart stays readable; the
    cumulative line uses the *capped* total, so the curve always reaches
    100% at the right edge. The dashed 80% reference still answers the
    concentration question correctly.
    """
    sorted_df = df.sort("event_count", descending=True).head(_PARETO_LIMIT)
    counts = [int(c) for c in sorted_df["event_count"].to_list()]
    titles = sorted_df["finding_title"].to_list()
    total = sum(counts)

    cumulative_pct: list[float] = []
    running = 0
    for c in counts:
        running += c
        cumulative_pct.append(100.0 * running / total if total > 0 else 0.0)

    ranks = list(range(1, len(counts) + 1))

    fig = go.Figure()
    fig.add_bar(
        x=ranks,
        y=counts,
        name="Events",
        marker_color="indianred",
        customdata=titles,
        hovertemplate="Rank %{x}<br>%{customdata}<br>Events: %{y}<extra></extra>",
    )
    fig.add_scatter(
        x=ranks,
        y=cumulative_pct,
        name="Cumulative %",
        yaxis="y2",
        mode="lines+markers",
        line={"color": "steelblue"},
        hovertemplate="Rank %{x}<br>Cumulative: %{y:.1f}%<extra></extra>",
    )
    fig.update_layout(
        xaxis={"title": "Rule rank (sorted by event count)", "dtick": 1},
        yaxis={"title": "Events"},
        yaxis2={
            "title": "Cumulative %",
            "overlaying": "y",
            "side": "right",
            "range": [0, 105],
        },
        margin={"l": 10, "r": 10, "t": 10, "b": 40},
        legend={"orientation": "h", "y": -0.2},
        height=420,
    )
    fig.add_hline(
        y=80,
        line_dash="dash",
        line_color="gray",
        yref="y2",
        annotation_text="80%",
        annotation_position="top right",
    )
    return fig


def render(selected_date: date) -> None:
    """Render the detection findings page for the selected date."""
    st.header(f"Detection Findings — {selected_date.isoformat()}")
    section = BRIEF_SECTIONS.get("Detection Highlights")
    if section:
        st.caption(section.tooltip())

    df = read_gold_table("detection_findings", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    # Summary metrics
    cols = st.columns(3)
    cols[0].metric(
        "Total Rules",
        len(df),
        help=_metric_help("Total Rules"),
    )
    cols[1].metric(
        "Total Events",
        f"{df['event_count'].sum():,}",
        help=_metric_help("Total Detection Events"),
    )
    cols[2].metric(
        "Total Unique IPs",
        f"{df['unique_ips'].sum():,}",
        help=_metric_help("Total Detection IPs"),
    )

    st.divider()

    # Top rules — full-name horizontal bar.
    st.subheader("Top Rules by Event Count")
    top_rules_section = BRIEF_SECTIONS.get("Top Rules by Event Count")
    if top_rules_section:
        st.caption(top_rules_section.tooltip())
    st.plotly_chart(_top_rules_bar(df), width="stretch")

    st.divider()

    # Pareto concentration — answers "how dominated is today's traffic?".
    st.subheader("Rule Concentration (Pareto)")
    pareto_section = BRIEF_SECTIONS.get("Rule Concentration")
    if pareto_section:
        st.caption(pareto_section.tooltip())
    st.plotly_chart(_pareto_concentration(df), width="stretch")

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
        width="stretch",
    )

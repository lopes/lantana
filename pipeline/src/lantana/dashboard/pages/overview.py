"""Overview page — daily summary metrics and charts."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type
from typing import Any

import plotly.graph_objects as go
import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS

# Stacked-bar palette for the Events by Type chart — Plotly's qualitative
# default mapped explicitly so each event class gets a stable colour even
# when one of them has zero count for the day (and would otherwise be
# skipped from the trace iteration).
_EVENT_TYPE_COLOURS: dict[str, str] = {
    "Auth": "#1f77b4",
    "Commands": "#ff7f0e",
    "Findings": "#d62728",
    "Network": "#2ca02c",
}


def _auth_donut(successes: int, failures: int) -> go.Figure:
    """Success/failure donut with the success rate written in the centre.

    Two slices (Success in green, Failure in red) over a 0.6 hole. Centre
    annotation shows the success rate as a percentage to one decimal —
    the headline an analyst wants from this widget. Total auth attempts
    is the hover detail on each slice.
    """
    total = successes + failures
    rate = (100.0 * successes / total) if total > 0 else 0.0
    fig = go.Figure(
        data=[
            go.Pie(
                labels=["Success", "Failure"],
                values=[successes, failures],
                hole=0.6,
                marker={"colors": ["#2ca02c", "#d62728"]},
                textinfo="label+value",
                hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>",
                sort=False,
            )
        ]
    )
    fig.update_layout(
        annotations=[
            {
                "text": f"<b>{rate:.1f}%</b><br><span style='font-size:0.7em'>success</span>",
                "x": 0.5, "y": 0.5,
                "font": {"size": 24},
                "showarrow": False,
            },
        ],
        height=320,
        margin={"l": 10, "r": 10, "t": 10, "b": 10},
        legend={"orientation": "h", "y": -0.05},
        showlegend=True,
    )
    return fig


def _events_by_type_stacked_bar(counts: dict[str, int]) -> go.Figure:
    """Horizontal stacked bar over event-class counts.

    One trace per category so each carries its own colour + legend entry.
    Stacked horizontally means asymmetric magnitudes (auth >> commands)
    still leave the small segments visible at the right edge — a pie
    chart would collapse them to invisible slivers. Total is shown on
    hover so the segment-widths read as proportions, not raw counts.
    """
    total = sum(counts.values())
    fig = go.Figure()
    for label, value in counts.items():
        pct = (100.0 * value / total) if total > 0 else 0.0
        fig.add_bar(
            y=["Events"],
            x=[value],
            name=label,
            orientation="h",
            marker_color=_EVENT_TYPE_COLOURS.get(label, "#888"),
            hovertemplate=(
                f"{label}: %{{x:,}} ({pct:.1f}%)<extra></extra>"
            ),
        )
    fig.update_layout(
        barmode="stack",
        height=180,
        margin={"l": 10, "r": 10, "t": 10, "b": 40},
        legend={"orientation": "h", "y": -0.4},
        xaxis={"title": "Events", "tickformat": ","},
        yaxis={"showticklabels": False, "title": ""},
    )
    return fig


def _metric_help(name: str) -> str | None:
    """Look up the dashboard tooltip for a metric card.

    Returns ``None`` if no explanation is registered — Streamlit's
    ``help=None`` then renders the card without a tooltip, which is
    preferable to a placeholder string."""
    triplet = METRICS.get(name)
    return triplet.tooltip() if triplet is not None else None


def _section_caption(name: str) -> str | None:
    """Look up the dashboard caption for a section heading."""
    triplet = BRIEF_SECTIONS.get(name)
    return triplet.tooltip() if triplet is not None else None


def _render_top_n_table(entries: list[dict[str, Any]], label: str) -> None:
    """Render a Rank | <label> | Count dataframe from a list[struct] top-N column."""
    if not entries:
        return
    st.dataframe(
        pl.DataFrame(
            {
                "Rank": list(range(1, len(entries) + 1)),
                label: [e["value"] for e in entries],
                "Count": [e["count"] for e in entries],
            }
        ),
        hide_index=True,
        width="stretch",
    )


def render(selected_date: date) -> None:
    """Render the overview page for the selected date."""
    st.header(f"Overview — {selected_date.isoformat()}")

    df = read_gold_table("daily_summary", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    row = df.row(0, named=True)

    # Metric cards — hover tooltips explain what/why/how for each.
    cols = st.columns(5)
    cols[0].metric("Total Events", f"{row['total_events']:,}", help=_metric_help("Total Events"))
    cols[1].metric("Unique IPs", f"{row['unique_source_ips']:,}", help=_metric_help("Unique IPs"))
    cols[2].metric(
        "Auth Attempts", f"{row['auth_attempts']:,}", help=_metric_help("Auth Attempts"),
    )
    cols[3].metric("Commands", f"{row['commands_executed']:,}", help=_metric_help("Commands"))
    cols[4].metric("Findings", f"{row['findings_detected']:,}", help=_metric_help("Findings"))

    st.divider()

    # Authentication + Events by Type. Both widgets show proportions of a
    # whole, so we use chart types tuned for that question rather than
    # generic bar charts: a donut (with the success rate in the centre)
    # for the binary auth outcome, and a horizontal stacked bar for the
    # 4-class event split (the latter handles asymmetric magnitudes —
    # auth typically dwarfs commands by 1-2 orders of magnitude — without
    # collapsing the small categories to invisible slivers).
    auth_col, net_col = st.columns(2)
    with auth_col:
        st.subheader("Authentication")
        auth_caption = BRIEF_SECTIONS.get("Authentication Outcome")
        if auth_caption:
            st.caption(auth_caption.tooltip())
        st.plotly_chart(
            _auth_donut(int(row["auth_successes"]), int(row["auth_failures"])),
            width="stretch",
        )

    with net_col:
        st.subheader("Events by Type")
        events_caption = BRIEF_SECTIONS.get("Events by Type")
        if events_caption:
            st.caption(events_caption.tooltip())
        st.plotly_chart(
            _events_by_type_stacked_bar({
                "Auth": int(row["auth_attempts"]),
                "Commands": int(row["commands_executed"]),
                "Findings": int(row["findings_detected"]),
                "Network": int(row["network_events"]),
            }),
            width="stretch",
        )

    st.divider()

    # Top-N tables: Rank | <Item> | Count. The caption sits ABOVE the
    # column row, not inside the left column — otherwise the left table
    # is pushed one line down and the two tables top-misalign.
    creds_caption = _section_caption("Top Credentials")
    if creds_caption:
        st.caption(creds_caption)
    user_col, pass_col = st.columns(2)
    with user_col:
        st.subheader("Top Usernames")
        _render_top_n_table(row.get("top_usernames", []) or [], "Username")
    with pass_col:
        st.subheader("Top Passwords")
        _render_top_n_table(row.get("top_passwords", []) or [], "Password")

    cmd_col, country_col = st.columns(2)
    with cmd_col:
        st.subheader("Top Commands")
        cmd_caption = _section_caption("Top Commands")
        if cmd_caption:
            st.caption(cmd_caption)
        _render_top_n_table(row.get("top_commands", []) or [], "Command")

    with country_col:
        st.subheader("Top Source Countries")
        country_caption = _section_caption("Geographic Origin")
        if country_caption:
            st.caption(country_caption)
        _render_top_n_table(row.get("top_source_countries", []) or [], "Country")

    st.divider()

    # Geographic summary
    geo_df = read_gold_table("geographic_summary", selected_date)
    if not geo_df.is_empty():
        geo_row = geo_df.row(0, named=True)
        asn_col, _ = st.columns(2)
        with asn_col:
            st.subheader("Top ASNs")
            caption = _section_caption("Geographic Origin")
            if caption:
                st.caption(caption)
            asn_entries = geo_row.get("top_asns", [])
            if asn_entries:
                asn_rows = []
                for entry in asn_entries:
                    parts = entry.split(":")
                    asn_info = parts[0] if parts else ""
                    count = parts[1] if len(parts) > 1 else "0"
                    asn_parts = asn_info.split("|")
                    asn = asn_parts[0] if asn_parts else ""
                    isp = asn_parts[1] if len(asn_parts) > 1 else ""
                    asn_rows.append({"ASN": asn, "ISP": isp, "Unique IPs": int(count)})
                st.dataframe(pl.DataFrame(asn_rows), hide_index=True)

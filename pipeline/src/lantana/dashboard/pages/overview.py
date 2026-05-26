"""Overview page — daily summary metrics and charts."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type
from typing import Any

import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS


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

    # Auth breakdown
    auth_col, net_col = st.columns(2)
    with auth_col:
        st.subheader("Authentication")
        auth_data = pl.DataFrame(
            {
                "Status": ["Success", "Failure"],
                "Count": [row["auth_successes"], row["auth_failures"]],
            }
        )
        st.bar_chart(auth_data, x="Status", y="Count")

    with net_col:
        st.subheader("Events by Type")
        type_data = pl.DataFrame(
            {
                "Type": ["Auth", "Commands", "Findings", "Network"],
                "Count": [
                    row["auth_attempts"],
                    row["commands_executed"],
                    row["findings_detected"],
                    row["network_events"],
                ],
            }
        )
        st.bar_chart(type_data, x="Type", y="Count")

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

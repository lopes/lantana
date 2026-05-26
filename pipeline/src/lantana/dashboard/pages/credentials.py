"""Credentials page — credential intelligence and campaign clusters."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type
from typing import Any

import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS


def _metric_help(name: str) -> str | None:
    triplet = METRICS.get(name)
    return triplet.tooltip() if triplet is not None else None


def _render_top_n_table(entries: list[dict[str, Any]], label: str, empty_caption: str) -> None:
    """Render a Rank | <label> | Count dataframe from a list[struct] top-N column."""
    if not entries:
        st.caption(empty_caption)
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


def _render_credential_pairs(entries: list[dict[str, Any]]) -> None:
    """Render a Rank | Username | Password | Count table from the credential pairs column."""
    if not entries:
        st.caption("No credential pair data.")
        return
    st.dataframe(
        pl.DataFrame(
            {
                "Rank": list(range(1, len(entries) + 1)),
                "Username": [e["username"] for e in entries],
                "Password": [e["password"] for e in entries],
                "Count": [e["count"] for e in entries],
            }
        ),
        hide_index=True,
        width="stretch",
    )


def render(selected_date: date) -> None:
    """Render the credentials page for the selected date."""
    st.header(f"Credentials — {selected_date.isoformat()}")

    summary = read_gold_table("daily_summary", selected_date)
    clusters = read_gold_table("campaign_clusters", selected_date)

    # Top credentials from daily summary
    if not summary.is_empty():
        row = summary.row(0, named=True)

        creds_caption = BRIEF_SECTIONS.get("Top Credentials")
        if creds_caption:
            st.caption(creds_caption.tooltip())

        user_col, pass_col, pair_col = st.columns(3)
        with user_col:
            st.subheader("Top Usernames")
            _render_top_n_table(
                row.get("top_usernames", []) or [], "Username", "No username data.",
            )

        with pass_col:
            st.subheader("Top Passwords")
            _render_top_n_table(
                row.get("top_passwords", []) or [], "Password", "No password data.",
            )

        with pair_col:
            st.subheader("Top Credential Pairs")
            _render_credential_pairs(row.get("top_credential_pairs", []) or [])

        st.divider()

    # Campaign clusters
    st.subheader("Campaign Clusters")
    clusters_caption = BRIEF_SECTIONS.get("Campaign Clusters")
    if clusters_caption:
        st.caption(clusters_caption.tooltip())

    if clusters.is_empty():
        st.info("No campaign clusters detected for this date.")
        return

    st.metric(
        "Active Clusters", len(clusters),
        help=_metric_help("Active Clusters"),
    )

    display_cols = [
        "shared_username",
        "shared_password",
        "ip_count",
        "ips",
        "total_events",
        "first_seen",
        "last_seen",
    ]
    available_cols = [c for c in display_cols if c in clusters.columns]

    # Convert list columns to comma-separated strings for display
    display_df = clusters.select(available_cols)
    if "ips" in display_df.columns:
        display_df = display_df.with_columns(
            pl.col("ips").list.join(", ").alias("ips"),
        )

    st.dataframe(
        display_df.to_pandas(),
        hide_index=True,
        width="stretch",
    )

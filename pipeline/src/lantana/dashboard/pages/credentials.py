"""Credentials page — credential intelligence and campaign clusters."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table


def render(selected_date: date) -> None:
    """Render the credentials page for the selected date."""
    st.header(f"Credentials — {selected_date.isoformat()}")

    summary = read_gold_table("daily_summary", selected_date)
    clusters = read_gold_table("campaign_clusters", selected_date)

    # Top credentials from daily summary
    if not summary.is_empty():
        row = summary.row(0, named=True)

        user_col, pass_col = st.columns(2)
        with user_col:
            st.subheader("Top Usernames")
            usernames = row.get("top_usernames", [])
            if usernames:
                user_df = pl.DataFrame(
                    {
                        "Username": usernames,
                        "Rank": list(range(1, len(usernames) + 1)),
                    }
                )
                st.dataframe(user_df.to_pandas(), hide_index=True)
            else:
                st.caption("No username data.")

        with pass_col:
            st.subheader("Top Passwords")
            passwords = row.get("top_passwords", [])
            if passwords:
                pass_df = pl.DataFrame(
                    {
                        "Password": passwords,
                        "Rank": list(range(1, len(passwords) + 1)),
                    }
                )
                st.dataframe(pass_df.to_pandas(), hide_index=True)
            else:
                st.caption("No password data.")

        st.divider()

    # Campaign clusters
    st.subheader("Campaign Clusters")
    st.caption("IPs sharing the same credential pair — likely botnets or coordinated attacks.")

    if clusters.is_empty():
        st.info("No campaign clusters detected for this date.")
        return

    st.metric("Active Clusters", len(clusters))

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
        use_container_width=True,
    )

"""Overview page — daily summary metrics and charts."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table


def render(selected_date: date) -> None:
    """Render the overview page for the selected date."""
    st.header(f"Overview — {selected_date.isoformat()}")

    df = read_gold_table("daily_summary", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    row = df.row(0, named=True)

    # Metric cards
    cols = st.columns(5)
    cols[0].metric("Total Events", f"{row['total_events']:,}")
    cols[1].metric("Unique IPs", f"{row['unique_source_ips']:,}")
    cols[2].metric("Auth Attempts", f"{row['auth_attempts']:,}")
    cols[3].metric("Commands", f"{row['commands_executed']:,}")
    cols[4].metric("Findings", f"{row['findings_detected']:,}")

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

    # Top-N charts
    user_col, pass_col = st.columns(2)
    with user_col:
        st.subheader("Top Usernames")
        usernames = row.get("top_usernames", [])
        if usernames:
            st.dataframe(
                pl.DataFrame({"Username": usernames, "Rank": range(1, len(usernames) + 1)}),
                hide_index=True,
            )

    with pass_col:
        st.subheader("Top Passwords")
        passwords = row.get("top_passwords", [])
        if passwords:
            st.dataframe(
                pl.DataFrame({"Password": passwords, "Rank": range(1, len(passwords) + 1)}),
                hide_index=True,
            )

    cmd_col, country_col = st.columns(2)
    with cmd_col:
        st.subheader("Top Commands")
        commands = row.get("top_commands", [])
        if commands:
            st.dataframe(
                pl.DataFrame({"Command": commands, "Rank": range(1, len(commands) + 1)}),
                hide_index=True,
            )

    with country_col:
        st.subheader("Top Source Countries")
        countries = row.get("top_source_countries", [])
        if countries:
            st.dataframe(
                pl.DataFrame({"Country": countries, "Rank": range(1, len(countries) + 1)}),
                hide_index=True,
            )

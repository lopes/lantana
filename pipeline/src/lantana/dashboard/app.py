"""Streamlit dashboard entry point -- Lantana Intelligence Console."""

from __future__ import annotations

from datetime import date, timedelta

import streamlit as st

from lantana.common.datalake import GOLD_ROOT, list_gold_dates
from lantana.dashboard.pages import credentials, ip_reputation, overview, progression, stix_export


def _setup_sidebar() -> date:
    """Render sidebar with date picker and return selected date."""
    st.sidebar.title("Lantana")
    st.sidebar.caption("Intelligence Console")

    available_dates = list_gold_dates("daily_summary", gold_root=GOLD_ROOT)
    yesterday = date.today() - timedelta(days=1)

    if available_dates:
        default_idx = (
            available_dates.index(yesterday) if yesterday in available_dates else 0
        )
        selected = st.sidebar.selectbox(
            "Date",
            options=available_dates,
            index=default_idx,
            format_func=lambda d: d.isoformat(),
        )
    else:
        selected = st.sidebar.date_input("Date", value=yesterday)

    st.sidebar.divider()
    return selected


def main() -> None:
    """Launch the Lantana Streamlit dashboard."""
    st.set_page_config(
        page_title="Lantana Intelligence Console",
        page_icon=":herb:",
        layout="wide",
    )

    selected_date = _setup_sidebar()

    d = selected_date
    pages = st.navigation([
        st.Page(lambda: overview.render(d), title="Overview", url_path="overview"),
        st.Page(lambda: ip_reputation.render(d), title="IP Reputation", url_path="ip-reputation"),
        st.Page(lambda: progression.render(d), title="Progression", url_path="progression"),
        st.Page(lambda: credentials.render(d), title="Credentials", url_path="credentials"),
        st.Page(lambda: stix_export.render(d), title="STIX Export", url_path="stix-export"),
    ])
    pages.run()


if __name__ == "__main__":
    main()

"""Streamlit dashboard entry point — Lantana Intelligence Console."""

from __future__ import annotations

import os
import sys
from datetime import date, timedelta

import streamlit as st
import streamlit.runtime

from lantana.common.datalake import GOLD_ROOT, list_gold_dates
from lantana.dashboard.pages import (
    credentials,
    findings,
    geography,
    ip_reputation,
    overview,
    progression,
    stix_export,
)


def _setup_sidebar() -> date:
    """Render sidebar with date picker and return selected date."""
    st.sidebar.title("Lantana")
    st.sidebar.caption("Intelligence Console")

    available_dates = list_gold_dates("daily_summary", gold_root=GOLD_ROOT)
    yesterday = date.today() - timedelta(days=1)

    if available_dates:
        default_idx = available_dates.index(yesterday) if yesterday in available_dates else 0
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
    """Launch the Lantana Streamlit dashboard.

    When invoked as a bare Python entry point (e.g. `lantana-dashboard`), re-exec
    via `streamlit run` so the Streamlit runtime and HTTP server are initialised.
    Binds to 127.0.0.1 — never expose externally (OPSEC Layer 3).
    """
    if not streamlit.runtime.exists():
        # When the dashboard runs as the homeless `nectar` system user (via
        # `sudo -u nectar`), $HOME stays as the invoking user's home — which
        # nectar can't traverse. Streamlit then crashes reading ~/.streamlit/
        # secrets.toml. Point HOME and CWD at a directory nectar owns: prefer
        # XDG_CACHE_HOME (the setup guide already sets it to /tmp), else /tmp.
        runtime_dir = os.environ.get("XDG_CACHE_HOME") or "/tmp"
        os.chdir(runtime_dir)
        env = {**os.environ, "HOME": runtime_dir}
        os.execvpe(
            sys.executable,
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                __file__,
                "--server.address=127.0.0.1",
                "--server.port=8501",
                "--server.headless=true",
            ],
            env,
        )

    st.set_page_config(
        page_title="Lantana Intelligence Console",
        page_icon=":herb:",
        layout="wide",
    )

    selected_date = _setup_sidebar()

    d = selected_date
    pages = st.navigation(
        [
            st.Page(lambda: overview.render(d), title="Overview", url_path="overview"),
            st.Page(lambda: geography.render(d), title="Geography", url_path="geography"),
            st.Page(
                lambda: ip_reputation.render(d), title="IP Reputation", url_path="ip-reputation"
            ),
            st.Page(lambda: progression.render(d), title="Progression", url_path="progression"),
            st.Page(lambda: findings.render(d), title="Findings", url_path="findings"),
            st.Page(lambda: credentials.render(d), title="Credentials", url_path="credentials"),
            st.Page(lambda: stix_export.render(d), title="STIX Export", url_path="stix-export"),
        ]
    )
    pages.run()


if __name__ == "__main__":
    main()

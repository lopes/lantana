"""Smoke tests for dashboard figure builders and helper transforms."""

from __future__ import annotations

import plotly.graph_objects as go

from lantana.dashboard.pages.overview import _auth_donut, _events_by_type_stacked_bar


def test_auth_donut_builds_valid_figure() -> None:
    """_auth_donut returns a valid Plotly Figure for both normal and zero-attempt days."""
    fig = _auth_donut(successes=25, failures=75)
    assert isinstance(fig, go.Figure)
    assert len(fig.data) == 1

    zero_fig = _auth_donut(successes=0, failures=0)
    assert isinstance(zero_fig, go.Figure)


def test_events_by_type_stacked_bar_includes_downloads() -> None:
    """_events_by_type_stacked_bar constructs traces for all 5 OCSF classes including Downloads."""
    counts = {
        "Auth": 120,
        "Commands": 15,
        "Findings": 30,
        "Network": 400,
        "Downloads": 4,
    }
    fig = _events_by_type_stacked_bar(counts)
    assert isinstance(fig, go.Figure)
    trace_names = [trace.name for trace in fig.data]
    assert trace_names == ["Auth", "Commands", "Findings", "Network", "Downloads"]

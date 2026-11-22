"""Smoke tests for Vigil dashboard figure builders and helper transforms."""

from __future__ import annotations

import plotly.graph_objects as go

from lantana.dashboard.charts import auth_donut_chart, events_by_type_stacked_bar


def test_auth_donut_builds_valid_figure() -> None:
    """auth_donut_chart returns a valid Plotly Figure for both normal and zero-attempt days."""
    fig = auth_donut_chart(successes=25, failures=75)
    assert isinstance(fig, go.Figure)
    assert len(fig.data) == 1

    zero_fig = auth_donut_chart(successes=0, failures=0)
    assert isinstance(zero_fig, go.Figure)


def test_events_by_type_stacked_bar_includes_downloads() -> None:
    """events_by_type_stacked_bar constructs traces for all 5 OCSF classes including Downloads."""
    counts = {
        "Auth": 120,
        "Commands": 15,
        "Findings": 30,
        "Network": 400,
        "Downloads": 4,
    }
    fig = events_by_type_stacked_bar(counts)
    assert isinstance(fig, go.Figure)
    trace_names = [trace.name for trace in fig.data]
    assert trace_names == ["Auth", "Commands", "Findings", "Network", "Downloads"]

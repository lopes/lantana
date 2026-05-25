"""Tests for the shared What/Why/How explanation constants."""

from __future__ import annotations

from lantana.notify.explanations import BRIEF_SECTIONS, METRICS, WhatWhyHow


class TestWhatWhyHow:
    def test_italic_one_liner_format(self) -> None:
        triplet = WhatWhyHow(what="foo.", why="bar.", how="baz.")
        line = triplet.italic_one_liner()
        # Wrapped in underscores so Markdown renders italic, with the three
        # clauses separated by their labels.
        assert line.startswith("_What: ")
        assert line.endswith("_")
        assert "Why: bar." in line
        assert "How: baz." in line

    def test_tooltip_format(self) -> None:
        triplet = WhatWhyHow(what="x.", why="y.", how="z.")
        tooltip = triplet.tooltip()
        # Plain text, no underscores (Streamlit's help= is rendered as-is).
        assert not tooltip.startswith("_")
        assert "What: x." in tooltip
        assert "Why: y." in tooltip
        assert "How: z." in tooltip


class TestBriefSectionsCoverage:
    """Pin the registered section names so the brief stays in sync with this dict."""

    def test_every_section_has_all_three_clauses(self) -> None:
        for name, triplet in BRIEF_SECTIONS.items():
            assert triplet.what, f"section {name!r} missing what clause"
            assert triplet.why, f"section {name!r} missing why clause"
            assert triplet.how, f"section {name!r} missing how clause"

    def test_pipeline_sections_present(self) -> None:
        """Pipeline Health + Pipeline Timing must always be registered — they're
        the operator-facing self-checks that fire on every brief."""
        assert "Pipeline Health" in BRIEF_SECTIONS
        assert "Pipeline Timing" in BRIEF_SECTIONS

    def test_data_sections_present(self) -> None:
        for name in (
            "Key Metrics",
            "Geographic Origin",
            "Escalation Funnel",
            "Top Attackers",
            "Threat Actor Attribution",
            "Notable Escalations",
            "Campaign Clusters",
            "Detection Highlights",
            "Malware Captured",
            "Top Credentials",
            "Top Commands",
            "Full IOC Inventory",
        ):
            assert name in BRIEF_SECTIONS, f"section {name!r} missing from BRIEF_SECTIONS"


class TestMetricsCoverage:
    def test_every_metric_has_all_three_clauses(self) -> None:
        for name, triplet in METRICS.items():
            assert triplet.what, f"metric {name!r} missing what clause"
            assert triplet.why, f"metric {name!r} missing why clause"
            assert triplet.how, f"metric {name!r} missing how clause"

    def test_overview_page_metrics_registered(self) -> None:
        """The 5 metric cards on the overview page must all have tooltips."""
        for name in ("Total Events", "Unique IPs", "Auth Attempts", "Commands", "Findings"):
            assert name in METRICS

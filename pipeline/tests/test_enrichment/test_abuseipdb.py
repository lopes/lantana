"""Tests for the AbuseIPDB enrichment provider."""

from __future__ import annotations

import pytest

from lantana.enrichment.providers.abuseipdb import compute_risk_score


class TestAbuseipdbRiskScore:
    """AbuseIPDB's abuseConfidenceScore is already 0..100; we pass it through.

    The risk-score helper is the integration point per docs/risk-scoring.md:
    every provider must expose a 0..100 score for the gold composite.
    """

    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [
            (0, 0.0),
            (1, 1.0),
            (50, 50.0),
            (99, 99.0),
            (100, 100.0),
        ],
    )
    def test_in_range_passes_through(self, confidence: int, expected: float) -> None:
        assert compute_risk_score(confidence) == expected

    def test_negative_clipped_to_zero(self) -> None:
        """Defensive: AbuseIPDB shouldn't return negative, but if it ever does
        (hand-edited response in tests, schema drift), clip rather than crash."""
        assert compute_risk_score(-5) == 0.0

    def test_over_hundred_clipped(self) -> None:
        assert compute_risk_score(150) == 100.0

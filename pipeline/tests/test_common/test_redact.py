"""Tests for lantana.common.redact."""

from __future__ import annotations

from lantana.common.redact import RedactionConfig, redact_infrastructure_ips


def test_redact_replaces_infrastructure_ips() -> None:
    """Verify that infrastructure IPs are replaced with pseudonyms."""
    # TODO: create a DataFrame with infrastructure IPs in dst_ip column,
    # apply redact_infrastructure_ips, and assert they are replaced.
    pass

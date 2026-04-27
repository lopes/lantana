"""STIX 2.1 bundle generation from gold-layer data."""

from __future__ import annotations

from datetime import date

import stix2

from lantana.common.config import ReportingConfig


def generate_bundle(gold_date: date, reporting: ReportingConfig) -> stix2.Bundle:
    """Generate a STIX 2.1 bundle from gold-layer data for a given date."""
    raise NotImplementedError("TODO")

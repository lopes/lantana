"""OPSEC redaction functions to strip infrastructure IPs from shared outputs."""

from __future__ import annotations

import polars as pl
from pydantic import BaseModel


class RedactionConfig(BaseModel):
    """Configuration for infrastructure IP redaction."""

    infrastructure_ips: list[str]
    infrastructure_cidrs: list[str]
    pseudonym_map: dict[str, str]


def redact_infrastructure_ips(
    df: pl.DataFrame, config: RedactionConfig
) -> pl.DataFrame:
    """Replace infrastructure IPs in destination columns with pseudonyms."""
    raise NotImplementedError("TODO")


def validate_no_leaks(df: pl.DataFrame, config: RedactionConfig) -> bool:
    """Assert that zero infrastructure IPs remain in the DataFrame."""
    raise NotImplementedError("TODO")

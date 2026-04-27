"""Load configuration files from /etc/lantana/collector/."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

DEFAULT_SECRETS_PATH = Path("/etc/lantana/collector/secrets.json")
DEFAULT_REPORTING_PATH = Path("/etc/lantana/collector/reporting.json")


class SecretsConfig(BaseModel):
    """API keys loaded from secrets.json."""

    virustotal: str
    shodan: str
    abuseipdb: str
    greynoise: str
    phishstats: str
    discord_webhook: str = ""


class OperatorConfig(BaseModel):
    """Operator identity block."""

    name: str
    handle: str
    contact: str
    pgp_fingerprint: str


class SharingConfig(BaseModel):
    """Intelligence sharing policy."""

    tlp: str
    community: str
    discord_channel: str


class OperationConfig(BaseModel):
    """Operation context for report headers and STIX identity."""

    name: str
    description: str
    sector: str
    region: str
    start_date: str


class RedactConfig(BaseModel):
    """OPSEC redaction targets."""

    infrastructure_ips: list[str]
    infrastructure_cidrs: list[str]
    pseudonym_map: dict[str, str]


class ReportingConfig(BaseModel):
    """Full reporting configuration loaded from reporting.json."""

    operator: OperatorConfig
    sharing: SharingConfig
    operation: OperationConfig
    redact: RedactConfig


def load_secrets(path: Path = DEFAULT_SECRETS_PATH) -> SecretsConfig:
    """Load and validate secrets.json."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return SecretsConfig.model_validate(raw)


def load_reporting(path: Path = DEFAULT_REPORTING_PATH) -> ReportingConfig:
    """Load and validate reporting.json."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return ReportingConfig.model_validate(raw)

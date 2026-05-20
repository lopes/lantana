"""Load configuration files from /etc/lantana/collector/."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_SECRETS_PATH = Path("/etc/lantana/collector/secrets.json")
DEFAULT_REPORTING_PATH = Path("/etc/lantana/collector/reporting.json")

# Older operator vault files used `vault_<service>_api_key` /
# `vault_<service>_license_key` / `vault_<service>_webhook_url`. The project
# now standardises on `vault_<type>_<service>` everywhere. The tolerant loader
# below rewrites these legacy keys so hand-written secrets.json files from
# pre-2026-05 vaults still parse — production templates always render the
# canonical form, so `load_secrets()` itself stays strict.
_LEGACY_KEYS: dict[str, str] = {
    "vault_virustotal_api_key":  "vault_apikey_virustotal",
    "vault_shodan_api_key":      "vault_apikey_shodan",
    "vault_abuseipdb_api_key":   "vault_apikey_abuseipdb",
    "vault_greynoise_api_key":   "vault_apikey_greynoise",
    "vault_maxmind_license_key": "vault_apikey_maxmind",
    "vault_discord_webhook_url": "vault_webhook_discord",
}

# Keys silently dropped when loading a secrets.json — providers that used to
# exist but have been removed from Lantana. Keeps existing vault files parsing
# cleanly instead of failing Pydantic validation on a now-unknown field.
_DROPPED_KEYS: frozenset[str] = frozenset({
    "vault_apikey_phishstats",
    "vault_phishstats_api_key",
})


class SecretsConfig(BaseModel):
    """API keys loaded from secrets.json.

    The on-disk JSON mirrors the Ansible vault verbatim — keys are
    ``vault_apikey_<service>`` / ``vault_webhook_<service>``. Python
    attributes use short names (``secrets.virustotal``, etc.) via Pydantic
    field aliases, so consumer code stays clean.

    ``greynoise`` is optional. A missing or null entry disables the
    provider; an empty string keeps it enabled in its unauthenticated
    mode (GreyNoise community endpoint).
    """

    model_config = ConfigDict(populate_by_name=True)

    virustotal:      str        = Field(alias="vault_apikey_virustotal")
    shodan:          str        = Field(alias="vault_apikey_shodan")
    abuseipdb:       str        = Field(alias="vault_apikey_abuseipdb")
    greynoise:       str | None = Field(alias="vault_apikey_greynoise",  default=None)
    maxmind:         str | None = Field(alias="vault_apikey_maxmind",    default=None)
    discord_webhook: str        = Field(alias="vault_webhook_discord",   default="")


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


def _strip_dropped_keys(raw: dict[str, Any]) -> dict[str, Any]:
    """Remove vault keys for providers that no longer exist in Lantana."""
    return {k: v for k, v in raw.items() if k not in _DROPPED_KEYS}


def load_secrets(path: Path = DEFAULT_SECRETS_PATH) -> SecretsConfig:
    """Load and validate secrets.json. Strict — expects canonical keys.

    Vault keys for providers that have been removed (see _DROPPED_KEYS)
    are tolerated for backwards compat — they're stripped silently rather
    than raising a Pydantic validation error. Operator templates can
    omit them at their leisure.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    return SecretsConfig.model_validate(_strip_dropped_keys(raw))


def _translate_legacy_keys(raw: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Rewrite legacy vault-key names to the canonical form.

    Returns (translated_dict, did_translate). Non-legacy keys pass through
    unchanged so files that mix conventions still parse.
    """
    if not any(k in _LEGACY_KEYS for k in raw):
        return raw, False
    translated = {_LEGACY_KEYS.get(k, k): v for k, v in raw.items()}
    return translated, True


def load_secrets_tolerant(path: Path) -> tuple[SecretsConfig, bool]:
    """Load secrets.json, accepting either the canonical or legacy key names.

    Operator tooling (the probe scripts) calls this so a hand-written or
    pre-2026-05 secrets.json still parses. Production code paths use
    ``load_secrets()`` — those files are always rendered by the Ansible
    template in canonical form.

    Returns ``(config, did_translate)``. Callers can use the bool to emit a
    one-line note when translation happened.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"expected a JSON object at {path}, got {type(raw).__name__}")
    translated, did_translate = _translate_legacy_keys(raw)
    translated = _strip_dropped_keys(translated)
    return SecretsConfig.model_validate(translated), did_translate


def load_reporting(path: Path = DEFAULT_REPORTING_PATH) -> ReportingConfig:
    """Load and validate reporting.json."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return ReportingConfig.model_validate(raw)

"""STIX 2.1 bundle generation from gold-layer data.

Produces a STIX Bundle containing:
- Identity: the Lantana operator
- Indicators: high-risk attacker IPs (risk_score >= threshold)
- Campaigns: credential-sharing clusters
- Relationships: links between indicators and campaigns
- Report: wraps all objects for the date
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import polars as pl
import stix2

from lantana.common.config import ReportingConfig  # noqa: TC001 -- runtime parameter type

# IPs with risk_score >= this threshold become STIX Indicators
RISK_THRESHOLD: float = 40.0

# TLP marking definition IDs (predefined by STIX)
_TLP_MAP: dict[str, stix2.MarkingDefinition] = {
    "WHITE": stix2.TLP_WHITE,
    "GREEN": stix2.TLP_GREEN,
    "AMBER": stix2.TLP_AMBER,
    "RED": stix2.TLP_RED,
}

# Behavioral stage -> STIX indicator label
_STAGE_LABELS: dict[str, list[str]] = {
    "scan": ["malicious-activity"],
    "credential": ["malicious-activity"],
    "authenticated": ["malicious-activity", "compromised"],
    "interactive": ["malicious-activity", "compromised"],
}


def _make_identity(reporting: ReportingConfig) -> stix2.Identity:
    """Create the operator Identity object."""
    return stix2.Identity(
        name=reporting.operator.name,
        identity_class="organization",
        description=reporting.operation.description,
        sectors=[reporting.operation.sector.lower()],
        contact_information=reporting.operator.contact,
    )


def _make_indicators(
    reputation: pl.DataFrame,
    progression: pl.DataFrame,
    identity: stix2.Identity,
    tlp: stix2.MarkingDefinition,
    multiday_progression: pl.DataFrame | None = None,
) -> list[stix2.Indicator]:
    """Create Indicator objects for high-risk IPs."""
    if reputation.is_empty():
        return []

    risky = reputation.filter(pl.col("risk_score") >= RISK_THRESHOLD)
    indicators: list[stix2.Indicator] = []

    for row in risky.iter_rows(named=True):
        ip = row["src_endpoint_ip"]

        # Determine labels from progression stage
        labels = ["malicious-activity"]
        if not progression.is_empty():
            ip_prog = progression.filter(pl.col("src_endpoint_ip") == ip)
            if ip_prog.height > 0:
                stage = ip_prog.row(0, named=True)["stage_label"]
                labels = list(_STAGE_LABELS.get(stage, labels))

        # Multi-day: add slow-burn label
        if multiday_progression is not None and not multiday_progression.is_empty():
            ip_md = multiday_progression.filter(pl.col("src_endpoint_ip") == ip)
            if ip_md.height > 0:
                md_row = ip_md.row(0, named=True)
                if md_row.get("is_slow_burn"):
                    labels.append("slow-burn-escalation")

        description_parts = [
            f"Risk score: {row['risk_score']:.1f}",
            f"Events: {row['total_events']}",
        ]
        if row.get("geo_country"):
            description_parts.append(f"Country: {row['geo_country']}")
        if row["auth_attempts"] > 0:
            description_parts.append(
                f"Auth: {row.get('auth_successes', 0)}/{row['auth_attempts']}"
            )
        if row["commands_executed"] > 0:
            description_parts.append(f"Commands: {row['commands_executed']}")

        # Multi-day: use first_seen_date for valid_from if available
        valid_from = row.get("first_seen")
        if multiday_progression is not None and not multiday_progression.is_empty():
            ip_md = multiday_progression.filter(pl.col("src_endpoint_ip") == ip)
            if ip_md.height > 0:
                first_date = ip_md.row(0, named=True).get("first_seen_date")
                if isinstance(first_date, date):
                    valid_from = datetime(
                        first_date.year, first_date.month, first_date.day, tzinfo=UTC,
                    )
        if valid_from is None or not isinstance(valid_from, datetime):
            valid_from = datetime.now(tz=UTC)

        indicators.append(stix2.Indicator(
            name=ip,
            description=". ".join(description_parts),
            pattern=f"[ipv4-addr:value = '{ip}']",
            pattern_type="stix",
            valid_from=valid_from,
            labels=labels,
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
            confidence=min(int(row["risk_score"]), 100),
        ))

    return indicators


def _make_campaigns(
    clusters: pl.DataFrame,
    identity: stix2.Identity,
    tlp: stix2.MarkingDefinition,
) -> list[stix2.Campaign]:
    """Create Campaign objects from credential clusters."""
    if clusters.is_empty():
        return []

    campaigns: list[stix2.Campaign] = []
    for row in clusters.iter_rows(named=True):
        first_seen = row.get("first_seen")
        if first_seen is None or not isinstance(first_seen, datetime):
            first_seen = datetime.now(tz=UTC)

        campaigns.append(stix2.Campaign(
            name=f"{row['shared_username']}:{row['shared_password']}",
            description=(
                f"Credential stuffing campaign: {row['ip_count']} IPs "
                f"sharing credentials {row['shared_username']}:{row['shared_password']}. "
                f"Total events: {row['total_events']}."
            ),
            first_seen=first_seen,
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
        ))

    return campaigns


def _make_relationships(
    indicators: list[stix2.Indicator],
    campaigns: list[stix2.Campaign],
    clusters: pl.DataFrame,
    identity: stix2.Identity,
) -> list[stix2.Relationship]:
    """Create Relationship objects linking indicators to campaigns."""
    if not indicators or not campaigns or clusters.is_empty():
        return []

    # Build lookup: IP -> indicator ID
    ip_to_indicator: dict[str, str] = {ind.name: ind.id for ind in indicators}

    relationships: list[stix2.Relationship] = []
    for campaign, cluster_row in zip(campaigns, clusters.iter_rows(named=True), strict=False):
        ips = cluster_row["ips"]
        if not isinstance(ips, list):
            continue
        for ip in ips:
            if ip in ip_to_indicator:
                relationships.append(stix2.Relationship(
                    relationship_type="indicates",
                    source_ref=ip_to_indicator[ip],
                    target_ref=campaign.id,
                    created_by_ref=identity.id,
                ))

    return relationships


def _make_malware_indicators(
    summary: pl.DataFrame,
    identity: stix2.Identity,
    tlp: stix2.MarkingDefinition,
) -> tuple[list[stix2.Malware], list[stix2.Indicator]]:
    """Create Malware and file-hash Indicator objects from captured samples."""
    if summary.is_empty():
        return [], []

    row = summary.row(0, named=True)
    hashes: list[str] = row.get("top_download_hashes", []) or []
    if not hashes:
        return [], []

    malware_objects: list[stix2.Malware] = []
    hash_indicators: list[stix2.Indicator] = []

    for sha256 in hashes:
        malware = stix2.Malware(
            name=f"sample-{sha256[:12]}",
            description=f"Malware sample captured by honeypot (SHA256: {sha256})",
            is_family=False,
            hashes={"SHA-256": sha256},
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
        )
        malware_objects.append(malware)

        indicator = stix2.Indicator(
            name=f"file-{sha256[:12]}",
            description="Malware hash captured by honeypot",
            pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
            pattern_type="stix",
            valid_from=datetime.now(tz=UTC),
            labels=["malicious-activity"],
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
        )
        hash_indicators.append(indicator)

    return malware_objects, hash_indicators


def generate_bundle(
    gold_date: date,
    reporting: ReportingConfig,
    reputation: pl.DataFrame,
    progression: pl.DataFrame,
    clusters: pl.DataFrame,
    summary: pl.DataFrame | None = None,
    multiday_progression: pl.DataFrame | None = None,
) -> stix2.Bundle:
    """Generate a STIX 2.1 bundle from gold-layer data for a given date."""
    tlp = _TLP_MAP.get(reporting.sharing.tlp.upper(), stix2.TLP_GREEN)
    identity = _make_identity(reporting)

    objects: list[object] = [identity]

    indicators = _make_indicators(
        reputation, progression, identity, tlp, multiday_progression,
    )
    objects.extend(indicators)

    campaigns = _make_campaigns(clusters, identity, tlp)
    objects.extend(campaigns)

    relationships = _make_relationships(indicators, campaigns, clusters, identity)
    objects.extend(relationships)

    # Malware objects from captured file hashes
    if summary is not None:
        malware_objects, hash_indicators = _make_malware_indicators(summary, identity, tlp)
        objects.extend(malware_objects)
        objects.extend(hash_indicators)

    # Create a Report wrapping all objects
    if len(objects) > 1:  # more than just the identity
        object_refs = [o.id for o in objects]  # type: ignore[attr-defined]
        report = stix2.Report(
            name=f"Lantana Daily Intel -- {gold_date.isoformat()}",
            description=(
                f"Daily threat intelligence from {reporting.operation.name} "
                f"for {gold_date.isoformat()}"
            ),
            published=datetime.now(tz=UTC),
            object_refs=object_refs,
            labels=["threat-report"],
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
        )
        objects.append(report)

    return stix2.Bundle(objects=objects)

"""STIX 2.1 bundle generation from gold-layer data.

Produces a STIX Bundle containing:
- Identity: the Lantana operator
- Indicators: high-risk attacker IPs (risk_score >= threshold)
- Campaigns: credential-sharing clusters
- Relationships: links between indicators and campaigns
- Report: wraps all objects for the date
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, date, datetime

import polars as pl
import stix2

from lantana.common.config import ReportingConfig  # noqa: TC001 — runtime parameter type

# Risk-score level thresholds. ``RISK_THRESHOLD`` is the STIX Indicator
# gate (IPs at or above this become Indicators in the daily bundle); it
# also marks the floor of the dashboard's Medium-risk bucket so the two
# views can't drift. ``RISK_HIGH_THRESHOLD`` marks the dashboard's High
# bucket — pageable signal, drives Discord top-N. Both are floats so a
# future fractional reweight (e.g. 67.5) doesn't need a type change.
RISK_THRESHOLD: float = 40.0
RISK_HIGH_THRESHOLD: float = 70.0

# TLP marking definition IDs (predefined by STIX)
_TLP_MAP: dict[str, stix2.MarkingDefinition] = {
    "CLEAR": stix2.TLP_WHITE,
    "WHITE": stix2.TLP_WHITE,
    "GREEN": stix2.TLP_GREEN,
    "AMBER": stix2.TLP_AMBER,
    "AMBER+STRICT": stix2.TLP_AMBER,
    "RED": stix2.TLP_RED,
}


def _date_to_utc_midnight(target_date: date) -> datetime:
    """Return deterministic UTC midnight datetime for a partition date."""
    return datetime(target_date.year, target_date.month, target_date.day, tzinfo=UTC)


def _ip_stix_pattern(ip: str) -> str:
    """Build a STIX 2.1 pattern for an IPv4 or IPv6 address literal."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"[ipv4-addr:value = '{ip}']"
    if isinstance(addr, ipaddress.IPv6Address):
        return f"[ipv6-addr:value = '{ip}']"
    return f"[ipv4-addr:value = '{ip}']"


def _assert_no_infra_leaks(serialized_bundle: str, reporting: ReportingConfig) -> None:
    """Raise ValueError if any configured infrastructure IP appears in serialized STIX JSON."""
    for infra_ip in reporting.redact.infrastructure_ips:
        if infra_ip and infra_ip in serialized_bundle:
            msg = f"Infrastructure IP leak in STIX bundle: {infra_ip}"
            raise ValueError(msg)


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
    default_ts: datetime | None = None,
) -> list[stix2.Indicator]:
    """Create Indicator objects for high-risk IPs."""
    if reputation.is_empty():
        return []

    fallback_ts = default_ts if default_ts is not None else datetime.now(tz=UTC)
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

        # Named threat actor
        if row.get("greynoise_name") and row["greynoise_name"] not in ("", "unknown"):
            labels.append(row["greynoise_name"])

        description_parts = [
            f"Risk score: {row['risk_score']:.1f}",
            f"Events: {row['total_events']}",
        ]
        # Phase D.2 sub-scores — give STIX consumers the decomposition so
        # they can apply their own enrichment-vs-behavioral weighting if
        # they need to. Both fields default to None on pre-D.2 gold.
        enrichment_sub = row.get("enrichment_risk_score")
        behavioral_sub = row.get("behavioral_risk_score")
        if enrichment_sub is not None or behavioral_sub is not None:
            e_str = f"{enrichment_sub:.1f}" if enrichment_sub is not None else "—"
            b_str = f"{behavioral_sub:.1f}" if behavioral_sub is not None else "—"
            description_parts.append(f"Risk breakdown: enrichment={e_str}, behavioral={b_str}")
        if row.get("geo_country"):
            geo_str = row["geo_country"]
            if row.get("geo_city"):
                geo_str = f"{row['geo_city']}, {geo_str}"
            description_parts.append(f"Location: {geo_str}")
        if row.get("geo_asn"):
            asn_str = str(row["geo_asn"])
            if row.get("geo_isp"):
                asn_str += f" ({row['geo_isp']})"
            description_parts.append(f"ASN: {asn_str}")
        if row["auth_attempts"] > 0:
            description_parts.append(f"Auth: {row.get('auth_successes', 0)}/{row['auth_attempts']}")
        if row["commands_executed"] > 0:
            description_parts.append(f"Commands: {row['commands_executed']}")
        if row.get("vt_malicious") and row["vt_malicious"] > 0:
            description_parts.append(f"VT detections: {row['vt_malicious']}")
        if row.get("shodan_vulns") and row["shodan_vulns"]:
            vuln_count = len(str(row["shodan_vulns"]).split(","))
            description_parts.append(f"Known CVEs: {vuln_count}")

        valid_from = row.get("first_seen")
        if valid_from is None or not isinstance(valid_from, datetime):
            valid_from = fallback_ts

        indicators.append(
            stix2.Indicator(
                name=ip,
                description=". ".join(description_parts),
                pattern=_ip_stix_pattern(str(ip)),
                pattern_type="stix",
                valid_from=valid_from,
                created=fallback_ts,
                labels=labels,
                created_by_ref=identity.id,
                object_marking_refs=[tlp.id],
                confidence=min(int(row["risk_score"]), 100),
            )
        )

    return indicators


def _make_campaigns(
    clusters: pl.DataFrame,
    identity: stix2.Identity,
    tlp: stix2.MarkingDefinition,
    default_ts: datetime | None = None,
) -> list[stix2.Campaign]:
    """Create Campaign objects from credential clusters."""
    if clusters.is_empty():
        return []

    fallback_ts = default_ts if default_ts is not None else datetime.now(tz=UTC)
    campaigns: list[stix2.Campaign] = []
    for row in clusters.iter_rows(named=True):
        first_seen = row.get("first_seen")
        if first_seen is None or not isinstance(first_seen, datetime):
            first_seen = fallback_ts

        campaigns.append(
            stix2.Campaign(
                name=f"{row['shared_username']}:{row['shared_password']}",
                description=(
                    f"Credential stuffing campaign: {row['ip_count']} IPs "
                    f"sharing credentials {row['shared_username']}:{row['shared_password']}. "
                    f"Total events: {row['total_events']}."
                ),
                first_seen=first_seen,
                created=fallback_ts,
                created_by_ref=identity.id,
                object_marking_refs=[tlp.id],
            )
        )

    return campaigns


def _make_relationships(
    indicators: list[stix2.Indicator],
    campaigns: list[stix2.Campaign],
    clusters: pl.DataFrame,
    identity: stix2.Identity,
    tlp: stix2.MarkingDefinition,
    default_ts: datetime | None = None,
) -> list[stix2.Relationship]:
    """Create Relationship objects linking indicators to campaigns."""
    if not indicators or not campaigns or clusters.is_empty():
        return []

    fallback_ts = default_ts if default_ts is not None else datetime.now(tz=UTC)
    # Build lookup: IP -> indicator ID
    ip_to_indicator: dict[str, str] = {ind.name: ind.id for ind in indicators}

    relationships: list[stix2.Relationship] = []
    for campaign, cluster_row in zip(campaigns, clusters.iter_rows(named=True), strict=False):
        ips = cluster_row["ips"]
        if not isinstance(ips, list):
            continue
        for ip in ips:
            if ip in ip_to_indicator:
                relationships.append(
                    stix2.Relationship(
                        relationship_type="indicates",
                        source_ref=ip_to_indicator[ip],
                        target_ref=campaign.id,
                        created=fallback_ts,
                        created_by_ref=identity.id,
                        object_marking_refs=[tlp.id],
                    )
                )

    return relationships


def _make_malware_indicators(
    summary: pl.DataFrame,
    identity: stix2.Identity,
    tlp: stix2.MarkingDefinition,
    default_ts: datetime | None = None,
) -> tuple[list[stix2.Malware], list[stix2.Indicator], list[stix2.Relationship]]:
    """Create Malware, file-hash Indicator, and Relationship objects from captured samples."""
    if summary.is_empty():
        return [], [], []

    fallback_ts = default_ts if default_ts is not None else datetime.now(tz=UTC)
    row = summary.row(0, named=True)
    hash_entries = row.get("top_download_hashes", []) or []
    hashes: list[str] = [e["value"] for e in hash_entries]
    if not hashes:
        return [], [], []

    malware_objects: list[stix2.Malware] = []
    hash_indicators: list[stix2.Indicator] = []
    malware_relationships: list[stix2.Relationship] = []

    for sha256 in hashes:
        malware = stix2.Malware(
            name=f"sample-{sha256[:12]}",
            description=f"Malware sample captured by honeypot (SHA256: {sha256})",
            is_family=False,
            created=fallback_ts,
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
        )
        malware_objects.append(malware)

        indicator = stix2.Indicator(
            name=f"file-{sha256[:12]}",
            description="Malware hash captured by honeypot",
            pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
            pattern_type="stix",
            valid_from=fallback_ts,
            created=fallback_ts,
            labels=["malicious-activity"],
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
        )
        hash_indicators.append(indicator)

        malware_relationships.append(
            stix2.Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware.id,
                created=fallback_ts,
                created_by_ref=identity.id,
                object_marking_refs=[tlp.id],
            )
        )

    return malware_objects, hash_indicators, malware_relationships


def _make_finding_indicators(
    detection: pl.DataFrame,
    identity: stix2.Identity,
    tlp: stix2.MarkingDefinition,
    default_ts: datetime | None = None,
) -> list[stix2.Indicator]:
    """Create Indicator objects from detection findings with broad IP coverage."""
    if detection.is_empty():
        return []

    fallback_ts = default_ts if default_ts is not None else datetime.now(tz=UTC)
    # Only rules triggered by >= 5 unique IPs are worth sharing as intel
    broad_rules = detection.filter(pl.col("unique_ips") >= 5)
    indicators: list[stix2.Indicator] = []

    for row in broad_rules.iter_rows(named=True):
        title = row.get("finding_title", "unknown")
        valid_from = row.get("first_seen")
        if valid_from is None or not isinstance(valid_from, datetime):
            valid_from = fallback_ts
        indicators.append(
            stix2.Indicator(
                name=f"rule-{title}",
                description=(
                    f"IDS rule triggered by {row['unique_ips']} unique source IPs "
                    f"({row['event_count']} events). Category: {row.get('category', 'unknown')}."
                ),
                pattern="[network-traffic:extensions.'http-request-ext'.request_method = 'alert']",
                pattern_type="stix",
                valid_from=valid_from,
                created=fallback_ts,
                labels=["anomalous-activity"],
                created_by_ref=identity.id,
                object_marking_refs=[tlp.id],
            )
        )

    return indicators


def generate_bundle(
    gold_date: date,
    reporting: ReportingConfig,
    reputation: pl.DataFrame,
    progression: pl.DataFrame,
    clusters: pl.DataFrame,
    summary: pl.DataFrame | None = None,
    detection: pl.DataFrame | None = None,
) -> stix2.Bundle:
    """Generate a STIX 2.1 bundle from gold-layer data for a given date."""
    default_ts = _date_to_utc_midnight(gold_date)
    tlp = _TLP_MAP.get(reporting.sharing.tlp.upper(), stix2.TLP_GREEN)
    identity = _make_identity(reporting)

    objects: list[object] = [identity]

    indicators = _make_indicators(
        reputation,
        progression,
        identity,
        tlp,
        default_ts=default_ts,
    )
    objects.extend(indicators)

    campaigns = _make_campaigns(clusters, identity, tlp, default_ts=default_ts)
    objects.extend(campaigns)

    relationships = _make_relationships(
        indicators,
        campaigns,
        clusters,
        identity,
        tlp,
        default_ts=default_ts,
    )
    objects.extend(relationships)

    # Malware objects from captured file hashes
    if summary is not None:
        malware_objects, hash_indicators, malware_rels = _make_malware_indicators(
            summary,
            identity,
            tlp,
            default_ts=default_ts,
        )
        objects.extend(malware_objects)
        objects.extend(hash_indicators)
        objects.extend(malware_rels)

    # Finding-based indicators from detection rules
    if detection is not None:
        finding_indicators = _make_finding_indicators(
            detection,
            identity,
            tlp,
            default_ts=default_ts,
        )
        objects.extend(finding_indicators)

    # Create a Report wrapping all objects
    if len(objects) > 1:  # more than just the identity
        # stix2 STIX-DO instances expose `.id`, but mypy only sees the abstract base.
        object_refs = [o.id for o in objects]  # type: ignore[attr-defined]
        report = stix2.Report(
            name=f"Lantana Daily Intel — {gold_date.isoformat()}",
            description=(
                f"Daily threat intelligence from {reporting.operation.name} "
                f"for {gold_date.isoformat()}"
            ),
            published=default_ts,
            created=default_ts,
            object_refs=object_refs,
            labels=["threat-report"],
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
        )
        objects.append(report)

    bundle = stix2.Bundle(objects=objects)
    _assert_no_infra_leaks(bundle.serialize(), reporting)
    return bundle

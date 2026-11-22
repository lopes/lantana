"""STIX 2.1 bundle generation from gold-layer data.

Produces a STIX 2.1 Bundle containing:
- Identity: the Lantana operator
- Durable Indicators from ``extracted_iocs`` (7th Gold table):
    * Outbound C2 IPs (30d validity)
    * Post-auth stager URLs & domains (30d validity)
    * All daily malware SHA-256 hashes (grouped/tagged by ``vhash`` cluster,
      with Malware SDOs, ``indicates`` relationships, and confidence-gated GTI
      ThreatActor ``uses`` relationships)
    * Persistent OpenSSH public-key fingerprints (90d validity)
- Transient Inbound Attacker IP Indicators: strictly gated on
  ``behavioral_risk_score > 0`` AND ``risk_score >= 40`` (excluding RIOT and
  GreyNoise ``benign`` scanners), with explicit 7-day ``valid_until``.
- Campaigns & Relationships from shared credential clusters
- Report wrapping all objects for the date
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import UTC, date, datetime, timedelta

import polars as pl
import stix2

from lantana.common.config import ReportingConfig  # noqa: TC001 — runtime parameter type
from lantana.common.redact import derive_ip_variants

# Risk-score level thresholds shared by STIX export, dashboard buckets, and brief.
RISK_THRESHOLD: float = 40.0
RISK_HIGH_THRESHOLD: float = 70.0

INBOUND_IP_VALID_DAYS: int = 7
OUTBOUND_INFRA_VALID_DAYS: int = 30
MALWARE_PERSISTENCE_VALID_DAYS: int = 90

_IPV4_EXTRACT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_EXTRACT_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")

# TLP marking definition IDs (predefined by STIX)
_TLP_MAP: dict[str, stix2.MarkingDefinition] = {
    "CLEAR": stix2.TLP_WHITE,
    "WHITE": stix2.TLP_WHITE,
    "GREEN": stix2.TLP_GREEN,
    "AMBER": stix2.TLP_AMBER,
    "AMBER+STRICT": stix2.TLP_AMBER,
    "RED": stix2.TLP_RED,
}

# Behavioral stage -> STIX indicator label
_STAGE_LABELS: dict[str, list[str]] = {
    "scan": ["malicious-activity"],
    "credential": ["malicious-activity"],
    "authenticated": ["malicious-activity", "compromised"],
    "interactive": ["malicious-activity", "compromised"],
}


def _date_to_utc_midnight(target_date: date) -> datetime:
    """Return deterministic UTC midnight datetime for a partition date."""
    return datetime(target_date.year, target_date.month, target_date.day, tzinfo=UTC)


def _ensure_utc_dt(value: object, fallback: datetime) -> datetime:
    """Coerce naive/aware datetime or ISO string to a UTC-aware datetime.

    Gold Parquet frames built from mixed sensor datasets (e.g. Dionaea's
    tz-naive timestamps combined with Cowrie's UTC timestamps) can store
    ``first_seen`` as tz-naive ``pl.Datetime``. ``stix2.Indicator`` compares
    ``valid_until <= valid_from`` and raises ``TypeError`` if one is naive
    and the other is UTC-aware.
    """
    fb = fallback.replace(tzinfo=UTC) if fallback.tzinfo is None else fallback.astimezone(UTC)
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return fb
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return fb


def _ensure_valid_until(
    valid_from: datetime,
    default_until: datetime,
    min_days: int,
) -> datetime:
    """Guarantee ``valid_until > valid_from`` even under minor clock skew."""
    if default_until > valid_from:
        return default_until
    return valid_from + timedelta(days=min_days)


def _escape_stix_value(value: str) -> str:
    """Escape backslashes and single quotes inside a STIX 2.1 pattern string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _ip_stix_pattern(ip: str) -> str:
    """Build a STIX 2.1 pattern for an IPv4 or IPv6 address literal."""
    escaped = _escape_stix_value(ip)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"[ipv4-addr:value = '{escaped}']"
    if isinstance(addr, ipaddress.IPv6Address):
        return f"[ipv6-addr:value = '{escaped}']"
    return f"[ipv4-addr:value = '{escaped}']"


def _assert_no_infra_leaks(serialized_bundle: str, reporting: ReportingConfig) -> None:
    """Raise ValueError if any infra IP, variant, CIDR member, or hostname appears in STIX JSON.

    OPSEC: error message omits the raw leaked value (reports sha256 prefix only).
    """
    lowered_bundle = serialized_bundle.lower()

    for infra_ip in reporting.redact.infrastructure_ips:
        if not infra_ip:
            continue
        for variant in derive_ip_variants(infra_ip):
            if variant and variant.lower() in lowered_bundle:
                digest = hashlib.sha256(variant.encode("utf-8")).hexdigest()[:12]
                msg = f"Infrastructure IP leak in STIX bundle (variant sha256={digest})"
                raise ValueError(msg)

    for hostname in reporting.redact.infrastructure_hostnames:
        cleaned = hostname.strip().lower()
        if cleaned and cleaned in lowered_bundle:
            digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:12]
            msg = f"Infrastructure hostname leak in STIX bundle (sha256={digest})"
            raise ValueError(msg)

    cidr_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in reporting.redact.infrastructure_cidrs:
        try:
            cidr_nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            continue

    parsed_infra: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for infra_ip in reporting.redact.infrastructure_ips:
        try:
            addr = ipaddress.ip_address(infra_ip.strip())
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
            parsed_infra.add(addr)
        except ValueError:
            continue

    if cidr_nets or parsed_infra:
        ip_tokens = set(_IPV4_EXTRACT_RE.findall(serialized_bundle)) | set(
            _IPV6_EXTRACT_RE.findall(serialized_bundle)
        )
        for token in ip_tokens:
            try:
                addr = ipaddress.ip_address(token)
            except ValueError:
                continue
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
            if addr in parsed_infra or any(addr in net for net in cidr_nets):
                digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
                msg = f"Infrastructure IP leak in STIX bundle (cidr/canonical sha256={digest})"
                raise ValueError(msg)


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
    """Create transient 7-day Indicator objects for interactive/authenticated inbound IPs.

    Gating:
      * ``risk_score >= RISK_THRESHOLD`` (40.0)
      * ``behavioral_risk_score > 0`` (or legacy behavioral columns > 0)
      * NOT ``greynoise_riot == True`` and NOT ``greynoise_class == "benign"``
    """
    if reputation.is_empty():
        return []

    fallback_ts = default_ts if default_ts is not None else datetime.now(tz=UTC)
    valid_until = fallback_ts + timedelta(days=INBOUND_IP_VALID_DAYS)

    mask = pl.col("risk_score") >= RISK_THRESHOLD
    if "behavioral_risk_score" in reputation.columns:
        mask = mask & (pl.col("behavioral_risk_score").fill_null(0.0) > 0.0)
    else:
        legacy_behav = pl.lit(False)
        for col in ("auth_attempts", "auth_successes", "commands_executed", "findings_triggered"):
            if col in reputation.columns:
                legacy_behav = legacy_behav | (pl.col(col).fill_null(0) > 0)
        mask = mask & legacy_behav

    if "greynoise_riot" in reputation.columns:
        mask = mask & ~pl.col("greynoise_riot").fill_null(False)
    if "greynoise_class" in reputation.columns:
        mask = mask & (pl.col("greynoise_class").fill_null("") != "benign")

    risky = reputation.filter(mask)
    indicators: list[stix2.Indicator] = []

    for row in risky.iter_rows(named=True):
        ip = row["src_endpoint_ip"]
        if not ip:
            continue

        labels = ["malicious-activity"]
        if not progression.is_empty():
            ip_prog = progression.filter(pl.col("src_endpoint_ip") == ip)
            if ip_prog.height > 0:
                stage = ip_prog.row(0, named=True)["stage_label"]
                labels = list(_STAGE_LABELS.get(stage, labels))

        # Only attach GreyNoise actor name when GreyNoise classifies it malicious
        # (never label benign internet scanners like Censys/Shadowserver/Driftnet).
        gn_name = row.get("greynoise_name")
        gn_class = row.get("greynoise_class")
        gn_riot = bool(row.get("greynoise_riot") or False)
        if gn_name and gn_name not in ("", "unknown") and gn_class == "malicious" and not gn_riot:
            labels.append(str(gn_name))

        gti_actors = row.get("gti_threat_actors")
        if isinstance(gti_actors, str) and gti_actors.strip():
            for actor in gti_actors.split(","):
                actor_clean = actor.strip()
                if actor_clean and actor_clean not in labels:
                    labels.append(actor_clean)

        description_parts = [
            f"Risk score: {row['risk_score']:.1f}",
            f"Events: {row['total_events']}",
        ]
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
        if row.get("auth_attempts", 0) > 0:
            description_parts.append(f"Auth: {row.get('auth_successes', 0)}/{row['auth_attempts']}")
        if row.get("commands_executed", 0) > 0:
            description_parts.append(f"Commands: {row['commands_executed']}")
        if row.get("vt_malicious") and row["vt_malicious"] > 0:
            description_parts.append(f"VT detections: {row['vt_malicious']}")
        if row.get("shodan_vulns"):
            vuln_count = len(str(row["shodan_vulns"]).split(","))
            description_parts.append(f"Known CVEs: {vuln_count}")

        valid_from = _ensure_utc_dt(row.get("first_seen"), fallback_ts)
        ind_valid_until = _ensure_valid_until(valid_from, valid_until, INBOUND_IP_VALID_DAYS)

        indicators.append(
            stix2.Indicator(
                name=str(ip),
                description=". ".join(description_parts),
                pattern=_ip_stix_pattern(str(ip)),
                pattern_type="stix",
                valid_from=valid_from,
                valid_until=ind_valid_until,
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
        first_seen = _ensure_utc_dt(row.get("first_seen"), fallback_ts)

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
    """Fallback malware hash SDO builder when ``extracted_iocs`` is not provided."""
    if summary.is_empty():
        return [], [], []

    fallback_ts = default_ts if default_ts is not None else datetime.now(tz=UTC)
    valid_until = fallback_ts + timedelta(days=MALWARE_PERSISTENCE_VALID_DAYS)
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
            pattern=f"[file:hashes.'SHA-256' = '{_escape_stix_value(sha256)}']",
            pattern_type="stix",
            valid_from=fallback_ts,
            valid_until=valid_until,
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


def _make_durable_ioc_objects(
    extracted_iocs: pl.DataFrame,
    identity: stix2.Identity,
    tlp: stix2.MarkingDefinition,
    default_ts: datetime | None = None,
) -> list[object]:
    """Create STIX 2.1 SDOs and Relationships from the ``extracted_iocs`` Gold table."""
    if extracted_iocs.is_empty():
        return []

    fallback_ts = default_ts if default_ts is not None else datetime.now(tz=UTC)
    infra_valid_until = fallback_ts + timedelta(days=OUTBOUND_INFRA_VALID_DAYS)
    artifact_valid_until = fallback_ts + timedelta(days=MALWARE_PERSISTENCE_VALID_DAYS)

    objects: list[object] = []
    actors_by_name: dict[str, stix2.ThreatActor] = {}

    def _get_or_create_actor(actor_name: str) -> stix2.ThreatActor:
        existing = actors_by_name.get(actor_name)
        if existing is not None:
            return existing
        actor = stix2.ThreatActor(
            name=actor_name,
            description=f"Confidence-gated threat actor attribution from GTI ({actor_name}).",
            created=fallback_ts,
            created_by_ref=identity.id,
            object_marking_refs=[tlp.id],
        )
        actors_by_name[actor_name] = actor
        objects.append(actor)
        return actor

    for row in extracted_iocs.iter_rows(named=True):
        ioc_type = str(row.get("ioc_type") or "")
        ioc_value = str(row.get("ioc_value") or "").strip()
        if not ioc_value:
            continue

        valid_from = _ensure_utc_dt(row.get("first_seen"), fallback_ts)
        row_infra_until = _ensure_valid_until(
            valid_from, infra_valid_until, OUTBOUND_INFRA_VALID_DAYS
        )
        row_artifact_until = _ensure_valid_until(
            valid_from, artifact_valid_until, MALWARE_PERSISTENCE_VALID_DAYS
        )

        vhash = row.get("vhash")
        family = row.get("malware_family")
        vt_mal = row.get("vt_malicious")
        gti_verdict = row.get("gti_verdict")
        actor_csv = row.get("actor_associations")

        meta_parts = [f"Events: {row.get('event_count', 1)}"]
        if row.get("unique_src_ips"):
            meta_parts.append(f"Unique source IPs: {row['unique_src_ips']}")
        if vhash:
            meta_parts.append(f"vhash: {vhash}")
        if family:
            meta_parts.append(f"Family: {family}")
        if vt_mal is not None:
            meta_parts.append(f"VT detections: {vt_mal}")
        if gti_verdict:
            meta_parts.append(f"GTI verdict: {gti_verdict}")
        meta_desc = ". ".join(meta_parts)

        if ioc_type == "malware_hash":
            labels = ["malicious-activity", "malware"]
            if vhash:
                labels.append(f"vhash:{str(vhash)[:16]}")
            if family:
                labels.append(str(family))
            malware = stix2.Malware(
                name=str(family) if family else f"sample-{ioc_value[:12]}",
                description=(
                    f"Malware sample captured by honeypot (SHA256: {ioc_value}). {meta_desc}"
                ),
                is_family=bool(family),
                created=fallback_ts,
                created_by_ref=identity.id,
                object_marking_refs=[tlp.id],
            )
            indicator = stix2.Indicator(
                name=f"file-{ioc_value[:12]}",
                description=f"Captured malware hash. {meta_desc}",
                pattern=f"[file:hashes.'SHA-256' = '{_escape_stix_value(ioc_value)}']",
                pattern_type="stix",
                valid_from=valid_from,
                valid_until=row_artifact_until,
                created=fallback_ts,
                labels=labels,
                created_by_ref=identity.id,
                object_marking_refs=[tlp.id],
            )
            rel = stix2.Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware.id,
                created=fallback_ts,
                created_by_ref=identity.id,
                object_marking_refs=[tlp.id],
            )
            objects.extend([malware, indicator, rel])

            if isinstance(actor_csv, str) and actor_csv.strip():
                for raw_actor in actor_csv.split(","):
                    name = raw_actor.strip()
                    if not name:
                        continue
                    actor = _get_or_create_actor(name)
                    objects.append(
                        stix2.Relationship(
                            relationship_type="uses",
                            source_ref=actor.id,
                            target_ref=malware.id,
                            created=fallback_ts,
                            created_by_ref=identity.id,
                            object_marking_refs=[tlp.id],
                        )
                    )

        elif ioc_type == "c2_ip":
            objects.append(
                stix2.Indicator(
                    name=f"c2-{ioc_value}",
                    description=f"Outbound C2 / payload staging IP observed post-auth. {meta_desc}",
                    pattern=_ip_stix_pattern(ioc_value),
                    pattern_type="stix",
                    valid_from=valid_from,
                    valid_until=row_infra_until,
                    created=fallback_ts,
                    labels=["malicious-activity", "command-and-control"],
                    created_by_ref=identity.id,
                    object_marking_refs=[tlp.id],
                )
            )

        elif ioc_type == "stager_url":
            objects.append(
                stix2.Indicator(
                    name=f"url-{hashlib.sha256(ioc_value.encode('utf-8')).hexdigest()[:12]}",
                    description=f"Post-auth malware stager URL. {meta_desc}",
                    pattern=f"[url:value = '{_escape_stix_value(ioc_value)}']",
                    pattern_type="stix",
                    valid_from=valid_from,
                    valid_until=row_infra_until,
                    created=fallback_ts,
                    labels=["malicious-activity", "malware-staging"],
                    created_by_ref=identity.id,
                    object_marking_refs=[tlp.id],
                )
            )

        elif ioc_type == "stager_domain":
            objects.append(
                stix2.Indicator(
                    name=f"domain-{ioc_value}",
                    description=f"Post-auth malware staging domain. {meta_desc}",
                    pattern=f"[domain-name:value = '{_escape_stix_value(ioc_value)}']",
                    pattern_type="stix",
                    valid_from=valid_from,
                    valid_until=row_infra_until,
                    created=fallback_ts,
                    labels=["malicious-activity", "malware-staging"],
                    created_by_ref=identity.id,
                    object_marking_refs=[tlp.id],
                )
            )

        elif ioc_type == "ssh_key":
            objects.append(
                stix2.Indicator(
                    name=f"sshkey-{hashlib.sha256(ioc_value.encode('utf-8')).hexdigest()[:12]}",
                    description=f"Attacker persistence OpenSSH public key. {meta_desc}",
                    pattern=f"[x-lantana-ssh-key:fingerprint = '{_escape_stix_value(ioc_value)}']",
                    pattern_type="stix",
                    valid_from=valid_from,
                    valid_until=row_artifact_until,
                    created=fallback_ts,
                    labels=["malicious-activity", "persistence"],
                    created_by_ref=identity.id,
                    object_marking_refs=[tlp.id],
                )
            )

    return objects


def generate_bundle(
    gold_date: date,
    reporting: ReportingConfig,
    reputation: pl.DataFrame,
    progression: pl.DataFrame,
    clusters: pl.DataFrame,
    summary: pl.DataFrame | None = None,
    detection: pl.DataFrame | None = None,
    extracted_iocs: pl.DataFrame | None = None,
) -> stix2.Bundle:
    """Generate a STIX 2.1 bundle from gold-layer data for a given date.

    Note: ``detection`` is retained as an optional keyword parameter for API
    compatibility; Suricata rules are no longer emitted as synthetic HTTP
    Indicator patterns.
    """
    _ = detection
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

    # Durable IOCs from 7th gold table (or fallback to summary top hashes when absent)
    if extracted_iocs is not None and not extracted_iocs.is_empty():
        objects.extend(
            _make_durable_ioc_objects(
                extracted_iocs,
                identity,
                tlp,
                default_ts=default_ts,
            )
        )
    elif summary is not None:
        malware_objects, hash_indicators, malware_rels = _make_malware_indicators(
            summary,
            identity,
            tlp,
            default_ts=default_ts,
        )
        objects.extend(malware_objects)
        objects.extend(hash_indicators)
        objects.extend(malware_rels)

    if len(objects) > 1:
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

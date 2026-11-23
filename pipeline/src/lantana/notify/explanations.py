"""Shared What / Why / How text for brief sections and Vigil dashboard widgets.

The daily brief and the air-gapped Vigil dashboard surface the same data
through different rendering paths. To keep the explanations in sync — so the
analyst learns one mental model and finds it in both places — the text lives
here as plain constants. Brief sections render the triplet as an italic
one-liner under the ``##`` heading; dashboard cards and sections render it
inside collapsible ``<details>`` help blocks.

Each entry is a ``WhatWhyHow`` dataclass — keep the three clauses short
(target ~120 chars total) so the italic line under a heading stays concise.

Risk-threshold numbers embedded in any triplet (40, 70, ...) are
f-string interpolated from ``intel/stix.py`` so the registry can't drift
from ``risk_level_label`` / the bucket filters / the dashboard explainer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from lantana.intel.stix import RISK_HIGH_THRESHOLD, RISK_THRESHOLD

_HIGH: Final[int] = int(RISK_HIGH_THRESHOLD)
_MED: Final[int] = int(RISK_THRESHOLD)


@dataclass(frozen=True)
class WhatWhyHow:
    """Three-clause explanation of a metric or section."""

    what: str
    why: str
    how: str

    def italic_one_liner(self) -> str:
        """For the brief: ``_What: …. Why: …. How: …._`` under a heading."""
        return f"_What: {self.what} Why: {self.why} How: {self.how}_"

    def tooltip(self) -> str:
        """For the Vigil dashboard: plain text for metric/section help drawers."""
        return f"What: {self.what} Why: {self.why} How: {self.how}"


# ---------------------------------------------------------------------------
# Brief sections (top-level ``##`` headings)
# ---------------------------------------------------------------------------

BRIEF_SECTIONS: Final[dict[str, WhatWhyHow]] = {
    "Pipeline Health": WhatWhyHow(
        what=(
            "errors, dead-man's-switch liveness, step exit codes, usable disk %, "
            "and blocked sensor egress."
        ),
        why=(
            "catches silent sensor freezes, starvation, disk exhaustion, "
            "and unexpected container egress early."
        ),
        how=(
            "enrichment_errors.json + D-1/D-2 silver presence + statvfs + "
            "systemd status + host sensor-egress.log."
        ),
    ),
    "Pipeline Timing": WhatWhyHow(
        what="wall-clock duration of each scheduled pipeline step.",
        why="spots regressions in enrichment throughput or transform cost.",
        how="systemd ExecMainStartTimestamp → ExecMainExitTimestamp per unit.",
    ),
    "Key Metrics": WhatWhyHow(
        what="day's aggregate event/IP counts across all datasets.",
        why="the at-a-glance pulse of operation activity.",
        how="OCSF event counts grouped by class on silver, post-redaction.",
    ),
    "Geographic Origin": WhatWhyHow(
        what="source countries and ASNs ranked by unique attacker IPs.",
        why="reveals geographic concentration and shared hosting infrastructure.",
        how="MaxMind GeoLite2 City + ASN lookup, deduplicated per IP per day.",
    ),
    "Escalation Funnel": WhatWhyHow(
        what="distinct IPs by deepest behavioral stage reached.",
        why="separates noisy scanners from targeted, interactive attackers.",
        how="max_stage on behavioral_progression: scan → cred → auth → interactive.",
    ),
    "Top Attackers": WhatWhyHow(
        what="source IPs ranked by monotonic behavioral-anchored composite risk_score.",
        why="prioritises interactive attackers over pure scanners and unindexed IPs.",
        how="pure scans <= 35; interactive = max(behavioral, (enrichment + behavioral)/2).",
    ),
    "Threat Actor Attribution": WhatWhyHow(
        what="IPs and malware samples tied to malicious actors (GreyNoise malicious or GTI).",
        why="cuts triage time without falsely attributing benign internet scanners.",
        how="greynoise_classification == 'malicious' or confidence-gated GTI associations.",
    ),
    "Notable Escalations": WhatWhyHow(
        what="IPs that reached authenticated or interactive stages.",
        why="these moved past scanning into hands-on-keyboard behaviour.",
        how="behavioral_progression rows with max_stage ≥ 3.",
    ),
    "Campaign Clusters": WhatWhyHow(
        what="credential pairs reused by two or more source IPs.",
        why="hints at botnets, shared toolkits, or coordinated campaigns.",
        how="groupby(username, password) on auth events, filter ip_count ≥ 2.",
    ),
    "Detection Highlights": WhatWhyHow(
        what="top Suricata rules ranked by event count.",
        why="surfaces what IDS signatures fired most across the day.",
        how="silver suricata events grouped by finding_title, ordered by count.",
    ),
    "Top Rules by Event Count": WhatWhyHow(
        what="horizontal bar of the top-20 firing Suricata rules with full titles and SIDs.",
        why="surfaces the highest-volume IDS signatures after excluding decoder noise.",
        how="go.Bar over detection_findings, colour-encoded by unique_ips / IP-days.",
    ),
    "Rule Concentration": WhatWhyHow(
        what="Pareto chart over the top-50 rules: bars + cumulative-% line.",
        why="answers 'is today's IDS noise dominated by a handful of signatures?'.",
        how="bars sorted by event_count, cumulative % computed against the capped total.",
    ),
    "Risk Score Distribution": WhatWhyHow(
        what="three side-by-side binned histograms — composite risk and its two halves.",
        why="reveals whether risk is enrichment-driven, behavioral-driven, or both.",
        how="go.Histogram (bin width 5) over risk_score / behavioral / enrichment.",
    ),
    "Stage vs Time": WhatWhyHow(
        what="scatter of per-IP max_stage (y) versus first_seen timestamp (x).",
        why=(
            "reveals when stage-N attackers landed — clusters at y=4 early in the day "
            "= morning interactive sessions; flat y=1 spread = scanner background."
        ),
        how="behavioral_progression rows, coloured by is_automated (bot vs manual).",
    ),
    "Progression Velocity": WhatWhyHow(
        what="distribution of days-to-max-stage across the selected date window.",
        why="long-tail to the right = attackers building access over multiple days.",
        how=(
            "(last_seen_date - first_seen_date) in days, aggregated per IP across the "
            "selected daily behavioral_progression gold partitions; only IPs with velocity > 0."
        ),
    ),
    "Multi-Day Progression": WhatWhyHow(
        what="selected date window rollup of every IP's deepest stage reached.",
        why="catches attackers who spread reconnaissance across days to evade per-day rate limits.",
        how=(
            "aggregated on demand from daily behavioral_progression gold partitions. "
            "Multi-day flag is a permissive proxy (active_days > 1) — lossless "
            "per-stage slow-burn detection remains on the README roadmap."
        ),
    ),
    "Multi-Day Attackers": WhatWhyHow(
        what="IPs observed across 2+ days of the selected date window.",
        why=(
            "contrasts with same-day burst behaviour — these are the patient ones "
            "worth a deeper look. Proper per-stage slow-burn detection is deferred."
        ),
        how=(
            "behavioral_progression rows aggregated by src_endpoint_ip across the selected "
            "daily partitions; flagged where active_days > 1, ranked by velocity_days."
        ),
    ),
    # STIX Export page
    "STIX Export": WhatWhyHow(
        what="curated indicators ready for OpenCTI / MISP, plus a long-tail raw IOC CSV.",
        why="machine-readable export for downstream threat-intel platforms and retro-hunting.",
        how="generate_bundle() in intel/stix.py + build_raw_ioc_export() in intel/iocs.py.",
    ),
    "Bundle Composition": WhatWhyHow(
        what="counts of durable IOC and interactive inbound IP objects in the STIX 2.1 bundle.",
        why="mirrors the gates in intel/stix.py so the analyst can preview what ships.",
        how=(
            f"extracted_iocs (hashes, C2 IPs, URLs, domains, SSH keys) plus interactive "
            f"inbound IPs with behavioral > 0 and risk_score >= {_MED} (7d valid_until)."
        ),
    ),
    "Raw IOC Export": WhatWhyHow(
        what="every IP/hash/URL observed on the date, including the long tail STIX drops.",
        why="threshold-free dump for retro-hunting, IDS rule seeding, and lake correlation.",
        how="build_raw_ioc_export() aggregates silver and joins risk_score for IPs.",
    ),
    # Geography page widgets
    "World Map": WhatWhyHow(
        what="one marker per attacker IP, plotted by MaxMind lat/long.",
        why="reveals geographic concentration and hosting-region patterns at a glance.",
        how="size = log10(events+1); colour = risk_score (Plasma scale).",
    ),
    "Top Countries": WhatWhyHow(
        what="top-10 countries by distinct attacker IPs, with total event count for context.",
        why="separates hosting-concentrated traffic (one country, many IPs) from broad noise.",
        how="ip_reputation grouped by geo_country, sorted by unique IPs descending.",
    ),
    "Top Cities": WhatWhyHow(
        what="top-10 (city, country) pairs by distinct attacker IPs.",
        why="city granularity helps spot specific hosting providers or campaign origins.",
        how="ip_reputation grouped by (geo_city, geo_country), sorted by unique IPs.",
    ),
    "Top ASNs": WhatWhyHow(
        what="top-10 ASN/ISP pairs by distinct attacker IPs.",
        why="shared ASN across many IPs hints at compromised hosting or VPN exit nodes.",
        how="ip_reputation grouped by (geo_asn, geo_isp), sorted by unique IPs.",
    ),
    "Malware Captured": WhatWhyHow(
        what="files downloaded by attackers, scoped to file_intent='malware'.",
        why=(
            "connects raw hashes to known malware families for fast triage; "
            "persistence drops and probe payloads are filtered out so they "
            "don't dominate the table."
        ),
        how=(
            "top SHA256s from cowrie file events where file_intent='malware', "
            "joined with vt_file_* enrichment columns."
        ),
    ),
    "Attacker Persistence": WhatWhyHow(
        what=(
            "cowrie file writes tagged file_intent='persistence' — destfiles "
            "that look like SSH/shell/sudo persistence targets."
        ),
        why=(
            "separates SSH-key drops and shell-init writes from malware so "
            "neither category gets misread as the other in triage."
        ),
        how=(
            "silver cowrie rows where file_intent='persistence', grouped by "
            "destfile, sorted by count."
        ),
    ),
    "Top Credentials": WhatWhyHow(
        what="most-attempted usernames and passwords on the day.",
        why="trending credentials reveal current attacker wordlists.",
        how="silver cowrie auth events grouped by user_name and unmapped_password.",
    ),
    "Top Commands": WhatWhyHow(
        what="most-executed shell commands after a successful auth.",
        why="post-login behaviour reveals attacker intent (recon, persistence, drop).",
        how="silver cowrie command events grouped by actor_process_cmd_line.",
    ),
    # Health page sections
    "Integrations Status": WhatWhyHow(
        what="configured vs unconfigured 3rd-party APIs and their latest run outcome.",
        why="explains missing enrichment or blank Geography views without inspecting secrets.",
        how="boolean presence in secrets.json + enrichment_errors.json + .provider_state.json.",
    ),
    "Dataset Liveness": WhatWhyHow(
        what="latest Bronze and Silver partition dates across all expected sensor datasets.",
        why="spots silent honeypot freezes, Vector drops, or ingestion lag immediately.",
        how="stateless D-1/D-2 freshness check across cowrie, dionaea, suricata, nftables.",
    ),
    "Storage & Retention": WhatWhyHow(
        what="non-root usable disk percentage and per-tier datalake footprint.",
        why="tracks headroom against 70% warning and 80% emergency-prune thresholds.",
        how="os.statvfs (f_bavail) + bounded non-symlink scan of bronze, silver, gold, and cache.",
    ),
    "Recent Messages": WhatWhyHow(
        what="deduped pipeline errors, rate-limit notices, and liveness alerts.",
        why="gives operators the exact failure reason without SSHing into journalctl.",
        how="enrichment_errors.json + evaluate_liveness_alerts(), sanitized at write time.",
    ),
}


# ---------------------------------------------------------------------------
# Dashboard metric cards (Vigil dashboard help drawers)
# ---------------------------------------------------------------------------

METRICS: Final[dict[str, WhatWhyHow]] = {
    "Total Events": WhatWhyHow(
        what="every OCSF-normalized event for the day across all datasets.",
        why="baseline activity number for the day.",
        how="row count of silver across cowrie/dionaea/suricata/nftables.",
    ),
    "Unique IPs": WhatWhyHow(
        what="distinct source IPs that produced at least one event.",
        why="cardinality of the attacker population.",
        how="silver src_endpoint_ip distinct, post-redaction.",
    ),
    "Auth Attempts": WhatWhyHow(
        what="total login attempts (success + failure).",
        why="brute-force pressure indicator.",
        how="silver events with class_uid=3002 (Authentication).",
    ),
    "Auth Successes": WhatWhyHow(
        what="login attempts the honeypot accepted.",
        why="ratio to attempts reveals attacker wordlist quality.",
        how="auth events with status_id=1 (success).",
    ),
    "Auth Failures": WhatWhyHow(
        what="login attempts the honeypot rejected.",
        why="the bulk signal of credential stuffing / brute force.",
        how="auth events with status_id=2 (failure).",
    ),
    "Commands": WhatWhyHow(
        what="post-login shell commands executed by attackers.",
        why="signals hands-on-keyboard activity beyond scanning.",
        how="silver events with class_uid=1007 (Process Activity).",
    ),
    "Findings": WhatWhyHow(
        what="IDS rule matches produced by Suricata.",
        why="categorical view of what types of malicious traffic landed.",
        how="silver events with class_uid=2004 (Detection Finding).",
    ),
    "Network Events": WhatWhyHow(
        what="connection-level events from nftables and network sensors.",
        why="L3/L4 picture of reconnaissance traffic.",
        how="silver events with class_uid=4001 (Network Activity).",
    ),
    # Detection-findings page metric cards
    "Total Rules": WhatWhyHow(
        what="number of distinct Suricata rules that fired today.",
        why="cardinality of the IDS signature space — broad vs targeted.",
        how="row count of detection_findings gold for the date.",
    ),
    "Total Detection Events": WhatWhyHow(
        what="sum of all rule-match events across every firing rule.",
        why="overall IDS pressure — a few rules firing thousands of times.",
        how="sum(event_count) over detection_findings.",
    ),
    "Total Detection IPs": WhatWhyHow(
        what="sum of unique source IPs per rule (not deduped across rules).",
        why="an IP triggering N rules counts N times — measures rule breadth.",
        how="sum(unique_ips) over detection_findings.",
    ),
    # IP Reputation page metric cards
    "Total Scored IPs": WhatWhyHow(
        what="distinct source IPs that received a risk_score on this date.",
        why="cardinality of today's scoring pass — the universe the buckets divide.",
        how="row count of ip_reputation gold for the date.",
    ),
    "High Risk IPs": WhatWhyHow(
        what=f"IPs with risk_score >= {_HIGH}.",
        why="drives the Discord top-N and the OpenCTI feed; pageable signal.",
        how=f"reputation.filter(risk_score >= {_HIGH}).",
    ),
    "Medium Risk IPs": WhatWhyHow(
        what=f"IPs with risk_score in [{_MED}, {_HIGH}).",
        why=f"STIX Indicator threshold sits at {_MED} — worth a glance, not pageable.",
        how=f"reputation.filter({_MED} <= risk_score < {_HIGH}).",
    ),
    "Low Risk IPs": WhatWhyHow(
        what=f"IPs with risk_score < {_MED}.",
        why="typically scanner noise or behavioral-only signal below the STIX cut.",
        how=f"reputation.filter(risk_score < {_MED}).",
    ),
    # Behavioral Progression page metric cards
    "Stage Scan": WhatWhyHow(
        what="IPs that produced any event (nftables drop, suricata alert, cowrie probe).",
        why="floor of the funnel — the entire attacker population for the day.",
        how="behavioral_progression.filter(max_stage >= 1).",
    ),
    "Stage Credential": WhatWhyHow(
        what="IPs that submitted at least one auth attempt to cowrie or dionaea.",
        why="separates scanners from credential-stuffing tools.",
        how="behavioral_progression.filter(max_stage >= 2).",
    ),
    "Stage Authenticated": WhatWhyHow(
        what="IPs the honeypot accepted (cowrie's permissive auth).",
        why="signals a working credential or a bot guessing right.",
        how="behavioral_progression.filter(max_stage >= 3).",
    ),
    "Stage Interactive": WhatWhyHow(
        what="authenticated IPs that ran shell commands after login.",
        why="hands-on-keyboard or scripted post-exploitation — the highest-intent signal.",
        how="behavioral_progression.filter(max_stage >= 4).",
    ),
    "Automated Bots": WhatWhyHow(
        what="IPs flagged as automated by GreyNoise classification or timing heuristics.",
        why="separates known scanner infrastructure from manual operators.",
        how="behavioral_progression.filter(is_automated).",
    ),
    "Manual or Unknown": WhatWhyHow(
        what="IPs without an automation signal — manual operators or unattributed bots.",
        why="the higher-effort attacker bucket; worth focused review.",
        how="behavioral_progression.filter(~is_automated).",
    ),
    "Multi-Day IPs": WhatWhyHow(
        what="IPs observed across 2+ days of the trailing 7-day window.",
        why=(
            "permissive proxy for slow-burn behaviour — patient attackers evading "
            "per-day rate limits. Proper per-stage detection is deferred."
        ),
        how=(
            "behavioral_progression aggregated over 7 daily partitions, "
            "filtered to active_days > 1."
        ),
    ),
    "Total Multi-Day IPs": WhatWhyHow(
        what="distinct IPs seen at least once in the trailing 7-day window.",
        why="cardinality of the multi-day surface — the universe Multi-Day IPs divides.",
        how="distinct src_endpoint_ip across 7 daily behavioral_progression partitions.",
    ),
    # STIX Export page metric cards
    "IP Indicators": WhatWhyHow(
        what=f"attacker IPs above the STIX risk threshold ({_MED}).",
        why="become STIX [ipv4-addr:value = ...] Indicators; drive the OpenCTI feed.",
        how=f"reputation.filter(risk_score >= {_MED}).",
    ),
    "Hash Indicators": WhatWhyHow(
        what="file SHA256s captured from cowrie downloads.",
        why="each emits a STIX [file:hashes.'SHA-256' = ...] Indicator + matching Malware SDO.",
        how="length of summary.top_download_hashes.",
    ),
    "Network-rule Indicators": WhatWhyHow(
        what="Suricata rules triggered by >= 5 unique source IPs.",
        why="broad enough to be worth sharing as intel; one STIX Indicator per rule.",
        how="detection_findings.filter(unique_ips >= 5).",
    ),
    "Campaigns": WhatWhyHow(
        what="credential-stuffing clusters: username:password pairs reused by >= 2 IPs.",
        why="become STIX Campaign SDOs linking shared-credential botnets together.",
        how="row count of campaign_clusters gold for the date.",
    ),
    # Credentials page metric cards
    "Active Clusters": WhatWhyHow(
        what="number of credential-stuffing clusters detected today.",
        why="each cluster groups >= 2 IPs reusing the same credentials — likely botnet activity.",
        how="row count of campaign_clusters gold for the date.",
    ),
    "Authentication Outcome": WhatWhyHow(
        what="proportion of auth attempts the honeypot accepted vs rejected.",
        why=(
            "success rate exposes attacker wordlist quality — "
            "high % = lucky guesses or weak creds list."
        ),
        how=(
            "auth_successes / auth_attempts on daily_summary, "
            "rendered as a donut with the rate centered."
        ),
    ),
    "Events by Type": WhatWhyHow(
        what="event count split across Auth, Commands, Findings, Network, and Downloads.",
        why="reveals where today's activity sits — credential stuffing vs hands-on vs scans.",
        how="horizontal stacked bar over OCSF class counts from daily_summary.",
    ),
    "Malware Uploaded": WhatWhyHow(
        what="non-probe, non-persistence malware captures across Cowrie and Dionaea.",
        why="tracks payload delivery volume and distinct SHA-256 samples.",
        how="downloads_captured on daily_summary + malware_hash rows in extracted_iocs.",
    ),
    "Outbound C2 & Stagers": WhatWhyHow(
        what="outbound C2 IPs, stager URLs, and staging domains extracted post-auth.",
        why="durable attacker infrastructure that outlives rotating botnet source IPs.",
        how="extracted_iocs rows with ioc_type in {c2_ip, stager_url, stager_domain}.",
    ),
    "Durable IOCs": WhatWhyHow(
        what="all durable daily observables: malware hashes, C2 IPs, URLs, domains, SSH keys.",
        why="high-shelf-life threat intelligence ready for OpenCTI, MISP, and retro-hunting.",
        how="row count of the extracted_iocs Gold table across the active window.",
    ),
    "Usable Disk": WhatWhyHow(
        what="non-root usable filesystem usage percentage matching df.",
        why="ext4 reserves ~5% for root; unprivileged nectar hits ENOSPC at 100% usable.",
        how="os.statvfs used / (used + f_bavail); warn >70%, emergency prune >80%.",
    ),
    "Enrichment Cache": WhatWhyHow(
        what="active (unexpired) IOC records cached in .enrichment_cache.db.",
        why="avoids burning scarce free-tier API quota on repeat scanners and known hashes.",
        how="read-only SQLite count where expires_at > now() across ip/hash/url/domain.",
    ),
    "Overall Status": WhatWhyHow(
        what="Healthy (all clear), Degraded (non-critical issues below), or Critical (data loss).",
        why="distinguishes routine rate-limits/warnings from outages that stop telemetry capture.",
        how="Critical on starvation/2+d silence/unit fail/disk>80%; Degraded on warn/429/disk>70%.",
    ),
    "Integrations Active": WhatWhyHow(
        what="count of 3rd-party APIs configured in secrets.json out of 6 optional services.",
        why="unset optional keys show Not Configured and never degrade Overall Status.",
        how="boolean presence check on secrets.json + on-disk MaxMind MMDB verification.",
    ),
    "Latest Run Alerts": WhatWhyHow(
        what="latest-partition alert totals split into C (Critical), W (Warning), and I (Info).",
        why="separates urgent failures (C) and key/network errors (W) from routine 429s (I).",
        how="enrichment_errors.json + evaluate_liveness_alerts() classified via notify/alerts.py.",
    ),
    "Sensor Egress": WhatWhyHow(
        what="blocked unsolicited outbound or loopback connection attempts from sensor containers.",
        why=(
            "Lantana sensors are non-egressing; any non-canary drop signals "
            "abuse, compromise, or config drift."
        ),
        how=(
            "read-only parse of host sensor-egress.log [LANTANA_OUTPUT_DROP_SENSOR_*] "
            "excluding RFC 5737 / loopback:1 canaries and SRC=."
        ),
    ),
}

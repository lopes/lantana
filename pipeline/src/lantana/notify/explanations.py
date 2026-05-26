"""Shared What / Why / How text for brief sections and dashboard widgets.

The daily brief and the Streamlit dashboard surface the same data through
different rendering paths. To keep the explanations in sync — so the
analyst learns one mental model and finds it in both places — the text
lives here as plain constants. Brief sections render the triplet as an
italic one-liner under the ``##`` heading; dashboard metric cards use it
verbatim in Streamlit's ``help=`` tooltip; dashboard chart sections render
it via ``st.caption()``.

Each entry is a ``WhatWhyHow`` dataclass — keep the three clauses short
(target ~120 chars total) so the italic line under a heading stays on one
visual row and the metric tooltip doesn't overflow Streamlit's hover popup.

Risk-threshold numbers embedded in any triplet (40, 70, ...) are
f-string interpolated from ``intel/stix.py`` so the registry can't drift
from ``_risk_label`` / the bucket filters / the dashboard explainer.
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
        """For the dashboard: plain text suitable for Streamlit's ``help=``."""
        return f"What: {self.what} Why: {self.why} How: {self.how}"


# ---------------------------------------------------------------------------
# Brief sections (top-level ``##`` headings)
# ---------------------------------------------------------------------------

BRIEF_SECTIONS: Final[dict[str, WhatWhyHow]] = {
    "Pipeline Health": WhatWhyHow(
        what="previous run's enrichment errors classified into severity tiers.",
        why="surfaces pipeline degradation before silent data loss accrues.",
        how="rows from enrichment_errors.json grouped by (provider, error_type).",
    ),
    "Pipeline Timing": WhatWhyHow(
        what="wall-clock duration of each scheduled pipeline step.",
        why="spots regressions in enrichment throughput or transform cost.",
        how="systemd ActiveEnterTimestamp → InactiveEnterTimestamp per unit.",
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
        what="source IPs ranked by composite risk_score.",
        why="prioritises analyst attention on the highest-value targets.",
        how="risk_score = (enrichment + behavioral)/2, clipped 0..100.",
    ),
    "Threat Actor Attribution": WhatWhyHow(
        what="IPs that GreyNoise tags with a known actor/scanner name.",
        why="cuts triage time on known benign-but-noisy or known-bad actors.",
        how="non-empty, non-'unknown' greynoise_name from ip_reputation.",
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
        what="horizontal bar of the top-20 firing Suricata rules with full titles.",
        why="long rule names need automargin; the native Streamlit chart truncates them.",
        how="px.bar over detection_findings, colour-encoded by unique_ips.",
    ),
    "Rule Concentration": WhatWhyHow(
        what="Pareto chart over the top-50 rules: bars + cumulative-% line.",
        why="answers 'is today's IDS noise dominated by a handful of signatures?'.",
        how="bars sorted by event_count, cumulative % computed against the capped total.",
    ),
    "Risk Score Distribution": WhatWhyHow(
        what="three side-by-side histograms — composite risk and its two halves.",
        why="reveals whether today's risk is enrichment-driven, behavioral-driven, or both.",
        how="bar_chart over risk_score / enrichment_risk_score / behavioral_risk_score.",
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
        what="distribution of days-to-max-stage across the 7-day window.",
        why="long-tail to the right = slow-burn attackers building access over multiple days.",
        how="multiday progression_velocity_days bucketed and counted; only IPs with velocity > 0.",
    ),
    "Multi-Day Progression": WhatWhyHow(
        what="7-day-lookback rollup of every IP's deepest stage reached.",
        why="catches attackers who spread reconnaissance across days to evade per-day rate limits.",
        how="behavioral_progression_multiday gold table, computed over the trailing 7 days.",
    ),
    "Slow-Burn Attackers": WhatWhyHow(
        what="IPs whose progression spanned multiple days before reaching max stage.",
        why=(
            "contrasts with same-day burst behaviour — these are the "
            "patient ones worth a deeper look."
        ),
        how="multiday rows where is_slow_burn flag is set, ranked by velocity_days.",
    ),
    # STIX Export page
    "STIX Export": WhatWhyHow(
        what="curated indicators ready for OpenCTI / MISP, plus a long-tail raw IOC CSV.",
        why="machine-readable export for downstream threat-intel platforms and retro-hunting.",
        how="generate_bundle() in intel/stix.py + build_raw_ioc_export() in intel/iocs.py.",
    ),
    "Bundle Composition": WhatWhyHow(
        what="counts of each indicator/object type the STIX bundle will contain.",
        why="mirrors the filters in intel/stix.py so the analyst can preview what ships.",
        how=(
            f"IP indicators apply risk_score >= {_MED}; network-rule "
            "indicators apply unique_ips >= 5."
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
        what="files downloaded by attackers with VT family/type context.",
        why="connects raw hashes to known malware families for fast triage.",
        how="top SHA256s from cowrie joined with vt_file_* enrichment columns.",
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
}


# ---------------------------------------------------------------------------
# Dashboard metric cards (Streamlit ``st.metric`` help= tooltips)
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
        how="silver events with class_uid=1005 (Process Activity).",
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
    "Slow-Burn IPs": WhatWhyHow(
        what="IPs whose progression spanned multiple days before hitting max stage.",
        why="patient attackers evading per-day rate limits and chunked detection logic.",
        how="multiday.filter(is_slow_burn).",
    ),
    "Total Multi-Day IPs": WhatWhyHow(
        what="distinct IPs seen at least once in the trailing 7-day window.",
        why="cardinality of the multi-day surface — the universe slow-burn divides.",
        how="row count of behavioral_progression_multiday.",
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
        what="event count split across Auth, Commands, Findings, and Network classes.",
        why="reveals where today's activity sits — credential stuffing vs hands-on vs L3/L4 scans.",
        how="horizontal stacked bar over the four OCSF class counts from daily_summary.",
    ),
}

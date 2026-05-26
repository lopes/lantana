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
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


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
}

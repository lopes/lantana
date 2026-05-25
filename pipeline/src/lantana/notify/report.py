"""Intel report generation from gold-layer data.

Produces Markdown daily briefs from gold tables. The embed summary
is a short Discord-compatible excerpt; the full brief is attached
as a .md file.
"""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type
from typing import TYPE_CHECKING, Any

import polars as pl

if TYPE_CHECKING:
    from lantana.notify.alerts import ErrorBuckets


def _fmt_provider_risk(row: dict[str, Any]) -> str:
    """Compact per-provider 0..100 risk-score quadruplet for the Top Attackers
    table.

    Format: ``A/V/S/G`` with each cell being the score rounded to int, or ``-``
    when the provider didn't contribute (column null, e.g. rate-limited
    that day). The four-slot fixed shape makes columns scannable across
    rows even when one provider was offline.

    Replaces the Phase E raw-cells (abuseipdb_score / vt_malicious /
    shodan_ports+CVE) — per-provider risk_score is the comparable
    0..100 surfacing that docs/risk-scoring.md defines.
    """
    def _cell(key: str) -> str:
        value = row.get(key)
        if value is None:
            return "-"
        return f"{round(float(value))}"

    return (
        f"{_cell('abuseipdb_risk_score')}/"
        f"{_cell('virustotal_risk_score')}/"
        f"{_cell('shodan_risk_score')}/"
        f"{_cell('greynoise_risk_score')}"
    )


def _fmt_risk_breakdown(row: dict[str, Any]) -> str:
    """`{composite} = ({enrichment}+{behavioral})/2` — risk decomposition.

    Lets the analyst answer "what drove this score?" without leaving the
    report. Defaults gracefully when sub-scores are absent (e.g. old gold
    partitions written before Phase D.2)."""
    composite = row.get("risk_score")
    enrichment = row.get("enrichment_risk_score")
    behavioral = row.get("behavioral_risk_score")
    if composite is None:
        return "-"
    if enrichment is None and behavioral is None:
        return f"{composite:.1f}"
    e_str = f"{enrichment:.0f}" if enrichment is not None else "—"
    b_str = f"{behavioral:.0f}" if behavioral is not None else "—"
    return f"{composite:.1f} ({e_str}+{b_str})/2"


def _render_pipeline_health(buckets: ErrorBuckets) -> list[str]:
    """Render the Pipeline Health markdown section from a three-tier bucket.

    Always emits a section header so the operator can verify the pipeline
    self-check ran. Clean days produce a one-line ``✅ No issues.`` body;
    non-clean days render per-tier aggregated tables grouped by
    (provider, error_type, count) so the analyst can see degradation
    patterns without opening logs.
    """
    from lantana.notify.alerts import _grouped_summary

    lines: list[str] = ["## Pipeline Health\n"]

    if buckets.is_clean and not buckets.info:
        lines.append("✅ No issues during the previous pipeline cycle.\n")
        return lines

    crit_n = sum(int(r.get("count", 1)) for r in buckets.critical)
    warn_n = sum(int(r.get("count", 1)) for r in buckets.warning)
    info_n = sum(int(r.get("count", 1)) for r in buckets.info)
    lines.append(
        f"🔴 Critical: **{crit_n}** &nbsp;·&nbsp; "
        f"🟡 Warning: **{warn_n}** &nbsp;·&nbsp; "
        f"🔵 Info: **{info_n}**\n"
    )

    if buckets.critical:
        lines.append("**Critical** — file creation failed:\n")
        lines.append("| Provider | Error Type | Count | Message |")
        lines.append("|----------|-----------|-------|---------|")
        for row in sorted(
            buckets.critical, key=lambda r: int(r.get("count", 1)), reverse=True
        )[:10]:
            provider = row.get("provider", "?")
            etype = row.get("error_type", "?")
            count = row.get("count", 1)
            msg = str(row.get("message", ""))[:120]
            lines.append(f"| `{provider}` | `{etype}` | {count} | {msg} |")
        lines.append("")

    if buckets.warning:
        lines.append("**Warning** — provider degradation (non-routine):\n")
        lines.append("| Provider | Error Type | Count |")
        lines.append("|----------|-----------|-------|")
        for provider, etype, count in _grouped_summary(buckets.warning, top_n=10):
            lines.append(f"| `{provider}` | `{etype}` | {count} |")
        lines.append("")

    if buckets.info:
        lines.append("**Info** — routine ops noise (rate-limit exhaustion):\n")
        lines.append("| Provider | Error Type | Count |")
        lines.append("|----------|-----------|-------|")
        for provider, etype, count in _grouped_summary(buckets.info, top_n=10):
            lines.append(f"| `{provider}` | `{etype}` | {count} |")
        lines.append("")

    return lines


def generate_daily_brief(
    target_date: date,
    summary: pl.DataFrame,
    reputation: pl.DataFrame,
    progression: pl.DataFrame,
    clusters: pl.DataFrame,
    operation_name: str,
    geographic: pl.DataFrame | None = None,
    detection: pl.DataFrame | None = None,
    buckets: ErrorBuckets | None = None,
) -> str:
    """Generate a Markdown daily intelligence brief from gold tables."""
    if summary.is_empty():
        return f"# Daily Brief — {target_date.isoformat()}\n\nNo data available for this date.\n"

    row = summary.row(0, named=True)
    lines: list[str] = []

    # Header
    lines.append(f"# Daily Brief — {target_date.isoformat()}")
    lines.append(f"**Operation:** {operation_name}\n")

    # Pipeline health — operators want this above the data so a critical
    # failure isn't buried below the daily metrics.
    if buckets is not None:
        lines.extend(_render_pipeline_health(buckets))

    # Key metrics
    lines.append("## Key Metrics\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Events | {row['total_events']:,} |")
    lines.append(f"| Unique Source IPs | {row['unique_source_ips']:,} |")
    lines.append(f"| Auth Attempts | {row['auth_attempts']:,} |")
    lines.append(f"| Auth Successes | {row['auth_successes']:,} |")
    lines.append(f"| Auth Failures | {row['auth_failures']:,} |")
    lines.append(f"| Commands Executed | {row['commands_executed']:,} |")
    lines.append(f"| IDS Findings | {row['findings_detected']:,} |")
    lines.append(f"| Network Events | {row['network_events']:,} |")
    lines.append("")

    # Geographic origin
    if geographic is not None and not geographic.is_empty():
        geo_row = geographic.row(0, named=True)
        lines.append("## Geographic Origin\n")

        countries = geo_row.get("top_countries", [])
        if countries:
            lines.append("**Top Countries:**\n")
            lines.append("| Country | Unique IPs |")
            lines.append("|---------|-----------|")
            for entry in countries[:5]:
                parts = entry.split(":")
                lines.append(f"| {parts[0]} | {parts[1]} |")
            lines.append("")

        asns = geo_row.get("top_asns", [])
        if asns:
            lines.append("**Top ASNs:**\n")
            lines.append("| ASN | ISP | Unique IPs |")
            lines.append("|-----|-----|-----------|")
            for entry in asns[:3]:
                parts = entry.split(":")
                asn_info = parts[0] if parts else ""
                count = parts[1] if len(parts) > 1 else "0"
                asn_parts = asn_info.split("|")
                asn = asn_parts[0] if asn_parts else ""
                isp = asn_parts[1] if len(asn_parts) > 1 else ""
                lines.append(f"| {asn} | {isp} | {count} |")
            lines.append("")

    # Escalation funnel (Mermaid)
    if not progression.is_empty():
        scan_n = progression.filter(pl.col("max_stage") >= 1).height
        cred_n = progression.filter(pl.col("max_stage") >= 2).height
        auth_n = progression.filter(pl.col("max_stage") >= 3).height
        inter_n = progression.filter(pl.col("max_stage") >= 4).height

        lines.append("## Escalation Funnel\n")
        lines.append("```mermaid")
        lines.append("graph LR")
        lines.append(f'    S["Scan<br/>{scan_n} IPs"]')
        lines.append(f'    C["Credential<br/>{cred_n} IPs"]')
        lines.append(f'    A["Authenticated<br/>{auth_n} IPs"]')
        lines.append(f'    I["Interactive<br/>{inter_n} IPs"]')
        lines.append("    S --> C --> A --> I")
        lines.append("```\n")

    # Top attackers (by composite risk_score). The "Risk" column shows the
    # composite + the (enrichment+behavioral)/2 decomposition; "A/V/S/G"
    # surfaces each provider's contribution at a glance so an analyst can
    # see which signal drove the score (or notice when only behavioral
    # signals are firing).
    if not reputation.is_empty():
        lines.append("## Top Attackers\n")
        top = reputation.sort("risk_score", descending=True).head(5)
        lines.append("| IP | Risk | Country | Events | Stage | A/V/S/G |")
        lines.append("|----|------|---------|--------|-------|---------|")
        for r in top.iter_rows(named=True):
            stage = ""
            if not progression.is_empty():
                ip_prog = progression.filter(pl.col("src_endpoint_ip") == r["src_endpoint_ip"])
                if ip_prog.height > 0:
                    stage = ip_prog.row(0, named=True)["stage_label"]
            lines.append(
                f"| {r['src_endpoint_ip']} "
                f"| {_fmt_risk_breakdown(r)} "
                f"| {r.get('geo_country', '?')} "
                f"| {r['total_events']:,} | {stage} "
                f"| {_fmt_provider_risk(r)} |"
            )
        lines.append("")
        lines.append("_Risk legend: `composite (enrichment+behavioral)/2`. "
                     "A/V/S/G = AbuseIPDB/VirusTotal/Shodan/GreyNoise per-provider "
                     "risk (0..100, `-` = provider didn't contribute)._")
        lines.append("")

    # Threat actor attribution
    if not reputation.is_empty() and "greynoise_name" in reputation.columns:
        named = reputation.filter(
            pl.col("greynoise_name").is_not_null()
            & (pl.col("greynoise_name") != "")
            & (pl.col("greynoise_name") != "unknown")
        )
        if named.height > 0:
            lines.append("## Threat Actor Attribution\n")
            lines.append("IPs with known threat actor labels (GreyNoise):\n")
            lines.append("| Actor | IP | Classification |")
            lines.append("|-------|----|---------------|")
            for r in named.head(5).iter_rows(named=True):
                lines.append(
                    f"| {r['greynoise_name']} "
                    f"| {r['src_endpoint_ip']} "
                    f"| {r.get('greynoise_class', '?')} |"
                )
            lines.append("")

    # Notable escalations (stage 3+)
    if not progression.is_empty():
        escalated = progression.filter(pl.col("max_stage") >= 3)
        if escalated.height > 0:
            lines.append("## Notable Escalations\n")
            lines.append("IPs that achieved authentication or interactive access:\n")
            for r in escalated.iter_rows(named=True):
                auto = " (automated)" if r["is_automated"] else ""
                lines.append(
                    f"- **{r['src_endpoint_ip']}** — "
                    f"stage: {r['stage_label']}{auto}, "
                    f"auth: {r['auth_successes']}/{r['auth_attempts']}, "
                    f"commands: {r['commands_executed']}"
                )
            lines.append("")

    # Campaign clusters
    if not clusters.is_empty():
        lines.append("## Campaign Clusters\n")
        lines.append("Credential pairs used by multiple IPs (likely botnets):\n")
        for r in clusters.iter_rows(named=True):
            ips = r["ips"]
            ip_str = ", ".join(ips) if isinstance(ips, list) else str(ips)
            lines.append(
                f"- **{r['shared_username']}:{r['shared_password']}** — "
                f"{r['ip_count']} IPs ({ip_str})"
            )
        lines.append("")

    # Detection highlights
    if detection is not None and not detection.is_empty():
        lines.append("## Detection Highlights\n")
        lines.append("Top Suricata rules triggered:\n")
        lines.append("| Rule | Events | Unique IPs |")
        lines.append("|------|--------|-----------|")
        for r in detection.head(5).iter_rows(named=True):
            title = r.get("finding_title", "unknown")
            lines.append(
                f"| {title} | {r['event_count']:,} | {r['unique_ips']:,} |"
            )
        lines.append("")

    # Malware captured
    downloads = row.get("downloads_captured", 0)
    if downloads and downloads > 0:
        lines.append("## Malware Captured\n")
        lines.append(f"**{downloads}** file(s) downloaded by attackers\n")
        download_urls = row.get("top_download_urls", [])
        if download_urls:
            lines.append("**Top URLs:**")
            for entry in download_urls[:5]:
                lines.append(f"- `{entry['value']}` ({entry['count']:,})")
            lines.append("")
        download_hashes = row.get("top_download_hashes", [])
        if download_hashes:
            lines.append("**Top Hashes (SHA256):**")
            for entry in download_hashes[:5]:
                lines.append(f"- `{entry['value']}` ({entry['count']:,})")
            lines.append("")

    # Top credentials
    usernames = row.get("top_usernames", [])
    passwords = row.get("top_passwords", [])
    if usernames or passwords:
        lines.append("## Top Credentials\n")
        if usernames:
            entries = ", ".join(f"{u['value']} ({u['count']:,})" for u in usernames[:5])
            lines.append(f"**Usernames:** {entries}")
        if passwords:
            entries = ", ".join(f"{p['value']} ({p['count']:,})" for p in passwords[:5])
            lines.append(f"**Passwords:** {entries}")
        lines.append("")

    # Top commands
    commands = row.get("top_commands", [])
    if commands:
        lines.append("## Top Commands\n")
        for entry in commands[:5]:
            lines.append(f"- `{entry['value']}` ({entry['count']:,})")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Generated by Lantana | {target_date.isoformat()} | TLP:GREEN*")

    return "\n".join(lines) + "\n"


def generate_embed_summary(
    target_date: date,
    summary: pl.DataFrame,
    progression: pl.DataFrame,
    buckets: ErrorBuckets | None = None,
) -> str:
    """Generate a short Discord embed summary (< 4096 chars).

    This is the embed description; the full report is attached as a file.
    When ``buckets`` is provided, a 1-line health summary is appended so the
    operator sees pipeline status without opening the attachment.
    """
    if summary.is_empty():
        return f"No data available for {target_date.isoformat()}."

    row = summary.row(0, named=True)
    parts: list[str] = []

    parts.append(
        f"**{row['total_events']:,}** events from **{row['unique_source_ips']:,}** unique IPs"
    )
    parts.append(
        f"Auth: {row['auth_successes']}/{row['auth_attempts']} success "
        f"| Commands: {row['commands_executed']} "
        f"| Findings: {row['findings_detected']}"
    )

    if not progression.is_empty():
        stage_counts = []
        for stage, label in [(4, "interactive"), (3, "auth'd"), (2, "cred"), (1, "scan")]:
            n = progression.filter(pl.col("max_stage") >= stage).height
            if n > 0:
                stage_counts.append(f"{n} {label}")
        if stage_counts:
            parts.append(f"Stages: {' | '.join(stage_counts)}")

        auto = progression.filter(pl.col("is_automated")).height
        if auto > 0:
            parts.append(f"Automated bots: {auto}")

    if buckets is not None:
        parts.append(_health_one_liner(buckets))

    parts.append("\nFull report attached.")
    return "\n".join(parts)


def _health_one_liner(buckets: ErrorBuckets) -> str:
    """One-line pipeline-health summary for the Discord embed description.

    Always emits a single line so the operator can see at a glance whether
    yesterday's pipeline was clean / had warnings / had a critical failure
    without opening the markdown attachment.
    """
    if buckets.is_clean and not buckets.info:
        return "✅ Pipeline clean — no issues."
    crit_n = sum(int(r.get("count", 1)) for r in buckets.critical)
    warn_n = sum(int(r.get("count", 1)) for r in buckets.warning)
    info_n = sum(int(r.get("count", 1)) for r in buckets.info)
    parts: list[str] = []
    if crit_n:
        parts.append(f"🔴 {crit_n} critical")
    if warn_n:
        parts.append(f"🟡 {warn_n} warning")
    if info_n:
        parts.append(f"🔵 {info_n} info")
    return " · ".join(parts)

"""Intel report generation from gold-layer data.

Produces Markdown daily briefs from gold tables. The embed summary
is a short Discord-compatible excerpt; the full brief is attached
as a .md file.
"""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import polars as pl


def generate_daily_brief(
    target_date: date,
    summary: pl.DataFrame,
    reputation: pl.DataFrame,
    progression: pl.DataFrame,
    clusters: pl.DataFrame,
    operation_name: str,
    geographic: pl.DataFrame | None = None,
    detection: pl.DataFrame | None = None,
) -> str:
    """Generate a Markdown daily intelligence brief from gold tables."""
    if summary.is_empty():
        return f"# Daily Brief — {target_date.isoformat()}\n\nNo data available for this date.\n"

    row = summary.row(0, named=True)
    lines: list[str] = []

    # Header
    lines.append(f"# Daily Brief — {target_date.isoformat()}")
    lines.append(f"**Operation:** {operation_name}\n")

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

    # Top attackers (by risk score)
    if not reputation.is_empty():
        lines.append("## Top Attackers\n")
        top = reputation.sort("risk_score", descending=True).head(5)
        lines.append("| IP | Risk | Country | Events | Stage |")
        lines.append("|-----|------|---------|--------|-------|")
        for r in top.iter_rows(named=True):
            stage = ""
            if not progression.is_empty():
                ip_prog = progression.filter(pl.col("src_endpoint_ip") == r["src_endpoint_ip"])
                if ip_prog.height > 0:
                    stage = ip_prog.row(0, named=True)["stage_label"]
            lines.append(
                f"| {r['src_endpoint_ip']} | {r['risk_score']:.1f} "
                f"| {r.get('geo_country', '?')} "
                f"| {r['total_events']:,} | {stage} |"
            )
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
            for url in download_urls[:5]:
                lines.append(f"- `{url}`")
            lines.append("")
        download_hashes = row.get("top_download_hashes", [])
        if download_hashes:
            lines.append("**Top Hashes (SHA256):**")
            for h in download_hashes[:5]:
                lines.append(f"- `{h}`")
            lines.append("")

    # Top credentials
    usernames = row.get("top_usernames", [])
    passwords = row.get("top_passwords", [])
    if usernames or passwords:
        lines.append("## Top Credentials\n")
        if usernames:
            lines.append(f"**Usernames:** {', '.join(usernames[:5])}")
        if passwords:
            lines.append(f"**Passwords:** {', '.join(passwords[:5])}")
        lines.append("")

    # Top commands
    commands = row.get("top_commands", [])
    if commands:
        lines.append("## Top Commands\n")
        for cmd in commands[:5]:
            lines.append(f"- `{cmd}`")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Generated by Lantana | {target_date.isoformat()} | TLP:GREEN*")

    return "\n".join(lines) + "\n"


def generate_embed_summary(
    target_date: date,
    summary: pl.DataFrame,
    progression: pl.DataFrame,
) -> str:
    """Generate a short Discord embed summary (< 4096 chars).

    This is the embed description; the full report is attached as a file.
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

    parts.append("\nFull report attached.")
    return "\n".join(parts)

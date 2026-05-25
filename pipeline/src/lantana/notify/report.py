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
    from lantana.notify.timing import StepTiming

TOP_N: int = 10
"""Brief sections cap top-N tables at this many rows so the markdown stays
scannable. Matches the dashboard's ``_render_top_n_table`` width and the
``TOP_N`` constant in ``transform/metrics.py`` so brief and dashboard
present the same depth."""


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


def _url_tail(url: str, max_len: int = 60) -> str:
    """Shorten a download URL for the malware table.

    Keeps the right-hand tail (path + filename) because that's where the
    payload name and CVE hints live; the host is typically redundant once
    you have the IOC inventory of full URLs below. Long tails are truncated
    from the left with an ellipsis so the column stays narrow without
    losing the filename.
    """
    if not url:
        return ""
    after_scheme = url.split("://", 1)[-1]
    if len(after_scheme) <= max_len:
        return after_scheme
    return "…" + after_scheme[-max_len + 1:]


def _build_vt_hash_lookup(
    silver: pl.DataFrame | None,
) -> dict[str, dict[str, Any]]:
    """Index VT enrichment fields by SHA256 from silver for the malware table.

    The malware section wants ``family``, ``type``, ``detections``,
    ``risk_score`` and the original ``url`` next to each top-N hash. Those
    fields live in silver alongside the file_hash_sha256 row; gold's
    top_download_hashes only carries the hash itself + count. This helper
    pre-joins them once per brief generation so the table-render loop is a
    pure dict lookup.

    Returns ``{sha256: {family, type, detections, risk_score, url_tail}}``.
    Silver-absent / silver-empty / required-columns-missing all collapse to
    an empty dict (data-presence rule — the malware table then renders
    ``?`` cells for every metadata column rather than crashing).
    """
    if silver is None or silver.is_empty():
        return {}
    if "file_hash_sha256" not in silver.columns:
        return {}

    # Pick up only the columns we actually surface; tolerate any subset
    # being missing (e.g. silver from before vt_file_family was added).
    select_cols: list[str] = ["file_hash_sha256"]
    for col in ("vt_file_family", "vt_file_type", "vt_file_malicious_count",
                "vt_file_risk_score", "file_url"):
        if col in silver.columns:
            select_cols.append(col)

    rows = (
        silver.select(select_cols)
        .filter(pl.col("file_hash_sha256").is_not_null())
        .unique(subset=["file_hash_sha256"], keep="first")
    )

    lookup: dict[str, dict[str, Any]] = {}
    for r in rows.iter_rows(named=True):
        sha = r["file_hash_sha256"]
        if not isinstance(sha, str):
            continue
        lookup[sha] = {
            "family": r.get("vt_file_family"),
            "type": r.get("vt_file_type"),
            "detections": r.get("vt_file_malicious_count"),
            "risk_score": r.get("vt_file_risk_score"),
            "url_tail": _url_tail(r.get("file_url") or ""),
        }
    return lookup


def _render_ioc_inventory(silver: pl.DataFrame | None) -> list[str]:
    """Markdown ``## Full IOC Inventory`` section with collapsed details blocks.

    Per IOC type (IPs, file hashes, download URLs), render a ``<details>``
    block listing all unique non-null values for the date. Discord shows
    them collapsed by default so the brief stays scannable; the analyst
    expands a block when they want to copy IOCs into another tool.

    Source: the diagonal-concat silver DataFrame (IPs from every dataset,
    hashes/URLs from cowrie rows). Each block is gated independently —
    when the underlying column is absent or all-null, the block is
    omitted (data-presence rule). When *all* blocks would be empty, the
    section header itself is skipped.

    No rank, no count, no enrichment — that's the brief's job above. This
    section is a flat IOC dump for downstream tooling.

    Domain IOCs are intentionally out of scope (per ``enrichment/ioc.py``
    they're deferred until Suricata HTTP fields surface in bronze).
    """
    if silver is None or silver.is_empty():
        return []

    def _unique_strings(column: str) -> list[str]:
        if column not in silver.columns:
            return []
        return sorted(
            v for v in silver.get_column(column).drop_nulls().unique().to_list()
            if isinstance(v, str) and v
        )

    ips = _unique_strings("src_endpoint_ip")
    hashes = _unique_strings("file_hash_sha256")
    urls = _unique_strings("file_url")

    if not (ips or hashes or urls):
        return []

    lines: list[str] = ["## Full IOC Inventory\n"]
    lines.append(
        "_Unique IOCs observed on this date. Collapsed by default; click to "
        "expand. Rank/count/enrichment context is in the sections above._\n"
    )

    if ips:
        lines.append(f"<details><summary>Source IPs ({len(ips)})</summary>\n")
        for ip in ips:
            lines.append(f"- `{ip}`")
        lines.append("\n</details>\n")

    if hashes:
        lines.append(f"<details><summary>File Hashes — SHA256 ({len(hashes)})</summary>\n")
        for sha in hashes:
            lines.append(f"- `{sha}`")
        lines.append("\n</details>\n")

    if urls:
        lines.append(f"<details><summary>Download URLs ({len(urls)})</summary>\n")
        for url in urls:
            lines.append(f"- `{url}`")
        lines.append("\n</details>\n")

    return lines


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
    timing: list[StepTiming] | None = None,
    silver: pl.DataFrame | None = None,
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

    # Pipeline timing — sits next to health since both are ops-self-checks.
    if timing is not None:
        from lantana.notify.timing import render_timing_section
        lines.extend(render_timing_section(timing))

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

        countries = geo_row.get("top_countries", []) or []
        if countries:
            lines.append("**Top Countries:**\n")
            lines.append("| Rank | Country | Unique IPs |")
            lines.append("|------|---------|-----------|")
            for rank, entry in enumerate(countries[:TOP_N], start=1):
                parts = entry.split(":")
                lines.append(f"| {rank} | {parts[0]} | {parts[1]} |")
            lines.append("")

        asns = geo_row.get("top_asns", []) or []
        if asns:
            lines.append("**Top ASNs:**\n")
            lines.append("| Rank | ASN | ISP | Unique IPs |")
            lines.append("|------|-----|-----|-----------|")
            for rank, entry in enumerate(asns[:TOP_N], start=1):
                parts = entry.split(":")
                asn_info = parts[0] if parts else ""
                count = parts[1] if len(parts) > 1 else "0"
                asn_parts = asn_info.split("|")
                asn = asn_parts[0] if asn_parts else ""
                isp = asn_parts[1] if len(asn_parts) > 1 else ""
                lines.append(f"| {rank} | {asn} | {isp} | {count} |")
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
        top = reputation.sort("risk_score", descending=True).head(TOP_N)
        lines.append("| Rank | IP | Risk | Country | Events | Stage | A/V/S/G |")
        lines.append("|------|----|------|---------|--------|-------|---------|")
        for rank, r in enumerate(top.iter_rows(named=True), start=1):
            stage = ""
            if not progression.is_empty():
                ip_prog = progression.filter(pl.col("src_endpoint_ip") == r["src_endpoint_ip"])
                if ip_prog.height > 0:
                    stage = ip_prog.row(0, named=True)["stage_label"]
            lines.append(
                f"| {rank} | {r['src_endpoint_ip']} "
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
            lines.append("| Rank | Actor | IP | Classification |")
            lines.append("|------|-------|----|---------------|")
            for rank, r in enumerate(named.head(TOP_N).iter_rows(named=True), start=1):
                lines.append(
                    f"| {rank} | {r['greynoise_name']} "
                    f"| {r['src_endpoint_ip']} "
                    f"| {r.get('greynoise_class', '?')} |"
                )
            lines.append("")

    # Notable escalations (stage 3+)
    if not progression.is_empty():
        escalated = progression.filter(pl.col("max_stage") >= 3).head(TOP_N)
        if escalated.height > 0:
            lines.append("## Notable Escalations\n")
            lines.append("IPs that achieved authentication or interactive access:\n")
            lines.append("| Rank | IP | Stage | Auth | Commands | Automated |")
            lines.append("|------|----|-------|------|----------|-----------|")
            for rank, r in enumerate(escalated.iter_rows(named=True), start=1):
                auto = "yes" if r["is_automated"] else "no"
                lines.append(
                    f"| {rank} | {r['src_endpoint_ip']} "
                    f"| {r['stage_label']} "
                    f"| {r['auth_successes']}/{r['auth_attempts']} "
                    f"| {r['commands_executed']} | {auto} |"
                )
            lines.append("")

    # Campaign clusters
    if not clusters.is_empty():
        lines.append("## Campaign Clusters\n")
        lines.append("Credential pairs used by multiple IPs (likely botnets):\n")
        lines.append("| Rank | Credentials | IP Count | IPs |")
        lines.append("|------|-------------|----------|-----|")
        for rank, r in enumerate(clusters.head(TOP_N).iter_rows(named=True), start=1):
            ips = r["ips"]
            ip_str = ", ".join(ips) if isinstance(ips, list) else str(ips)
            lines.append(
                f"| {rank} "
                f"| `{r['shared_username']}:{r['shared_password']}` "
                f"| {r['ip_count']} | {ip_str} |"
            )
        lines.append("")

    # Detection highlights
    if detection is not None and not detection.is_empty():
        lines.append("## Detection Highlights\n")
        lines.append("Top Suricata rules triggered:\n")
        lines.append("| Rank | Rule | Events | Unique IPs |")
        lines.append("|------|------|--------|-----------|")
        for rank, r in enumerate(detection.head(TOP_N).iter_rows(named=True), start=1):
            title = r.get("finding_title", "unknown")
            lines.append(
                f"| {rank} | {title} | {r['event_count']:,} | {r['unique_ips']:,} |"
            )
        lines.append("")

    # Malware captured — top-10 hashes with VT enrichment context
    downloads = row.get("downloads_captured", 0)
    if downloads and downloads > 0:
        lines.append("## Malware Captured\n")
        lines.append(f"**{downloads}** file(s) downloaded by attackers\n")
        download_hashes = row.get("top_download_hashes", []) or []
        if download_hashes:
            vt_lookup = _build_vt_hash_lookup(silver)
            lines.append("**Top Hashes (SHA256) with VirusTotal context:**\n")
            lines.append(
                "| Rank | SHA256 | Family | Type | VT Detections | VT Risk | URL | Count |"
            )
            lines.append(
                "|------|--------|--------|------|---------------|---------|-----|-------|"
            )
            for rank, entry in enumerate(download_hashes[:TOP_N], start=1):
                sha = str(entry["value"])
                count = int(entry["count"])
                meta = vt_lookup.get(sha, {})
                family = meta.get("family") or "?"
                ftype = meta.get("type") or "?"
                detections = meta.get("detections")
                detections_cell = "?" if detections is None else f"{detections}"
                vt_risk = meta.get("risk_score")
                vt_risk_cell = "?" if vt_risk is None else f"{vt_risk:.0f}"
                url_path = meta.get("url_tail") or "?"
                short_sha = f"`{sha[:16]}…`"
                lines.append(
                    f"| {rank} | {short_sha} | {family} | {ftype} "
                    f"| {detections_cell} | {vt_risk_cell} | `{url_path}` | {count:,} |"
                )
            lines.append("")
            lines.append(
                "_VT Detections = number of AV engines flagging the file. "
                "VT Risk = bucketed 0..100 score from `compute_file_risk_score`. "
                "Family from VT's popular_threat_name (fallback: suggested_threat_label). "
                "Full SHA256s appear in the IOC inventory below._"
            )
            lines.append("")

        # Top download URLs — kept as a separate top-N table for cases where
        # the same payload is fetched from many URLs.
        download_urls = row.get("top_download_urls", []) or []
        if download_urls:
            lines.append("**Top Download URLs:**\n")
            lines.append("| Rank | URL | Count |")
            lines.append("|------|-----|-------|")
            for rank, entry in enumerate(download_urls[:TOP_N], start=1):
                lines.append(f"| {rank} | `{entry['value']}` | {entry['count']:,} |")
            lines.append("")

    # Top credentials — split into two rank/item/count tables (matches dashboard).
    usernames = row.get("top_usernames", []) or []
    passwords = row.get("top_passwords", []) or []
    if usernames or passwords:
        lines.append("## Top Credentials\n")
        if usernames:
            lines.append("**Top Usernames:**\n")
            lines.append("| Rank | Username | Count |")
            lines.append("|------|----------|-------|")
            for rank, entry in enumerate(usernames[:TOP_N], start=1):
                lines.append(f"| {rank} | `{entry['value']}` | {entry['count']:,} |")
            lines.append("")
        if passwords:
            lines.append("**Top Passwords:**\n")
            lines.append("| Rank | Password | Count |")
            lines.append("|------|----------|-------|")
            for rank, entry in enumerate(passwords[:TOP_N], start=1):
                lines.append(f"| {rank} | `{entry['value']}` | {entry['count']:,} |")
            lines.append("")

    # Top commands
    commands = row.get("top_commands", []) or []
    if commands:
        lines.append("## Top Commands\n")
        lines.append("| Rank | Command | Count |")
        lines.append("|------|---------|-------|")
        for rank, entry in enumerate(commands[:TOP_N], start=1):
            lines.append(f"| {rank} | `{entry['value']}` | {entry['count']:,} |")
        lines.append("")

    # Full IOC inventory — collapsed lists of unique IPs / hashes / URLs.
    # Comes last so the brief's narrative flow stays on top; analysts
    # expand the blocks only when they want a raw IOC dump.
    if silver is not None:
        lines.extend(_render_ioc_inventory(silver))

    # Footer
    lines.append("---")
    lines.append(f"*Generated by Lantana | {target_date.isoformat()} | TLP:GREEN*")

    return "\n".join(lines) + "\n"


def generate_embed_summary(
    target_date: date,
    summary: pl.DataFrame,
    progression: pl.DataFrame,
    buckets: ErrorBuckets | None = None,
    timing: list[StepTiming] | None = None,
) -> str:
    """Generate a short Discord embed summary (< 4096 chars).

    This is the embed description; the full report is attached as a file.
    When ``buckets`` is provided, a 1-line health summary is appended so the
    operator sees pipeline status without opening the attachment. When
    ``timing`` is provided, a 1-line per-step duration summary is appended
    too.
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

    if timing is not None:
        from lantana.notify.timing import render_timing_one_liner
        timing_line = render_timing_one_liner(timing)
        if timing_line is not None:
            parts.append(timing_line)

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

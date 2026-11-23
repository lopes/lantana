"""Air-gapped stdlib ``ThreadingHTTPServer`` Vigil dashboard — Lantana Intelligence Console.

Binds strictly to ``127.0.0.1:8501`` (OPSEC Layer 3: access only over an SSH
local port-forward ``ssh -L 8501:localhost:8501``). Zero external network
requests — serves ``/static/vigil.css`` from package data and
``/static/plotly.min.js`` directly from ``plotly.offline.get_plotlyjs()``.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import date
from functools import lru_cache
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse

import plotly.offline
import polars as pl

from lantana.common.config import (
    OperationConfig,
    OperatorConfig,
    RedactConfig,
    ReportingConfig,
    SharingConfig,
    load_reporting,
)
from lantana.common.datalake import GOLD_ROOT, SILVER_ROOT, read_gold_range
from lantana.dashboard.charts import (
    activity_trend_chart,
    auth_donut_chart,
    events_by_type_stacked_bar,
    ioc_breakdown_chart,
    pareto_concentration_chart,
    risk_histogram_chart,
    stage_scatter_chart,
    stix_composition_chart,
    top_countries_bar_chart,
    top_rules_bar_chart,
    velocity_histogram_chart,
    world_map_chart,
)
from lantana.dashboard.health import (
    collect_health_snapshot,
    format_bytes,
)
from lantana.dashboard.html import (
    KpiCard,
    TableColumn,
    esc,
    render_chart_card,
    render_interactive_table,
    render_kpis,
    render_page,
    render_section_heading,
    render_simple_table,
    window_query_string,
)
from lantana.dashboard.queries import (
    VALID_WINDOW_MODES,
    DateWindow,
    _merge_credential_pairs,
    _merge_top_n_structs,
    aggregate_behavioral_progression,
    aggregate_campaign_clusters,
    aggregate_detection_findings,
    aggregate_extracted_iocs,
    aggregate_ip_reputation,
    build_window_raw_ioc_csv_gz,
    build_window_stix_bundle,
    count_stix_composition,
    discover_available_dates,
    load_overview,
    resolve_window,
    risk_level_label,
)
from lantana.dashboard.theme import VIGIL_LIGHT
from lantana.intel.stix import RISK_HIGH_THRESHOLD, RISK_THRESHOLD

if TYPE_CHECKING:
    from typing import Any

_CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'none'; "
    "font-src 'self'"
)


@lru_cache(maxsize=1)
def _load_vigil_css_bytes() -> bytes:
    css_file = resources.files("lantana.dashboard.static").joinpath("vigil.css")
    return css_file.read_bytes()


@lru_cache(maxsize=1)
def _load_plotly_js_bytes() -> bytes:
    return plotly.offline.get_plotlyjs().encode("utf-8")


def _load_reporting_checked(reporting_path: Path | None = None) -> tuple[ReportingConfig, bool]:
    """Load reporting config and report whether real OPSEC redaction rules loaded.

    Returns ``(config, True)`` when ``reporting.json`` parsed cleanly and
    ``(fallback_config, False)`` when missing/unreadable/corrupt. Display-only
    views may render with the fallback title, while export endpoints
    (``/stix``, ``/download/stix``) MUST fail closed whenever ``loaded`` is
    ``False`` so STIX bundles are never emitted without OPSEC leak rules.
    """
    try:
        cfg = load_reporting(reporting_path) if reporting_path is not None else load_reporting()
    except (FileNotFoundError, PermissionError, ValueError):
        return (
            ReportingConfig(
                operator=OperatorConfig(
                    name="Lantana Operator",
                    handle="lantana",
                    contact="",
                    pgp_fingerprint="",
                ),
                sharing=SharingConfig(tlp="GREEN", community="", discord_channel=""),
                operation=OperationConfig(
                    name="Lantana",
                    description="",
                    sector="",
                    region="",
                    start_date="",
                ),
                redact=RedactConfig(),
            ),
            False,
        )
    return cfg, True


def _fmt_float(value: object, digits: int = 1) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{float(value):.{digits}f}"
    return "—"


def _fmt_ts(value: object) -> str:
    if value is None:
        return "—"
    return str(value)[:19].replace("T", " ")


def _render_overview_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    bundle = load_overview(window.dates, gold_root=gold_root)
    if bundle is None:
        return render_page(
            title="Overview",
            subtitle="Honeypot telemetry pulse across all OCSF classes and sensors.",
            active_route="/overview",
            window=window,
            toc_items=(),
            body_html='<div class="callout">No Gold data available for the selected window.</div>',
            operation_name=op_name,
        )

    auth_rate = (
        f"{100.0 * bundle.auth_successes / bundle.auth_attempts:.1f}% accepted"
        if bundle.auth_attempts > 0
        else "0.0% accepted"
    )
    kpis = [
        KpiCard(
            "Connections / Events",
            f"{bundle.total_events:,}",
            tone="info",
            metric_key="Total Events",
        ),
        KpiCard(
            "Unique External IPs",
            f"{bundle.unique_ips:,}",
            tone="info",
            metric_key="Unique IPs",
        ),
        KpiCard(
            "Auth Attempts",
            f"{bundle.auth_attempts:,}",
            sub=auth_rate,
            metric_key="Auth Attempts",
        ),
        KpiCard(
            "Commands Executed",
            f"{bundle.commands_executed:,}",
            tone="med" if bundle.commands_executed > 0 else "",
            metric_key="Commands",
        ),
        KpiCard(
            "Malware Uploaded",
            f"{bundle.downloads_captured:,}",
            sub=f"{bundle.unique_malware_hashes:,} unique SHA-256",
            tone="high" if bundle.unique_malware_hashes > 0 else "",
            metric_key="Malware Uploaded",
        ),
        KpiCard(
            "Outbound C2 & Stagers",
            f"{bundle.outbound_c2_and_urls:,}",
            tone="high" if bundle.outbound_c2_and_urls > 0 else "",
            metric_key="Outbound C2 & Stagers",
        ),
        KpiCard(
            "Real IDS Findings",
            f"{bundle.findings_detected:,}",
            tone="med" if bundle.findings_detected > 0 else "",
            metric_key="Findings",
        ),
    ]

    sections: list[str] = [
        render_section_heading("pulse", "Telemetry Pulse", help_key="Key Metrics"),
        render_kpis(kpis),
    ]
    toc: list[tuple[str, str]] = [("pulse", "Telemetry Pulse")]

    if bundle.daily_trend.height > 1:
        toc.append(("trend", "Multi-Day Activity Trend"))
        sections.append(render_section_heading("trend", "Multi-Day Activity Trend"))
        sections.append(
            render_chart_card(
                "overview-trend",
                "Daily Events & Unique Attacker IPs",
                activity_trend_chart(bundle.daily_trend),
            )
        )

    toc.append(("mix", "Authentication & Event Mix"))
    sections.append(render_section_heading("mix", "Authentication & Event Mix"))
    auth_fig = auth_donut_chart(bundle.auth_successes, bundle.auth_failures)
    type_fig = events_by_type_stacked_bar(
        {
            "Auth": bundle.auth_attempts,
            "Commands": bundle.commands_executed,
            "Findings": bundle.findings_detected,
            "Network": bundle.network_events,
            "Downloads": bundle.downloads_captured,
        }
    )
    sections.append(
        '<div class="chart-grid">'
        + render_chart_card("overview-auth", "Authentication Outcome", auth_fig)
        + render_chart_card("overview-types", "Events by OCSF Class", type_fig)
        + "</div>"
    )

    toc.append(("highlights", "Activity Highlights"))
    sections.append(
        render_section_heading("highlights", "Activity Highlights", help_key="Top Commands")
    )
    cmd_tbl = render_simple_table(
        ["Rank", "Command", "Count"],
        [[r["rank"], r["value"], f"{int(str(r['count'])):,}"] for r in bundle.top_commands[:10]],
        numeric_cols={0, 2},
        mono_cols={1},
    )
    top_findings = aggregate_detection_findings(window.dates, gold_root=gold_root).head(10)
    finding_rows = [
        [
            idx,
            str(r.get("finding_uid") or "—"),
            str(r.get("finding_title") or ""),
            f"{int(r.get('event_count') or 0):,}",
        ]
        for idx, r in enumerate(top_findings.iter_rows(named=True), start=1)
    ]
    findings_tbl = render_simple_table(
        ["Rank", "SID", "Top Suricata Signatures", "Events"],
        finding_rows,
        numeric_cols={0, 3},
        mono_cols={1},
    )
    qs = window_query_string(window)
    sections.append(
        '<div class="chart-grid">'
        f"<div><h3>Top Post-Auth Commands</h3>{cmd_tbl}</div>"
        f"<div><h3>Top IDS Signatures</h3>{findings_tbl}</div>"
        "</div>"
        '<p class="table-meta">Drill into '
        f'<a href="/attackers?{qs}">Attackers (Risk &amp; Geo)</a> · '
        f'<a href="/behavior?{qs}">Behavior (Progression, Creds &amp; Findings)</a> · '
        f'<a href="/intel?{qs}">Intel &amp; STIX Export</a>.</p>'
    )

    return render_page(
        title="Overview",
        subtitle=(
            "Connections, authentication pressure, uploaded malware, outbound C2s, and IDS alerts."
        ),
        active_route="/overview",
        window=window,
        toc_items=toc,
        body_html="".join(sections),
        operation_name=op_name,
    )


def _render_attackers_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    df = aggregate_ip_reputation(window.dates, gold_root=gold_root)
    if df.is_empty():
        return render_page(
            title="Attackers",
            subtitle=(
                "Monotonic behavioral-anchored risk scores, geographic origins, and hosting ASNs."
            ),
            active_route="/attackers",
            window=window,
            toc_items=(),
            body_html='<div class="callout">No IP reputation data available for this window.</div>',
            operation_name=op_name,
        )

    high = df.filter(pl.col("risk_score") >= RISK_HIGH_THRESHOLD).height
    med = df.filter(
        (pl.col("risk_score") >= RISK_THRESHOLD) & (pl.col("risk_score") < RISK_HIGH_THRESHOLD)
    ).height
    low = df.filter(pl.col("risk_score") < RISK_THRESHOLD).height

    kpis = [
        KpiCard("Total Scored IPs", f"{df.height:,}", tone="info", metric_key="Total Scored IPs"),
        KpiCard(
            f"High Risk (>= {int(RISK_HIGH_THRESHOLD)})",
            f"{high:,}",
            tone="high",
            metric_key="High Risk IPs",
        ),
        KpiCard(
            f"Medium Risk ({int(RISK_THRESHOLD)}-{int(RISK_HIGH_THRESHOLD)})",
            f"{med:,}",
            tone="med",
            metric_key="Medium Risk IPs",
        ),
        KpiCard(
            f"Low Risk (< {int(RISK_THRESHOLD)})",
            f"{low:,}",
            tone="low",
            metric_key="Low Risk IPs",
        ),
    ]

    comp_vals = [float(v) for v in df.get_column("risk_score").drop_nulls().to_list()]
    behav_vals = (
        [float(v) for v in df.get_column("behavioral_risk_score").drop_nulls().to_list()]
        if "behavioral_risk_score" in df.columns
        else []
    )
    enrich_vals = (
        [float(v) for v in df.get_column("enrichment_risk_score").drop_nulls().to_list()]
        if "enrichment_risk_score" in df.columns
        else []
    )

    hist_grid = (
        '<div class="chart-grid cols-3">'
        + render_chart_card(
            "risk-hist-comp",
            "Composite Risk Score",
            risk_histogram_chart(comp_vals, "risk_score", VIGIL_LIGHT["important"]),
        )
        + render_chart_card(
            "risk-hist-behav",
            "Behavioral Anchor",
            risk_histogram_chart(behav_vals, "behavioral_risk_score", VIGIL_LIGHT["caution"]),
        )
        + render_chart_card(
            "risk-hist-enrich",
            "Enrichment Mean",
            risk_histogram_chart(enrich_vals, "enrichment_risk_score", VIGIL_LIGHT["accent"]),
        )
        + "</div>"
    )

    countries_df = (
        df.filter(pl.col("geo_country").is_not_null())
        .group_by("geo_country")
        .agg(
            pl.col("src_endpoint_ip").n_unique().alias("Unique IPs"),
            pl.col("total_events").sum().alias("Total Events"),
        )
        .sort(["Unique IPs", "Total Events"], descending=[True, True])
        .head(15)
        .rename({"geo_country": "Country"})
        if "geo_country" in df.columns
        else pl.DataFrame()
    )
    cities_df = (
        df.filter(pl.col("geo_city").is_not_null() & pl.col("geo_country").is_not_null())
        .group_by(["geo_city", "geo_country"])
        .agg(pl.col("src_endpoint_ip").n_unique().alias("Unique IPs"))
        .sort("Unique IPs", descending=True)
        .head(15)
        if {"geo_city", "geo_country"} <= set(df.columns)
        else pl.DataFrame()
    )
    asns_df = (
        df.filter(pl.col("geo_asn").is_not_null())
        .with_columns(
            pl.col("geo_isp").fill_null("Unknown")
            if "geo_isp" in df.columns
            else pl.lit("Unknown").alias("geo_isp")
        )
        .group_by(["geo_asn", "geo_isp"])
        .agg(
            pl.col("src_endpoint_ip").n_unique().alias("Unique IPs"),
            pl.col("total_events").sum().alias("Events"),
        )
        .sort(["Unique IPs", "Events"], descending=[True, True])
        .head(15)
        if "geo_asn" in df.columns
        else pl.DataFrame()
    )

    has_coords = {"geo_latitude", "geo_longitude"} <= set(df.columns) and not df.filter(
        pl.col("geo_latitude").is_not_null() & pl.col("geo_longitude").is_not_null()
    ).is_empty()
    has_geo_any = has_coords or not countries_df.is_empty() or not asns_df.is_empty()
    qs = window_query_string(window)
    if not has_geo_any:
        geo_section = (
            '<div class="callout callout-warning">'
            '<div class="callout-title">MaxMind GeoLite2 Not Populated</div>'
            "No GeoLite2 coordinates, countries, or ASNs were recorded for this window. "
            "Configure <code>vault_apikey_maxmind</code> (GeoLite2-City &amp; GeoLite2-ASN MMDBs) "
            f'to enable geographic origin views — see <a href="/health?{qs}">System Health</a> '
            "for integration status."
            "</div>"
        )
    else:
        country_rows = [
            [idx, r["Country"], f"{int(r['Unique IPs']):,}", f"{int(r['Total Events']):,}"]
            for idx, r in enumerate(countries_df.iter_rows(named=True), start=1)
        ]
        city_rows = [
            [idx, r["geo_city"], r["geo_country"], f"{int(r['Unique IPs']):,}"]
            for idx, r in enumerate(cities_df.iter_rows(named=True), start=1)
        ]
        asn_rows = [
            [
                idx,
                f"AS{r['geo_asn']}",
                r["geo_isp"],
                f"{int(r['Unique IPs']):,}",
                f"{int(r['Events']):,}",
            ]
            for idx, r in enumerate(asns_df.iter_rows(named=True), start=1)
        ]
        map_block = (
            render_chart_card(
                "world-map",
                "Attacker Origins (Size = log10 Events, Color = Risk)",
                world_map_chart(df),
            )
            if has_coords
            else ""
        )
        countries_chart_block = (
            render_chart_card(
                "top-countries-bar",
                "Unique Attacker IPs by Country",
                top_countries_bar_chart(countries_df),
            )
            if not countries_df.is_empty()
            else ""
        )
        countries_tbl = render_simple_table(
            ["Rank", "Country", "Unique IPs", "Total Events"],
            country_rows,
            numeric_cols={0, 2, 3},
        )
        cities_tbl = render_simple_table(
            ["Rank", "City", "Country", "Unique IPs"],
            city_rows,
            numeric_cols={0, 3},
        )
        asns_tbl = render_simple_table(
            ["Rank", "ASN", "ISP", "Unique IPs", "Events"],
            asn_rows,
            numeric_cols={0, 3, 4},
            mono_cols={1},
        )
        geo_section = (
            map_block
            + countries_chart_block
            + '<div class="chart-grid">'
            + f"<div><h3>Top Countries</h3>{countries_tbl}</div>"
            + f"<div><h3>Top Cities</h3>{cities_tbl}</div>"
            + "</div>"
            + f"<h3>Top Hosting ASNs / ISPs</h3>{asns_tbl}"
        )

    rows: list[dict[str, object]] = []
    for row in df.iter_rows(named=True):
        score = float(row.get("risk_score") or 0.0)
        rows.append(
            {
                "src_endpoint_ip": str(row.get("src_endpoint_ip") or ""),
                "risk_score": round(score, 1),
                "risk_level": risk_level_label(score),
                "behavioral_risk_score": (
                    round(float(row["behavioral_risk_score"]), 1)
                    if row.get("behavioral_risk_score") is not None
                    else None
                ),
                "enrichment_risk_score": (
                    round(float(row["enrichment_risk_score"]), 1)
                    if row.get("enrichment_risk_score") is not None
                    else None
                ),
                "total_events": int(row.get("total_events") or 0),
                "geo_country": str(row.get("geo_country") or "—"),
                "geo_asn": f"AS{row['geo_asn']}" if row.get("geo_asn") is not None else "—",
                "auth_attempts": int(row.get("auth_attempts") or 0),
                "commands_executed": int(row.get("commands_executed") or 0),
                "findings_triggered": int(row.get("findings_triggered") or 0),
                "greynoise_class": str(row.get("greynoise_class") or "—"),
                "greynoise_name": str(row.get("greynoise_name") or "—"),
                "shodan_org": str(row.get("shodan_org") or "—"),
            }
        )

    columns = [
        TableColumn("src_endpoint_ip", "Source IP", mono=True),
        TableColumn("risk_score", "Risk", numeric=True),
        TableColumn("risk_level", "Level", badge=True),
        TableColumn("behavioral_risk_score", "Behav.", numeric=True),
        TableColumn("enrichment_risk_score", "Enrich.", numeric=True),
        TableColumn("total_events", "Events", numeric=True),
        TableColumn("geo_country", "CC"),
        TableColumn("geo_asn", "ASN", mono=True),
        TableColumn("auth_attempts", "Auth", numeric=True),
        TableColumn("commands_executed", "Cmds", numeric=True),
        TableColumn("findings_triggered", "IDS", numeric=True),
        TableColumn("greynoise_class", "GN Class", badge=True),
        TableColumn("greynoise_name", "GN Actor"),
        TableColumn("shodan_org", "Org"),
    ]

    formula_callout = (
        '<div class="callout">'
        '<div class="callout-title">Monotonic Risk Formula (v1.5)</div>'
        "Pure scanners (<code>behavioral == 0</code>) are capped at "
        "<code>enrichment &times; 0.35 &le; 35.0</code> and excluded from STIX. "
        "Interactive attackers (<code>behavioral &gt; 0</code>) score "
        "<code>max(behavioral, 0.5&middot;behavioral + 0.5&middot;enrichment)</code>, "
        "with GreyNoise RIOT/benign applying a <code>0.5&times;</code> FP brake. "
        "HTTP 404 lookups emit <code>null</code> (never diluting the enrichment mean)."
        "</div>"
    )

    toc = [
        ("ip-buckets", "Risk Buckets"),
        ("ip-dist", "Score Decomposition"),
        ("geo-origins", "Geographic Origins & ASNs"),
        ("ip-table-sec", "Scored IP Details"),
    ]
    body = (
        render_section_heading("ip-buckets", "Risk Buckets", help_key="Top Attackers")
        + render_kpis(kpis)
        + formula_callout
        + render_section_heading(
            "ip-dist", "Risk Score Distribution", help_key="Risk Score Distribution"
        )
        + hist_grid
        + render_section_heading(
            "geo-origins", "Geographic Origins & Hosting ASNs", help_key="World Map"
        )
        + geo_section
        + render_section_heading("ip-table-sec", "Scored IP Details")
        + render_interactive_table(
            "ips-table",
            columns,
            rows,
            page_size=25,
            search_placeholder="Search IP, country, ASN, GreyNoise, org...",
            min_risk_filter=True,
        )
    )
    return render_page(
        title="Attackers",
        subtitle=(
            "Composite risk scores, behavioral vs enrichment decomposition, "
            "geographic origins, and hosting ASNs."
        ),
        active_route="/attackers",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=op_name,
    )


def _render_behavior_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    prog_df, multiday = aggregate_behavioral_progression(window.dates, gold_root=gold_root)
    summary_df = read_gold_range("daily_summary", window.dates, gold_root=gold_root)
    clusters_df = aggregate_campaign_clusters(window.dates, gold_root=gold_root)
    findings_df = aggregate_detection_findings(window.dates, gold_root=gold_root)

    if (
        prog_df.is_empty()
        and summary_df.is_empty()
        and clusters_df.is_empty()
        and findings_df.is_empty()
    ):
        return render_page(
            title="Behavior & TTPs",
            subtitle=(
                "Escalation depth, credential campaigns, post-auth commands, "
                "and Suricata IDS detections."
            ),
            active_route="/behavior",
            window=window,
            toc_items=(),
            body_html=(
                '<div class="callout">No behavioral or IDS data available for this window.</div>'
            ),
            operation_name=op_name,
        )

    toc: list[tuple[str, str]] = []
    sections: list[str] = []

    toc.append(("prog-funnel", "Escalation Funnel"))
    if prog_df.is_empty():
        sections.append(
            render_section_heading("prog-funnel", "Escalation Funnel", help_key="Escalation Funnel")
            + '<div class="callout">No progression data available for this window.</div>'
        )
    else:
        funnel_kpis = [
            KpiCard(
                label,
                f"{prog_df.filter(pl.col('max_stage') >= stage).height:,}",
                tone=tone,
                metric_key=mkey,
            )
            for stage, label, tone, mkey in (
                (1, "Stage 1 · Scan", "info", "Stage Scan"),
                (2, "Stage 2 · Credential", "", "Stage Credential"),
                (3, "Stage 3 · Authenticated", "med", "Stage Authenticated"),
                (4, "Stage 4 · Interactive", "high", "Stage Interactive"),
            )
        ]
        auto_count = prog_df.filter(pl.col("is_automated").fill_null(False)).height
        manual_count = prog_df.height - auto_count
        auto_kpis = [
            KpiCard("Automated Bots", f"{auto_count:,}", tone="med", metric_key="Automated Bots"),
            KpiCard(
                "Manual / Unknown", f"{manual_count:,}", tone="info", metric_key="Manual or Unknown"
            ),
        ]
        prog_rows: list[dict[str, object]] = [
            {
                "src_endpoint_ip": str(row.get("src_endpoint_ip") or ""),
                "max_stage": int(row.get("max_stage") or 1),
                "stage_label": str(row.get("stage_label") or ""),
                "is_automated": "Automated" if row.get("is_automated") else "Manual",
                "scan_events": int(row.get("scan_events") or 0),
                "auth_attempts": int(row.get("auth_attempts") or 0),
                "auth_successes": int(row.get("auth_successes") or 0),
                "commands_executed": int(row.get("commands_executed") or 0),
                "seconds_to_auth": _fmt_float(row.get("seconds_to_auth")),
                "seconds_to_command": _fmt_float(row.get("seconds_to_command")),
                "first_seen": _fmt_ts(row.get("first_seen")),
            }
            for row in prog_df.iter_rows(named=True)
        ]
        prog_cols = [
            TableColumn("src_endpoint_ip", "Source IP", mono=True),
            TableColumn("max_stage", "Stage", numeric=True),
            TableColumn("stage_label", "Label", badge=True),
            TableColumn("is_automated", "Behavior"),
            TableColumn("scan_events", "Scan", numeric=True),
            TableColumn("auth_attempts", "Auth", numeric=True),
            TableColumn("auth_successes", "OK", numeric=True),
            TableColumn("commands_executed", "Cmds", numeric=True),
            TableColumn("seconds_to_auth", "s→Auth", numeric=True),
            TableColumn("seconds_to_command", "s→Cmd", numeric=True),
            TableColumn("first_seen", "First Seen (UTC)", mono=True),
        ]
        multi_html = ""
        if not multiday.is_empty():
            toc.append(("prog-multiday", "Multi-Day Persistence"))
            multi_ips = multiday.filter(pl.col("is_multi_day"))
            vel_vals = [
                int(v)
                for v in multiday.filter(pl.col("progression_velocity_days") > 0)
                .get_column("progression_velocity_days")
                .to_list()
            ]
            md_rows = [
                {
                    "src_endpoint_ip": str(r["src_endpoint_ip"]),
                    "max_stage": int(r["max_stage"]),
                    "stage_label": str(r["stage_label"]),
                    "active_days": int(r["active_days"]),
                    "progression_velocity_days": int(r["progression_velocity_days"]),
                    "first_seen_date": str(r["first_seen_date"]),
                    "last_seen_date": str(r["last_seen_date"]),
                }
                for r in multi_ips.iter_rows(named=True)
            ]
            md_cols = [
                TableColumn("src_endpoint_ip", "Source IP", mono=True),
                TableColumn("max_stage", "Stage", numeric=True),
                TableColumn("stage_label", "Label", badge=True),
                TableColumn("active_days", "Active Days", numeric=True),
                TableColumn("progression_velocity_days", "Velocity (d)", numeric=True),
                TableColumn("first_seen_date", "First Date", mono=True),
                TableColumn("last_seen_date", "Last Date", mono=True),
            ]
            vel_chart = (
                render_chart_card(
                    "velocity-hist",
                    "Progression Velocity (Days to Max Stage)",
                    velocity_histogram_chart(vel_vals),
                    help_key="Progression Velocity",
                )
                if vel_vals
                else ""
            )
            multi_html = (
                render_section_heading(
                    "prog-multiday", "Multi-Day Persistence", help_key="Multi-Day Progression"
                )
                + render_kpis(
                    [
                        KpiCard(
                            "Multi-Day IPs",
                            f"{multi_ips.height:,}",
                            tone="high" if multi_ips.height > 0 else "",
                            metric_key="Multi-Day IPs",
                        ),
                        KpiCard(
                            "Total IPs in Lookback",
                            f"{multiday.height:,}",
                            tone="info",
                            metric_key="Total Multi-Day IPs",
                        ),
                    ]
                )
                + vel_chart
                + render_interactive_table(
                    "multiday-table",
                    md_cols,
                    md_rows,
                    page_size=25,
                    search_placeholder="Search returning attacker IP...",
                    empty_message="No multi-day repeat attackers in this lookback window.",
                )
            )
        sections.append(
            render_section_heading("prog-funnel", "Escalation Funnel", help_key="Escalation Funnel")
            + render_kpis(funnel_kpis)
            + render_kpis(auto_kpis)
            + render_chart_card(
                "stage-scatter",
                "Max Stage vs First Seen (UTC)",
                stage_scatter_chart(prog_df),
                help_key="Stage vs Time",
            )
            + "<h3>IP Progression Details</h3>"
            + render_interactive_table(
                "prog-table",
                prog_cols,
                prog_rows,
                page_size=25,
                search_placeholder="Search IP or stage...",
                min_stage_filter=True,
            )
            + multi_html
        )

    toc.append(("cred-lists", "Credentials & Campaigns"))
    users = _merge_top_n_structs(summary_df, "top_usernames", limit=15)
    passwords = _merge_top_n_structs(summary_df, "top_passwords", limit=15)
    pairs = _merge_credential_pairs(summary_df, limit=15)
    commands = _merge_top_n_structs(summary_df, "top_commands", limit=15)
    users_tbl = render_simple_table(
        ["Rank", "Username", "Count"],
        [[r["rank"], r["value"], f"{int(str(r['count'])):,}"] for r in users],
        numeric_cols={0, 2},
        mono_cols={1},
    )
    passwords_tbl = render_simple_table(
        ["Rank", "Password", "Count"],
        [[r["rank"], r["value"], f"{int(str(r['count'])):,}"] for r in passwords],
        numeric_cols={0, 2},
        mono_cols={1},
    )
    pairs_tbl = render_simple_table(
        ["Rank", "Username", "Password", "Count"],
        [[r["rank"], r["username"], r["password"], f"{int(str(r['count'])):,}"] for r in pairs],
        numeric_cols={0, 3},
        mono_cols={1, 2},
    )
    commands_tbl = render_simple_table(
        ["Rank", "Post-Auth Command", "Count"],
        [[r["rank"], r["value"], f"{int(str(r['count'])):,}"] for r in commands],
        numeric_cols={0, 2},
        mono_cols={1},
    )
    cluster_rows: list[dict[str, object]] = []
    for row in clusters_df.iter_rows(named=True):
        ips = row.get("ips") or []
        ip_str = ", ".join(str(x) for x in ips) if isinstance(ips, list) else str(ips)
        cluster_rows.append(
            {
                "shared_username": str(row.get("shared_username") or ""),
                "shared_password": str(row.get("shared_password") or ""),
                "ip_count": int(row.get("ip_count") or 0),
                "total_events": int(row.get("total_events") or 0),
                "ips": ip_str,
                "first_seen": _fmt_ts(row.get("first_seen")),
                "last_seen": _fmt_ts(row.get("last_seen")),
            }
        )
    cluster_cols = [
        TableColumn("shared_username", "Username", mono=True),
        TableColumn("shared_password", "Password", mono=True),
        TableColumn("ip_count", "Unique IPs", numeric=True),
        TableColumn("total_events", "Events", numeric=True),
        TableColumn("ips", "Source IPs", mono=True),
        TableColumn("first_seen", "First Seen (UTC)", mono=True),
        TableColumn("last_seen", "Last Seen (UTC)", mono=True),
    ]
    sections.append(
        render_section_heading(
            "cred-lists", "Credentials, Campaigns & Commands", help_key="Top Credentials"
        )
        + '<div class="chart-grid cols-3">'
        + f"<div><h3>Top Usernames</h3>{users_tbl}</div>"
        + f"<div><h3>Top Passwords</h3>{passwords_tbl}</div>"
        + f"<div><h3>Top Pairs</h3>{pairs_tbl}</div>"
        + "</div>"
        + f"<h3>Top Post-Auth Commands</h3>{commands_tbl}"
        + render_section_heading(
            "cred-clusters", "Shared-Credential Campaigns", help_key="Campaign Clusters"
        )
        + render_kpis(
            [
                KpiCard(
                    "Active Clusters",
                    f"{clusters_df.height:,}",
                    tone="med" if clusters_df.height > 0 else "",
                    metric_key="Active Clusters",
                )
            ]
        )
        + render_interactive_table(
            "clusters-table",
            cluster_cols,
            cluster_rows,
            page_size=25,
            search_placeholder="Search username, password, IP...",
        )
    )

    toc.append(("find-summary", "Suricata Detections"))
    if findings_df.is_empty():
        sections.append(
            render_section_heading(
                "find-summary", "Suricata Detections", help_key="Detection Highlights"
            )
            + '<div class="callout">No IDS detection findings for this window.</div>'
        )
    else:
        ip_col_label = "IP-days" if window.is_multi_day else "Unique IPs"
        total_events = int(findings_df.get_column("event_count").sum())
        total_ip_breadth = int(findings_df.get_column("unique_ips").sum())
        find_kpis = [
            KpiCard(
                "Distinct Rules", f"{findings_df.height:,}", tone="info", metric_key="Total Rules"
            ),
            KpiCard(
                "Total Alert Events",
                f"{total_events:,}",
                tone="med",
                metric_key="Total Detection Events",
            ),
            KpiCard(
                f"Rule {ip_col_label} Sum",
                f"{total_ip_breadth:,}",
                metric_key="Total Detection IPs",
            ),
        ]
        find_rows: list[dict[str, object]] = [
            {
                "finding_uid": str(row.get("finding_uid") or "—"),
                "finding_title": str(row.get("finding_title") or ""),
                "event_count": int(row.get("event_count") or 0),
                "unique_ips": int(row.get("unique_ips") or 0),
                "severity_id": int(row.get("severity_id") or 0),
                "category": str(row.get("category") or "—"),
                "first_seen": _fmt_ts(row.get("first_seen")),
                "last_seen": _fmt_ts(row.get("last_seen")),
            }
            for row in findings_df.iter_rows(named=True)
        ]
        find_cols = [
            TableColumn("finding_uid", "SID", mono=True),
            TableColumn("finding_title", "Signature Title"),
            TableColumn("event_count", "Events", numeric=True),
            TableColumn("unique_ips", ip_col_label, numeric=True),
            TableColumn("severity_id", "Sev", numeric=True),
            TableColumn("category", "Category"),
            TableColumn("first_seen", "First Seen (UTC)", mono=True),
            TableColumn("last_seen", "Last Seen (UTC)", mono=True),
        ]
        sections.append(
            render_section_heading(
                "find-summary", "Suricata Detections", help_key="Detection Highlights"
            )
            + render_kpis(find_kpis)
            + render_chart_card(
                "top-rules-bar",
                f"Top 20 Signatures (colored by {ip_col_label})",
                top_rules_bar_chart(findings_df, ip_label=ip_col_label),
                help_key="Top Rules by Event Count",
            )
            + render_chart_card(
                "findings-pareto",
                "Rule Concentration (Top 50 Cumulative Share)",
                pareto_concentration_chart(findings_df),
                help_key="Rule Concentration",
            )
            + "<h3>All Findings</h3>"
            + render_interactive_table(
                "findings-table",
                find_cols,
                find_rows,
                page_size=25,
                search_placeholder="Search SID, rule title, or category...",
            )
        )

    return render_page(
        title="Behavior & TTPs",
        subtitle=(
            "Attacker escalation depth, credential wordlists & campaigns, "
            "post-auth commands, and Suricata IDS signatures."
        ),
        active_route="/behavior",
        window=window,
        toc_items=toc,
        body_html="".join(sections),
        operation_name=op_name,
    )


def _render_intel_view(
    window: DateWindow,
    gold_root: Path,
    reporting: ReportingConfig,
    *,
    reporting_loaded: bool = True,
) -> str:
    reputation = aggregate_ip_reputation(window.dates, gold_root=gold_root)
    clusters = aggregate_campaign_clusters(window.dates, gold_root=gold_root)
    extracted = aggregate_extracted_iocs(window.dates, gold_root=gold_root)

    toc: list[tuple[str, str]] = [
        ("ioc-summary", "Durable IOCs"),
        ("stix-export", "STIX 2.1 & Raw Export"),
    ]
    sections: list[str] = []

    if extracted.is_empty():
        sections.append(
            render_section_heading("ioc-summary", "Durable IOCs", help_key="Malware Captured")
            + '<div class="callout">'
            "No durable IOCs recorded in extracted_iocs for this window.</div>"
        )
    else:
        counts = {
            "malware_hash": extracted.filter(pl.col("ioc_type") == "malware_hash").height,
            "c2_ip": extracted.filter(pl.col("ioc_type") == "c2_ip").height,
            "stager_url": extracted.filter(pl.col("ioc_type") == "stager_url").height,
            "stager_domain": extracted.filter(pl.col("ioc_type") == "stager_domain").height,
            "ssh_key": extracted.filter(pl.col("ioc_type") == "ssh_key").height,
        }
        ioc_kpis = [
            KpiCard(
                "Total Durable IOCs",
                f"{extracted.height:,}",
                tone="info",
                metric_key="Durable IOCs",
            ),
            KpiCard(
                "Malware Hashes",
                f"{counts['malware_hash']:,}",
                tone="high" if counts["malware_hash"] > 0 else "",
                metric_key="Malware Uploaded",
            ),
            KpiCard(
                "Outbound C2 IPs",
                f"{counts['c2_ip']:,}",
                tone="high" if counts["c2_ip"] > 0 else "",
            ),
            KpiCard(
                "Stager URLs",
                f"{counts['stager_url']:,}",
                tone="med" if counts["stager_url"] > 0 else "",
            ),
            KpiCard("Stager Domains", f"{counts['stager_domain']:,}", tone="info"),
            KpiCard("SSH Public Keys", f"{counts['ssh_key']:,}", tone="low"),
        ]
        ioc_rows: list[dict[str, object]] = [
            {
                "ioc_type": str(row.get("ioc_type") or ""),
                "ioc_value": str(row.get("ioc_value") or ""),
                "vhash": str(row.get("vhash") or "—"),
                "malware_family": str(row.get("malware_family") or "—"),
                "vt_malicious": row.get("vt_malicious"),
                "gti_verdict": str(row.get("gti_verdict") or "—"),
                "actor_associations": str(row.get("actor_associations") or "—"),
                "event_count": int(row.get("event_count") or 0),
                "unique_src_ips": int(row.get("unique_src_ips") or 0),
                "first_seen": _fmt_ts(row.get("first_seen")),
            }
            for row in extracted.iter_rows(named=True)
        ]
        ioc_cols = [
            TableColumn("ioc_type", "Type", badge=True),
            TableColumn("ioc_value", "Observable (SHA-256 / URL / Host / IP / SSH Key)", mono=True),
            TableColumn("vhash", "vhash", mono=True),
            TableColumn("malware_family", "Family"),
            TableColumn("vt_malicious", "VT Det.", numeric=True),
            TableColumn("gti_verdict", "GTI Verdict", badge=True),
            TableColumn("actor_associations", "Actors"),
            TableColumn("event_count", "Events", numeric=True),
            TableColumn("unique_src_ips", "Src IPs", numeric=True),
            TableColumn("first_seen", "First Seen (UTC)", mono=True),
        ]
        sections.append(
            render_section_heading("ioc-summary", "Durable IOCs", help_key="Malware Captured")
            + render_kpis(ioc_kpis)
            + render_chart_card(
                "iocs-breakdown", "Durable IOC Breakdown", ioc_breakdown_chart(counts)
            )
            + "<h3>Observable Inventory</h3>"
            + render_interactive_table(
                "iocs-table",
                ioc_cols,
                ioc_rows,
                page_size=25,
                search_placeholder="Search hash, domain, URL, IP, family, vhash...",
                ioc_type_filter=True,
            )
        )

    if not reporting_loaded:
        sections.append(
            render_section_heading(
                "stix-export", "STIX 2.1 & Raw IOC Export", help_key="Bundle Composition"
            )
            + '<div class="callout callout-important">'
            '<div class="callout-title">OPSEC Guard — STIX Export Disabled</div>'
            "Could not load <code>reporting.json</code> (infrastructure IP/hostname "
            "redaction rules unavailable). Refusing to generate or download STIX "
            "bundles until <code>reporting.json</code> is valid and readable."
            "</div>"
        )
    elif reputation.is_empty() and extracted.is_empty():
        sections.append(
            render_section_heading(
                "stix-export", "STIX 2.1 & Raw IOC Export", help_key="Bundle Composition"
            )
            + '<div class="callout">No Gold data available to export for this window.</div>'
        )
    else:
        comp = count_stix_composition(reputation, clusters, extracted)
        durable_total = (
            comp["malware_hashes"]
            + comp["c2_ips"]
            + comp["stager_urls"]
            + comp["stager_domains"]
            + comp["ssh_keys"]
        )
        stix_kpis = [
            KpiCard(
                "Interactive Inbound IPs (7d)",
                f"{comp['inbound_ips']:,}",
                tone="high",
                metric_key="IP Indicators",
            ),
            KpiCard(
                "Durable IOC Indicators",
                f"{durable_total:,}",
                tone="info",
                metric_key="Durable IOCs",
            ),
            KpiCard(
                "Malware Hashes",
                f"{comp['malware_hashes']:,}",
                tone="high",
                metric_key="Hash Indicators",
            ),
            KpiCard("Campaigns", f"{comp['campaigns']:,}", tone="med", metric_key="Campaigns"),
        ]
        qs = window_query_string(window)
        try:
            bundle = build_window_stix_bundle(window, reporting, gold_root=gold_root)
            serialized = bundle.serialize(pretty=True)
            preview_snippet = serialized[:6000]
            if len(serialized) > 6000:
                preview_snippet += "\n... (truncated for preview; download full JSON above)"
            preview_block = (
                '<p class="table-meta">Verified OPSEC-clean bundle · '
                f"{len(bundle.objects):,} STIX 2.1 objects "
                f"(TLP:{esc(reporting.sharing.tlp.upper())}).</p>"
                f"<pre><code>{esc(preview_snippet)}</code></pre>"
            )
        except Exception as exc:
            preview_block = (
                '<div class="callout callout-important">'
                f'<div class="callout-title">STIX Preview Error</div>{esc(exc)}</div>'
            )
        stix_btn = (
            f'<a class="btn btn-primary" href="/download/stix?{qs}">'
            "Download STIX 2.1 Bundle (.json)</a>"
        )
        csv_btn = (
            f'<a class="btn" href="/download/iocs.csv.gz?{qs}">Download Raw IOCs (.csv.gz)</a>'
        )
        toc.append(("stix-preview", "STIX 2.1 Preview"))
        sections.append(
            render_section_heading(
                "stix-export", "STIX 2.1 & Raw IOC Export", help_key="Bundle Composition"
            )
            + render_kpis(stix_kpis)
            + render_chart_card(
                "stix-comp-chart", "STIX 2.1 Object Breakdown", stix_composition_chart(comp)
            )
            + render_section_heading("stix-download", "Export Artifacts", help_key="Raw IOC Export")
            + f'<div class="action-bar">{stix_btn}{csv_btn}</div>'
            + render_section_heading("stix-preview", "STIX 2.1 Preview")
            + preview_block
        )

    return render_page(
        title="Intel & Export",
        subtitle=(
            "Durable malware hashes (vhash), outbound C2s, stager URLs/domains, "
            "SSH keys, and OPSEC-verified STIX 2.1 / CSV.gz exports."
        ),
        active_route="/intel",
        window=window,
        toc_items=toc,
        body_html="".join(sections),
        operation_name=reporting.operation.name,
    )


def _render_health_view(
    window: DateWindow,
    gold_root: Path,
    silver_root: Path,
    reporting: ReportingConfig,
    *,
    datalake_root: Path | None = None,
    secrets_path: Path | None = None,
    geoip_dir: Path | None = None,
    firewall_log_path: Path | None = None,
) -> str:
    snap = collect_health_snapshot(
        dates=window.dates,
        reporting=reporting,
        gold_root=gold_root,
        silver_root=silver_root,
        datalake_root=datalake_root,
        secrets_path=secrets_path,
        geoip_dir=geoip_dir,
        firewall_log_path=firewall_log_path,
    )

    configured_cnt = sum(1 for i in snap.integrations if i.config_mode != "Not Configured")
    unconfigured_names = [i.name for i in snap.integrations if i.config_mode == "Not Configured"]
    if snap.disk is not None:
        disk_val = f"{snap.disk.usage_pct:.1f}%"
        disk_sub = (
            f"{format_bytes(snap.disk.used_bytes)} / "
            f"{format_bytes(snap.disk.total_usable_bytes)} "
            f"({format_bytes(snap.disk.free_bytes)} free)"
        )
        disk_tone = (
            "high"
            if snap.disk.status == "Critical"
            else ("med" if snap.disk.status == "Warning" else "low")
        )
    else:
        disk_val = "—"
        disk_sub = "Unavailable"
        disk_tone = ""

    crit_n = sum(int(r.get("count", 1)) for r in snap.buckets.critical)
    warn_n = sum(int(r.get("count", 1)) for r in snap.buckets.warning)
    info_n = sum(int(r.get("count", 1)) for r in snap.buckets.info)
    alert_tone = "high" if crit_n > 0 else ("med" if warn_n > 0 else "low")

    status_sub = " · ".join(snap.status_reasons)
    if snap.target_date is not None:
        status_sub = f"{status_sub} ({snap.target_date.isoformat()})"

    if snap.egress is None:
        egress_val = "Remote"
        egress_sub = "No local sensor-egress.log (multi-node collector)"
        egress_tone = ""
    elif snap.egress.total_violations > 0:
        egress_val = f"{snap.egress.total_violations:,} Blocked"
        egress_sub = (
            f"{snap.egress.wan_drops} WAN · {snap.egress.local_drops} local "
            f"({snap.egress.canary_drops} canary)"
        )
        egress_tone = "high"
    else:
        egress_val = "0 Blocked"
        egress_sub = f"Dark policy intact ({snap.egress.canary_drops} canary)"
        egress_tone = "low"

    kpis = [
        KpiCard(
            "Overall Status",
            snap.overall_status,
            sub=status_sub,
            tone=snap.overall_tone,
            metric_key="Overall Status",
        ),
        KpiCard(
            "Usable Disk",
            disk_val,
            sub=disk_sub,
            tone=disk_tone,
            metric_key="Usable Disk",
        ),
        KpiCard(
            "Sensor Egress",
            egress_val,
            sub=egress_sub,
            tone=egress_tone,
            metric_key="Sensor Egress",
        ),
        KpiCard(
            "Integrations Active",
            f"{configured_cnt} / {len(snap.integrations)}",
            sub=(
                "All configured"
                if not unconfigured_names
                else f"Unset: {', '.join(unconfigured_names[:2])}"
                + ("…" if len(unconfigured_names) > 2 else "")
            ),
            tone="low" if not unconfigured_names else "info",
            metric_key="Integrations Active",
        ),
        KpiCard(
            "Latest Run Alerts",
            f"{crit_n}C · {warn_n}W · {info_n}I",
            sub="Critical · Warning · Info",
            tone=alert_tone,
            metric_key="Latest Run Alerts",
        ),
        KpiCard(
            "Enrichment Cache",
            f"{snap.cache_active_entries:,}",
            sub=f"SQLite DB: {format_bytes(snap.cache_size_bytes)}",
            tone="info",
            metric_key="Enrichment Cache",
        ),
    ]

    secrets_warning = (
        ""
        if snap.secrets_loaded
        else (
            '<div class="callout callout-warning">'
            '<div class="callout-title">Secrets Config Unavailable</div>'
            "<code>secrets.json</code> was not readable from the dashboard process — "
            "integration configuration status defaults to Not Configured."
            "</div>"
        )
    )

    integration_rows = [
        [
            i.name,
            i.config_mode,
            i.status,
            f"{i.cache_entries:,}" if i.cache_entries is not None else "—",
            i.last_rate_limited or "—",
            i.last_message,
        ]
        for i in snap.integrations
    ]
    integrations_tbl = render_simple_table(
        ["Integration", "Config", "Last Run Status", "Cached IOCs", "Last 429", "Details"],
        integration_rows,
        numeric_cols={3},
        mono_cols={4},
        badge_cols={1, 2},
    )

    unit_rows = [
        [
            u.step,
            u.schedule,
            u.status,
            u.raw_result,
            u.duration_display,
            u.finished_at_display,
        ]
        for u in snap.units
    ]
    units_tbl = render_simple_table(
        ["Step", "Schedule", "Status", "Systemd Result", "Duration", "Last Finished"],
        unit_rows,
        numeric_cols={4},
        mono_cols={0, 1, 3, 5},
        badge_cols={2},
    )

    ds_rows = [
        [
            d.dataset,
            d.status,
            d.latest_bronze,
            d.latest_silver,
            format_bytes(d.silver_size_bytes) if d.silver_size_bytes > 0 else "—",
        ]
        for d in snap.datasets
    ]
    datasets_tbl = render_simple_table(
        ["Dataset", "Liveness", "Latest Bronze", "Latest Silver", "Latest Silver Size"],
        ds_rows,
        numeric_cols={4},
        mono_cols={0, 2, 3},
        badge_cols={1},
    )

    disk_bar_html = ""
    if snap.disk is not None:
        clamped = max(0.0, min(100.0, snap.disk.usage_pct))
        bar_tone = f" tone-{disk_tone}" if disk_tone in ("med", "high") else ""
        disk_bar_html = (
            '<div class="callout">'
            f'<div class="callout-title">Filesystem Headroom — {snap.disk.usage_pct:.1f}% Used '
            f"(Warn &gt;70% · Emergency Prune &gt;80%)</div>"
            f'<div class="disk-meter"><div class="disk-meter-fill{bar_tone}" '
            f'style="width:{clamped:.1f}%"></div></div>'
            f'<div class="table-meta">Used: {esc(format_bytes(snap.disk.used_bytes))} · '
            f"Free (non-root usable): {esc(format_bytes(snap.disk.free_bytes))} · "
            f"Total usable: {esc(format_bytes(snap.disk.total_usable_bytes))}</div>"
            "</div>"
        )

    storage_rows = [
        [
            t.tier,
            t.retention,
            f"{t.files:,}",
            format_bytes(t.size_bytes),
        ]
        for t in snap.storage_tiers
    ]
    storage_tbl = render_simple_table(
        ["Storage Tier", "Retention Policy", "Files", "Footprint"],
        storage_rows,
        numeric_cols={2, 3},
    )

    msg_columns = [
        TableColumn("date", "Date", mono=True),
        TableColumn("severity", "Severity", badge=True),
        TableColumn("provider", "Component", mono=True),
        TableColumn("error_type", "Type", mono=True),
        TableColumn("count", "Count", numeric=True),
        TableColumn("message", "Message"),
    ]
    messages_block = render_interactive_table(
        "health-messages-table",
        msg_columns,
        snap.recent_messages,
        page_size=25,
        search_placeholder="Filter provider, error type, or message...",
        empty_message="All clear — no pipeline or provider errors recorded for this window.",
    )

    toc = [
        ("health-summary", "System Summary"),
        ("health-integrations", "3rd-Party Integrations"),
        ("health-pipeline", "Pipeline Units & Liveness"),
        ("health-storage", "Storage & Retention"),
        ("health-messages", "Recent Messages"),
    ]
    body = (
        render_section_heading("health-summary", "System Summary", help_key="Pipeline Health")
        + render_kpis(kpis)
        + secrets_warning
        + render_section_heading(
            "health-integrations", "3rd-Party Integrations", help_key="Integrations Status"
        )
        + integrations_tbl
        + render_section_heading(
            "health-pipeline", "Pipeline Units & Dataset Liveness", help_key="Dataset Liveness"
        )
        + '<div class="chart-grid">'
        + f"<div><h3>Scheduled Units</h3>{units_tbl}</div>"
        + f"<div><h3>Dataset Liveness</h3>{datasets_tbl}</div>"
        + "</div>"
        + render_section_heading(
            "health-storage", "Storage & Retention", help_key="Storage & Retention"
        )
        + disk_bar_html
        + storage_tbl
        + render_section_heading(
            "health-messages", "Recent Pipeline & Provider Messages", help_key="Recent Messages"
        )
        + messages_block
    )
    return render_page(
        title="System Health",
        subtitle=(
            "3rd-party API status, last-run messages, dataset liveness, "
            "pipeline timing, and storage headroom."
        ),
        active_route="/health",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=reporting.operation.name,
    )


_LEGACY_ROUTE_REDIRECTS: dict[str, tuple[str, str]] = {
    "/ips": ("/attackers", ""),
    "/geography": ("/attackers", "#geo-origins"),
    "/progression": ("/behavior", "#prog-funnel"),
    "/credentials": ("/behavior", "#cred-lists"),
    "/findings": ("/behavior", "#find-summary"),
    "/iocs": ("/intel", "#ioc-summary"),
    "/stix": ("/intel", "#stix-export"),
}

_ALLOWED_REDIRECT_WINDOWS: dict[str, str] = {mode: mode for mode in VALID_WINDOW_MODES}


def _build_safe_redirect_location(
    dest_path: str,
    anchor: str,
    query: dict[str, list[str]],
) -> str:
    """Build a strictly sanitized relative ``Location`` header for legacy redirects.

    Reconstructs only allowlisted date-window parameters (``window``, ``start``,
    ``end``) from static literals and parsed ISO dates so raw request strings
    never flow into HTTP response headers.
    """
    params: list[tuple[str, str]] = []
    window_vals = query.get("window")
    if window_vals:
        safe_window = _ALLOWED_REDIRECT_WINDOWS.get(window_vals[0].strip().lower())
        if safe_window is not None:
            params.append(("window", safe_window))

    for date_key in ("start", "end"):
        raw_vals = query.get(date_key)
        if not raw_vals:
            continue
        try:
            parsed_date = date.fromisoformat(raw_vals[0].strip())
        except ValueError:
            continue
        params.append((date_key, parsed_date.isoformat()))

    qs_suffix = f"?{urlencode(params)}" if params else ""
    return f"{dest_path}{qs_suffix}{anchor}"


class DashboardServer(ThreadingHTTPServer):
    """Typed ``ThreadingHTTPServer`` carrying datalake & reporting config."""

    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        gold_root: Path = GOLD_ROOT,
        silver_root: Path = SILVER_ROOT,
        reporting_path: Path | None = None,
        secrets_path: Path | None = None,
        datalake_root: Path | None = None,
        geoip_dir: Path | None = None,
        firewall_log_path: Path | None = None,
    ) -> None:
        self.gold_root = gold_root
        self.silver_root = silver_root
        self.reporting_path = reporting_path
        self.secrets_path = secrets_path
        self.datalake_root = datalake_root
        self.geoip_dir = geoip_dir
        self.firewall_log_path = firewall_log_path
        super().__init__(server_address, DashboardRequestHandler)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Air-gapped HTTP handler serving Vigil HTML views, local static assets, and exports."""

    server: DashboardServer

    def log_message(self, format: str, *args: Any) -> None:
        # Keep stdout clean unless debugging; standard server quiet mode.
        _ = (format, args)

    def _send_bytes(
        self,
        body: bytes,
        *,
        content_type: str,
        status: int = HTTPStatus.OK,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", _CSP_HEADER)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_text: str, *, status: int = HTTPStatus.OK) -> None:
        self._send_bytes(
            html_text.encode("utf-8"),
            content_type="text/html; charset=utf-8",
            status=status,
            extra_headers={"Cache-Control": "no-store"},
        )

    def _resolve_request_window(self, query: dict[str, list[str]]) -> DateWindow:
        available = discover_available_dates(gold_root=self.server.gold_root)
        mode_vals = query.get("window")
        start_vals = query.get("start")
        end_vals = query.get("end")
        mode = mode_vals[0] if mode_vals else "latest"
        start = start_vals[0] if start_vals else None
        end = end_vals[0] if end_vals else None
        return resolve_window(available, mode=mode, start=start, end=end)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if route == "/":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/overview")
            self.end_headers()
            return

        if route == "/static/vigil.css":
            self._send_bytes(
                _load_vigil_css_bytes(),
                content_type="text/css; charset=utf-8",
                extra_headers={"Cache-Control": "public, max-age=3600"},
            )
            return

        if route == "/static/plotly.min.js":
            self._send_bytes(
                _load_plotly_js_bytes(),
                content_type="application/javascript; charset=utf-8",
                extra_headers={"Cache-Control": "public, max-age=86400, immutable"},
            )
            return

        if route in _LEGACY_ROUTE_REDIRECTS:
            dest_path, anchor = _LEGACY_ROUTE_REDIRECTS[route]
            location = _build_safe_redirect_location(dest_path, anchor, query)
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", location)
            self.end_headers()
            return

        window = self._resolve_request_window(query)
        reporting, reporting_loaded = _load_reporting_checked(self.server.reporting_path)
        op_name = reporting.operation.name
        gold_root = self.server.gold_root

        if route == "/overview":
            self._send_html(_render_overview_view(window, gold_root, op_name))
            return
        if route == "/attackers":
            self._send_html(_render_attackers_view(window, gold_root, op_name))
            return
        if route == "/behavior":
            self._send_html(_render_behavior_view(window, gold_root, op_name))
            return
        if route == "/intel":
            self._send_html(
                _render_intel_view(
                    window,
                    gold_root,
                    reporting,
                    reporting_loaded=reporting_loaded,
                )
            )
            return
        if route == "/health":
            self._send_html(
                _render_health_view(
                    window,
                    gold_root,
                    self.server.silver_root,
                    reporting,
                    datalake_root=self.server.datalake_root,
                    secrets_path=self.server.secrets_path,
                    geoip_dir=self.server.geoip_dir,
                    firewall_log_path=self.server.firewall_log_path,
                )
            )
            return

        if route == "/download/stix":
            if not reporting_loaded:
                self._send_bytes(
                    b'{"error": "reporting config unavailable; refusing STIX export"}',
                    content_type="application/json",
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                    extra_headers={"Cache-Control": "no-store"},
                )
                return
            if not window.dates:
                self._send_bytes(
                    b'{"error": "no gold data for selected window"}',
                    content_type="application/json",
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            try:
                bundle = build_window_stix_bundle(window, reporting, gold_root=gold_root)
            except ValueError as exc:
                self._send_bytes(
                    json.dumps({"error": str(exc)}).encode("utf-8"),
                    content_type="application/json",
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                    extra_headers={"Cache-Control": "no-store"},
                )
                return
            tag = window.end_date.isoformat() if window.end_date else "export"
            payload = bundle.serialize(pretty=True).encode("utf-8")
            self._send_bytes(
                payload,
                content_type="application/stix+json; charset=utf-8",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="lantana-stix-{tag}.json"',
                    "Cache-Control": "no-store",
                },
            )
            return

        if route == "/download/iocs.csv.gz":
            exported = build_window_raw_ioc_csv_gz(
                window.dates,
                silver_root=self.server.silver_root,
                gold_root=gold_root,
            )
            if exported is None:
                self._send_bytes(
                    b"No silver IOCs available for selected window.",
                    content_type="text/plain; charset=utf-8",
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            gz_bytes, _count = exported
            tag = window.end_date.isoformat() if window.end_date else "export"
            self._send_bytes(
                gz_bytes,
                content_type="application/gzip",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="lantana-iocs-{tag}.csv.gz"',
                    "Cache-Control": "no-store",
                },
            )
            return

        self._send_html(
            render_page(
                title="404 — View Not Found",
                subtitle="The requested route does not exist.",
                active_route="/overview",
                window=window,
                toc_items=(),
                body_html='<div class="callout">Return to <a href="/overview">Overview</a>.</div>',
                operation_name=op_name,
            ),
            status=HTTPStatus.NOT_FOUND,
        )


def create_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8501,
    gold_root: Path | None = None,
    silver_root: Path | None = None,
    reporting_path: Path | None = None,
    secrets_path: Path | None = None,
    datalake_root: Path | None = None,
    geoip_dir: Path | None = None,
    firewall_log_path: Path | None = None,
) -> DashboardServer:
    """Create a configured ``DashboardServer`` bound strictly to ``host:port``."""
    resolved_gold = (
        gold_root
        if gold_root is not None
        else Path(os.environ.get("LANTANA_GOLD_ROOT", str(GOLD_ROOT)))
    )
    resolved_silver = (
        silver_root
        if silver_root is not None
        else Path(os.environ.get("LANTANA_SILVER_ROOT", str(SILVER_ROOT)))
    )
    return DashboardServer(
        (host, port),
        gold_root=resolved_gold,
        silver_root=resolved_silver,
        reporting_path=reporting_path,
        secrets_path=secrets_path,
        datalake_root=datalake_root,
        geoip_dir=geoip_dir,
        firewall_log_path=firewall_log_path,
    )


def serve(
    *,
    host: str = "127.0.0.1",
    port: int = 8501,
    gold_root: Path | None = None,
    silver_root: Path | None = None,
    reporting_path: Path | None = None,
) -> None:
    """Start the air-gapped Vigil dashboard server until interrupted."""
    server = create_server(
        host=host,
        port=port,
        gold_root=gold_root,
        silver_root=silver_root,
        reporting_path=reporting_path,
    )
    bound_host, bound_port = server.server_address[:2]
    host_str = bound_host.decode("ascii") if isinstance(bound_host, bytes) else str(bound_host)
    print(f"Lantana Vigil Console listening on http://{host_str}:{bound_port}/overview")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    """CLI entry point for ``lantana-dashboard``."""
    parser = argparse.ArgumentParser(
        description="Launch the air-gapped Lantana Vigil Intelligence Console (127.0.0.1 only).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host (default: 127.0.0.1 — never expose publicly).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("LANTANA_DASHBOARD_PORT", "8501")),
        help="Bind port (default: 8501 or $LANTANA_DASHBOARD_PORT).",
    )
    parser.add_argument(
        "--gold-root",
        type=Path,
        default=None,
        help="Override Gold Parquet directory (default: $LANTANA_GOLD_ROOT).",
    )
    parser.add_argument(
        "--silver-root",
        type=Path,
        default=None,
        help="Override Silver Parquet directory (default: $LANTANA_SILVER_ROOT).",
    )
    args = parser.parse_args()
    serve(
        host=args.host,
        port=args.port,
        gold_root=args.gold_root,
        silver_root=args.silver_root,
    )


if __name__ == "__main__":
    main()

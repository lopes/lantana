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
from functools import lru_cache
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

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

    toc.append(("top-activity", "Top Credentials & Commands"))
    sections.append(
        render_section_heading(
            "top-activity", "Top Credentials & Commands", help_key="Top Credentials"
        )
    )
    user_tbl = render_simple_table(
        ["Rank", "Username", "Count"],
        [[r["rank"], r["value"], f"{int(str(r['count'])):,}"] for r in bundle.top_usernames],
        numeric_cols={0, 2},
        mono_cols={1},
    )
    pass_tbl = render_simple_table(
        ["Rank", "Password", "Count"],
        [[r["rank"], r["value"], f"{int(str(r['count'])):,}"] for r in bundle.top_passwords],
        numeric_cols={0, 2},
        mono_cols={1},
    )
    cmd_tbl = render_simple_table(
        ["Rank", "Command", "Count"],
        [[r["rank"], r["value"], f"{int(str(r['count'])):,}"] for r in bundle.top_commands],
        numeric_cols={0, 2},
        mono_cols={1},
    )
    sections.append(
        '<div class="chart-grid">'
        f"<div><h3>Top Usernames</h3>{user_tbl}</div>"
        f"<div><h3>Top Passwords</h3>{pass_tbl}</div>"
        "</div>"
        f"<h3>Top Commands</h3>{cmd_tbl}"
    )

    toc.append(("origin", "Top Countries & ASNs"))
    sections.append(
        render_section_heading("origin", "Top Countries & ASNs", help_key="Geographic Origin")
    )
    country_tbl = render_simple_table(
        ["Rank", "Country", "Count"],
        [[r["rank"], r["value"], f"{int(str(r['count'])):,}"] for r in bundle.top_countries],
        numeric_cols={0, 2},
    )
    asn_tbl = render_simple_table(
        ["Rank", "ASN", "ISP", "Unique IPs", "Events"],
        [
            [
                r["rank"],
                r["asn"],
                r["isp"],
                f"{int(str(r['unique_ips'])):,}",
                f"{int(str(r['events'])):,}",
            ]
            for r in bundle.top_asns
        ],
        numeric_cols={0, 3, 4},
        mono_cols={1},
    )
    sections.append(
        '<div class="chart-grid">'
        f"<div><h3>Top Countries</h3>{country_tbl}</div>"
        f"<div><h3>Top ASNs</h3>{asn_tbl}</div>"
        "</div>"
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


def _render_iocs_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    df = aggregate_extracted_iocs(window.dates, gold_root=gold_root)
    if df.is_empty():
        return render_page(
            title="Malware & Durable IOCs",
            subtitle=(
                "High-signal malware hashes, outbound C2 IPs, stager URLs, "
                "domains, and attacker SSH keys."
            ),
            active_route="/iocs",
            window=window,
            toc_items=(),
            body_html=(
                '<div class="callout">'
                "No durable IOCs recorded in extracted_iocs for this window.</div>"
            ),
            operation_name=op_name,
        )

    counts = {
        "malware_hash": df.filter(pl.col("ioc_type") == "malware_hash").height,
        "c2_ip": df.filter(pl.col("ioc_type") == "c2_ip").height,
        "stager_url": df.filter(pl.col("ioc_type") == "stager_url").height,
        "stager_domain": df.filter(pl.col("ioc_type") == "stager_domain").height,
        "ssh_key": df.filter(pl.col("ioc_type") == "ssh_key").height,
    }
    kpis = [
        KpiCard("Total Durable IOCs", f"{df.height:,}", tone="info", metric_key="Durable IOCs"),
        KpiCard(
            "Malware Hashes",
            f"{counts['malware_hash']:,}",
            tone="high" if counts["malware_hash"] > 0 else "",
            metric_key="Malware Uploaded",
        ),
        KpiCard(
            "Outbound C2 IPs", f"{counts['c2_ip']:,}", tone="high" if counts["c2_ip"] > 0 else ""
        ),
        KpiCard(
            "Stager URLs",
            f"{counts['stager_url']:,}",
            tone="med" if counts["stager_url"] > 0 else "",
        ),
        KpiCard("Stager Domains", f"{counts['stager_domain']:,}", tone="info"),
        KpiCard("SSH Public Keys", f"{counts['ssh_key']:,}", tone="low"),
    ]

    rows: list[dict[str, object]] = []
    for row in df.iter_rows(named=True):
        rows.append(
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
                "last_seen": _fmt_ts(row.get("last_seen")),
            }
        )

    columns = [
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

    toc = [
        ("ioc-summary", "Durable IOC Summary"),
        ("ioc-inventory", "Observable Inventory"),
    ]
    body = (
        render_section_heading("ioc-summary", "Durable IOC Summary", help_key="Malware Captured")
        + render_kpis(kpis)
        + render_chart_card("iocs-breakdown", "Durable IOC Breakdown", ioc_breakdown_chart(counts))
        + render_section_heading("ioc-inventory", "Observable Inventory")
        + render_interactive_table(
            "iocs-table",
            columns,
            rows,
            page_size=25,
            search_placeholder="Search hash, domain, URL, IP, family, vhash...",
            ioc_type_filter=True,
        )
    )
    return render_page(
        title="Malware & Durable IOCs",
        subtitle=(
            "Uploaded binaries (SHA-256 + vhash clusters), outbound C2 infrastructure, "
            "stager hostnames, and persistence keys."
        ),
        active_route="/iocs",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=op_name,
    )


def _render_ips_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    df = aggregate_ip_reputation(window.dates, gold_root=gold_root)
    if df.is_empty():
        return render_page(
            title="IP Reputation",
            subtitle=(
                "Monotonic behavioral-anchored risk scores and provider sub-score decomposition."
            ),
            active_route="/ips",
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
        title="IP Reputation",
        subtitle=(
            "Composite risk scores, behavioral vs enrichment decomposition, "
            "and searchable attacker index."
        ),
        active_route="/ips",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=op_name,
    )


def _render_geography_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    df = aggregate_ip_reputation(window.dates, gold_root=gold_root)
    if df.is_empty():
        return render_page(
            title="Geography",
            subtitle="Attacker origin map, countries, cities, and hosting ASNs.",
            active_route="/geography",
            window=window,
            toc_items=(),
            body_html='<div class="callout">No geographic data available for this window.</div>',
            operation_name=op_name,
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

    toc = [
        ("geo-map", "World Map"),
        ("geo-countries", "Top Countries & Cities"),
        ("geo-asns", "Top ASNs / ISPs"),
    ]
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
    body = (
        render_section_heading("geo-map", "World Map", help_key="World Map")
        + render_chart_card(
            "world-map", "Attacker Origins (Size = log10 Events, Color = Risk)", world_map_chart(df)
        )
        + render_section_heading(
            "geo-countries", "Top Countries & Cities", help_key="Top Countries"
        )
        + render_chart_card(
            "top-countries-bar",
            "Unique Attacker IPs by Country",
            top_countries_bar_chart(countries_df),
        )
        + '<div class="chart-grid">'
        + f"<div><h3>Top Countries</h3>{countries_tbl}</div>"
        + f"<div><h3>Top Cities</h3>{cities_tbl}</div>"
        + "</div>"
        + render_section_heading("geo-asns", "Top ASNs / ISPs", help_key="Top ASNs")
        + render_simple_table(
            ["Rank", "ASN", "ISP", "Unique IPs", "Events"],
            asn_rows,
            numeric_cols={0, 3, 4},
            mono_cols={1},
        )
    )
    return render_page(
        title="Geography",
        subtitle=(
            "MaxMind GeoLite2 origin distribution, cities, and hosting ASNs deduplicated per IP."
        ),
        active_route="/geography",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=op_name,
    )


def _render_credentials_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    summary_df = read_gold_range("daily_summary", window.dates, gold_root=gold_root)
    clusters_df = aggregate_campaign_clusters(window.dates, gold_root=gold_root)

    if summary_df.is_empty() and clusters_df.is_empty():
        return render_page(
            title="Credentials & Campaigns",
            subtitle="Trending credential wordlists and multi-IP stuffing clusters.",
            active_route="/credentials",
            window=window,
            toc_items=(),
            body_html=(
                '<div class="callout">'
                "No credential or campaign data available for this window.</div>"
            ),
            operation_name=op_name,
        )

    users = _merge_top_n_structs(summary_df, "top_usernames", limit=15)
    passwords = _merge_top_n_structs(summary_df, "top_passwords", limit=15)
    pairs = _merge_credential_pairs(summary_df, limit=15)

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

    toc = [
        ("cred-lists", "Top Credentials"),
        ("cred-clusters", "Campaign Clusters"),
    ]
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

    body = (
        render_section_heading("cred-lists", "Top Credentials", help_key="Top Credentials")
        + '<div class="chart-grid cols-3">'
        + f"<div><h3>Top Usernames</h3>{users_tbl}</div>"
        + f"<div><h3>Top Passwords</h3>{passwords_tbl}</div>"
        + f"<div><h3>Top Pairs</h3>{pairs_tbl}</div>"
        + "</div>"
        + render_section_heading("cred-clusters", "Campaign Clusters", help_key="Campaign Clusters")
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
    return render_page(
        title="Credentials & Campaigns",
        subtitle=(
            "Most-attempted usernames, passwords, pairs, and coordinated "
            "credential-stuffing botnets (exact IP union)."
        ),
        active_route="/credentials",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=op_name,
    )


def _render_progression_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    df, multiday = aggregate_behavioral_progression(window.dates, gold_root=gold_root)
    if df.is_empty():
        return render_page(
            title="Behavioral Progression",
            subtitle=(
                "Escalation funnel, automation split, stage timing, and multi-day persistence."
            ),
            active_route="/progression",
            window=window,
            toc_items=(),
            body_html='<div class="callout">No progression data available for this window.</div>',
            operation_name=op_name,
        )

    funnel_kpis = [
        KpiCard(
            label,
            f"{df.filter(pl.col('max_stage') >= stage).height:,}",
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
    auto_count = df.filter(pl.col("is_automated").fill_null(False)).height
    manual_count = df.height - auto_count
    auto_kpis = [
        KpiCard("Automated Bots", f"{auto_count:,}", tone="med", metric_key="Automated Bots"),
        KpiCard(
            "Manual / Unknown", f"{manual_count:,}", tone="info", metric_key="Manual or Unknown"
        ),
    ]

    prog_rows: list[dict[str, object]] = []
    for row in df.iter_rows(named=True):
        prog_rows.append(
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
        )
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
    toc: list[tuple[str, str]] = [
        ("prog-funnel", "Escalation Funnel"),
        ("prog-scatter", "Stage vs Time"),
        ("prog-details", "IP Progression Details"),
    ]
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

    body = (
        render_section_heading("prog-funnel", "Escalation Funnel", help_key="Escalation Funnel")
        + render_kpis(funnel_kpis)
        + render_kpis(auto_kpis)
        + render_section_heading("prog-scatter", "Stage vs Time", help_key="Stage vs Time")
        + render_chart_card(
            "stage-scatter", "Max Stage vs First Seen (UTC)", stage_scatter_chart(df)
        )
        + render_section_heading("prog-details", "IP Progression Details")
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
    return render_page(
        title="Behavioral Progression",
        subtitle=(
            "Depth of attacker engagement from initial scan through hands-on-keyboard commands."
        ),
        active_route="/progression",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=op_name,
    )


def _render_findings_view(window: DateWindow, gold_root: Path, op_name: str) -> str:
    df = aggregate_detection_findings(window.dates, gold_root=gold_root)
    if df.is_empty():
        return render_page(
            title="Detection Findings",
            subtitle=(
                "Suricata IDS signatures (decoder/stream noise SIDs 2200000-2260999 excluded)."
            ),
            active_route="/findings",
            window=window,
            toc_items=(),
            body_html='<div class="callout">No IDS detection findings for this window.</div>',
            operation_name=op_name,
        )

    ip_col_label = "IP-days" if window.is_multi_day else "Unique IPs"
    total_events = int(df.get_column("event_count").sum())
    total_ip_breadth = int(df.get_column("unique_ips").sum())

    kpis = [
        KpiCard("Distinct Rules", f"{df.height:,}", tone="info", metric_key="Total Rules"),
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

    rows: list[dict[str, object]] = []
    for row in df.iter_rows(named=True):
        rows.append(
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
        )
    columns = [
        TableColumn("finding_uid", "SID", mono=True),
        TableColumn("finding_title", "Signature Title"),
        TableColumn("event_count", "Events", numeric=True),
        TableColumn("unique_ips", ip_col_label, numeric=True),
        TableColumn("severity_id", "Sev", numeric=True),
        TableColumn("category", "Category"),
        TableColumn("first_seen", "First Seen (UTC)", mono=True),
        TableColumn("last_seen", "Last Seen (UTC)", mono=True),
    ]

    toc = [
        ("find-summary", "Summary"),
        ("find-top", "Top Rules"),
        ("find-pareto", "Rule Concentration"),
        ("find-all", "All Findings"),
    ]
    body = (
        render_section_heading("find-summary", "IDS Summary", help_key="Detection Highlights")
        + render_kpis(kpis)
        + render_section_heading(
            "find-top", "Top Rules by Event Count", help_key="Top Rules by Event Count"
        )
        + render_chart_card(
            "top-rules-bar",
            f"Top 20 Signatures (colored by {ip_col_label})",
            top_rules_bar_chart(df, ip_label=ip_col_label),
        )
        + render_section_heading(
            "find-pareto", "Rule Concentration (Pareto)", help_key="Rule Concentration"
        )
        + render_chart_card(
            "findings-pareto", "Top 50 Rules Cumulative Share", pareto_concentration_chart(df)
        )
        + render_section_heading("find-all", "All Findings")
        + render_interactive_table(
            "findings-table",
            columns,
            rows,
            page_size=25,
            search_placeholder="Search SID, rule title, or category...",
        )
    )
    return render_page(
        title="Detection Findings",
        subtitle=(
            "Suricata IDS alerts with preserved signature IDs and "
            "honest multi-day IP-day aggregation."
        ),
        active_route="/findings",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=op_name,
    )


def _render_stix_view(
    window: DateWindow,
    gold_root: Path,
    reporting: ReportingConfig,
    *,
    reporting_loaded: bool = True,
) -> str:
    if not reporting_loaded:
        return render_page(
            title="STIX 2.1 & Raw IOC Export",
            subtitle=(
                "Durable threat intelligence bundle for OpenCTI/MISP and "
                "threshold-free Silver CSV.gz export."
            ),
            active_route="/stix",
            window=window,
            toc_items=(),
            body_html=(
                '<div class="callout callout-important">'
                '<div class="callout-title">OPSEC Guard — STIX Export Disabled</div>'
                "Could not load <code>reporting.json</code> (infrastructure IP/hostname "
                "redaction rules unavailable). Refusing to generate or download STIX "
                "bundles until <code>reporting.json</code> is valid and readable."
                "</div>"
            ),
            operation_name=reporting.operation.name,
        )

    reputation = aggregate_ip_reputation(window.dates, gold_root=gold_root)
    clusters = aggregate_campaign_clusters(window.dates, gold_root=gold_root)
    extracted = aggregate_extracted_iocs(window.dates, gold_root=gold_root)

    if reputation.is_empty() and extracted.is_empty():
        return render_page(
            title="STIX 2.1 & Raw IOC Export",
            subtitle=(
                "Durable threat intelligence bundle for OpenCTI/MISP and "
                "threshold-free Silver CSV.gz export."
            ),
            active_route="/stix",
            window=window,
            toc_items=(),
            body_html=(
                '<div class="callout">No Gold data available to export for this window.</div>'
            ),
            operation_name=reporting.operation.name,
        )

    comp = count_stix_composition(reputation, clusters, extracted)
    durable_total = (
        comp["malware_hashes"]
        + comp["c2_ips"]
        + comp["stager_urls"]
        + comp["stager_domains"]
        + comp["ssh_keys"]
    )
    kpis = [
        KpiCard(
            "Interactive Inbound IPs (7d)",
            f"{comp['inbound_ips']:,}",
            tone="high",
            metric_key="IP Indicators",
        ),
        KpiCard(
            "Durable IOC Indicators", f"{durable_total:,}", tone="info", metric_key="Durable IOCs"
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
    preview_block = ""
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

    toc = [
        ("stix-comp", "Bundle Composition"),
        ("stix-download", "Downloads"),
        ("stix-preview", "STIX 2.1 Preview"),
    ]
    stix_btn = (
        f'<a class="btn btn-primary" href="/download/stix?{qs}">'
        "Download STIX 2.1 Bundle (.json)</a>"
    )
    csv_btn = f'<a class="btn" href="/download/iocs.csv.gz?{qs}">Download Raw IOCs (.csv.gz)</a>'
    body = (
        render_section_heading("stix-comp", "Bundle Composition", help_key="Bundle Composition")
        + render_kpis(kpis)
        + render_chart_card(
            "stix-comp-chart", "STIX 2.1 Object Breakdown", stix_composition_chart(comp)
        )
        + render_section_heading("stix-download", "Export Artifacts", help_key="Raw IOC Export")
        + f'<div class="action-bar">{stix_btn}{csv_btn}</div>'
        + render_section_heading("stix-preview", "STIX 2.1 Preview")
        + preview_block
    )
    return render_page(
        title="STIX 2.1 & Raw IOC Export",
        subtitle=(
            "Durable malware hashes (vhash), C2 IPs, stager URLs/domains, "
            "SSH keys, and 7-day interactive inbound IPs."
        ),
        active_route="/stix",
        window=window,
        toc_items=toc,
        body_html=body,
        operation_name=reporting.operation.name,
    )


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
    ) -> None:
        self.gold_root = gold_root
        self.silver_root = silver_root
        self.reporting_path = reporting_path
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

        window = self._resolve_request_window(query)
        reporting, reporting_loaded = _load_reporting_checked(self.server.reporting_path)
        op_name = reporting.operation.name
        gold_root = self.server.gold_root

        if route == "/overview":
            self._send_html(_render_overview_view(window, gold_root, op_name))
            return
        if route == "/iocs":
            self._send_html(_render_iocs_view(window, gold_root, op_name))
            return
        if route == "/ips":
            self._send_html(_render_ips_view(window, gold_root, op_name))
            return
        if route == "/geography":
            self._send_html(_render_geography_view(window, gold_root, op_name))
            return
        if route == "/credentials":
            self._send_html(_render_credentials_view(window, gold_root, op_name))
            return
        if route == "/progression":
            self._send_html(_render_progression_view(window, gold_root, op_name))
            return
        if route == "/findings":
            self._send_html(_render_findings_view(window, gold_root, op_name))
            return
        if route == "/stix":
            self._send_html(
                _render_stix_view(
                    window,
                    gold_root,
                    reporting,
                    reporting_loaded=reporting_loaded,
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

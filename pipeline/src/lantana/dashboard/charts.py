"""Pure ``plotly.graph_objects`` chart builders for the Vigil dashboard.

Zero ``plotly.express`` and zero Pandas conversion calls — every figure takes
plain Python lists extracted from Polars frames.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import plotly.graph_objects as go
import polars as pl

from lantana.dashboard.theme import (
    EVENT_TYPE_COLORS,
    IOC_TYPE_COLORS,
    VIGIL_LIGHT,
    apply_vigil_layout,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_STAGE_LABELS_BY_NUM: dict[int, str] = {
    1: "Scan",
    2: "Credential",
    3: "Authenticated",
    4: "Interactive",
}


def auth_donut_chart(successes: int, failures: int) -> go.Figure:
    """Success/failure donut with success rate centered inside the hole."""
    total = successes + failures
    rate = (100.0 * successes / total) if total > 0 else 0.0
    fig = go.Figure(
        data=[
            go.Pie(
                labels=["Success", "Failure"],
                values=[successes, failures],
                hole=0.62,
                marker={"colors": [VIGIL_LIGHT["tip"], VIGIL_LIGHT["important"]]},
                textinfo="label+value",
                hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>",
                sort=False,
            )
        ]
    )
    return apply_vigil_layout(
        fig,
        height=300,
        margin={"l": 12, "r": 12, "t": 12, "b": 34},
        extra={
            "annotations": [
                {
                    "text": f"<b>{rate:.1f}%</b><br><span style='font-size:0.75em'>success</span>",
                    "x": 0.5,
                    "y": 0.5,
                    "font": {"size": 22},
                    "showarrow": False,
                }
            ],
            "legend": {"orientation": "h", "y": -0.08},
            "showlegend": True,
        },
    )


def events_by_type_stacked_bar(counts: Mapping[str, int]) -> go.Figure:
    """Horizontal stacked bar across OCSF event classes."""
    total = sum(counts.values())
    fig = go.Figure()
    for label, value in counts.items():
        pct = (100.0 * value / total) if total > 0 else 0.0
        fig.add_bar(
            y=["Events"],
            x=[value],
            name=label,
            orientation="h",
            marker_color=EVENT_TYPE_COLORS.get(label, "#888888"),
            hovertemplate=f"{label}: %{{x:,}} ({pct:.1f}%)<extra></extra>",
        )
    return apply_vigil_layout(
        fig,
        height=190,
        margin={"l": 16, "r": 16, "t": 12, "b": 46},
        extra={
            "barmode": "stack",
            "legend": {"orientation": "h", "y": -0.42},
            "xaxis": {"title": "Events", "tickformat": ","},
            "yaxis": {"showticklabels": False, "title": ""},
        },
    )


def activity_trend_chart(daily_df: pl.DataFrame) -> go.Figure:
    """Multi-day activity trend: Total Events (bars) + Unique Source IPs (line)."""
    dates = [str(d) for d in daily_df.get_column("report_date").to_list()]
    events = [int(v or 0) for v in daily_df.get_column("total_events").to_list()]
    ips = (
        [int(v or 0) for v in daily_df.get_column("unique_source_ips").to_list()]
        if "unique_source_ips" in daily_df.columns
        else [0] * len(dates)
    )
    fig = go.Figure()
    fig.add_bar(
        x=dates,
        y=events,
        name="Total Events",
        marker_color=VIGIL_LIGHT["accent"],
        hovertemplate="%{x}<br>Events: %{y:,}<extra></extra>",
    )
    fig.add_scatter(
        x=dates,
        y=ips,
        name="Unique IPs",
        yaxis="y2",
        mode="lines+markers",
        line={"color": VIGIL_LIGHT["important"], "width": 2},
        marker={"size": 6},
        hovertemplate="%{x}<br>Unique IPs: %{y:,}<extra></extra>",
    )
    return apply_vigil_layout(
        fig,
        height=310,
        margin={"l": 52, "r": 52, "t": 16, "b": 46},
        extra={
            "xaxis": {"title": "Date (UTC)", "type": "category"},
            "yaxis": {"title": "Events", "tickformat": ","},
            "yaxis2": {
                "title": "Unique IPs",
                "overlaying": "y",
                "side": "right",
                "tickformat": ",",
                "showgrid": False,
            },
            "legend": {"orientation": "h", "y": -0.22},
        },
    )


def ioc_breakdown_chart(counts: Mapping[str, int]) -> go.Figure:
    """Bar chart of durable IOC counts by category."""
    labels = list(counts.keys())
    values = [int(counts[k]) for k in labels]
    colors = [IOC_TYPE_COLORS.get(k, VIGIL_LIGHT["accent"]) for k in labels]
    fig = go.Figure(
        data=[
            go.Bar(
                x=labels,
                y=values,
                marker_color=colors,
                text=[f"{v:,}" for v in values],
                textposition="outside",
                hovertemplate="%{x}: %{y:,}<extra></extra>",
            )
        ]
    )
    return apply_vigil_layout(
        fig,
        height=270,
        margin={"l": 48, "r": 18, "t": 22, "b": 42},
        extra={
            "xaxis": {"title": "IOC Type"},
            "yaxis": {"title": "Unique IOCs", "tickformat": ","},
            "showlegend": False,
        },
    )


def risk_histogram_chart(values: list[float], title: str, color: str) -> go.Figure:
    """Binned 0..100 histogram (bin width 5) for risk score decomposition."""
    fig = go.Figure(
        data=[
            go.Histogram(
                x=values,
                name=title,
                xbins={"start": 0.0, "end": 105.0, "size": 5.0},
                marker_color=color,
                hovertemplate="Score %{x}: %{y:,} IPs<extra></extra>",
            )
        ]
    )
    return apply_vigil_layout(
        fig,
        height=260,
        margin={"l": 46, "r": 14, "t": 14, "b": 42},
        extra={
            "xaxis": {"title": title, "range": [0, 105]},
            "yaxis": {"title": "IPs", "tickformat": ","},
            "bargap": 0.08,
            "showlegend": False,
        },
    )


# Simplified Natural Earth ~110m landmass outlines (lon, lat) embedded locally so
# /geography renders a crisp vector world map with ZERO external CDN/topojson XHRs
# under ``Content-Security-Policy: connect-src 'none'``.
_WORLD_LANDMASSES: tuple[tuple[list[float], list[float]], ...] = (
    # North America
    (
        [
            -168,
            -162,
            -140,
            -130,
            -124,
            -117,
            -105,
            -97,
            -87,
            -83,
            -80,
            -82,
            -80,
            -75,
            -70,
            -60,
            -55,
            -64,
            -78,
            -94,
            -112,
            -135,
            -156,
            -168,
        ],
        [
            66,
            60,
            60,
            54,
            48,
            33,
            20,
            16,
            12,
            9,
            9,
            25,
            25,
            35,
            42,
            46,
            52,
            60,
            63,
            60,
            68,
            69,
            71,
            66,
        ],
    ),
    # Greenland
    (
        [-52, -42, -22, -18, -32, -55, -60, -52],
        [60, 60, 70, 81, 83, 78, 70, 60],
    ),
    # South America
    (
        [-78, -72, -62, -50, -35, -38, -48, -55, -65, -68, -73, -76, -81, -78],
        [9, 11, 10, 1, -6, -14, -26, -35, -45, -55, -52, -38, -5, 9],
    ),
    # Europe
    (
        [-9, -2, 3, 10, 14, 22, 28, 32, 42, 48, 42, 30, 26, 20, 16, 12, 8, 2, -5, -9],
        [37, 43, 49, 54, 55, 60, 61, 68, 66, 60, 47, 46, 41, 39, 41, 44, 44, 41, 36, 37],
    ),
    # Scandinavia
    (
        [5, 8, 15, 25, 30, 28, 21, 18, 12, 5],
        [59, 63, 68, 71, 70, 65, 63, 59, 56, 59],
    ),
    # UK & Ireland
    (
        [-10, -5, -2, 2, 0, -5, -10],
        [51, 50, 51, 52, 58, 58, 51],
    ),
    # Africa
    (
        [-17, -6, 10, 25, 33, 39, 43, 51, 49, 41, 36, 32, 20, 15, 12, 9, 2, -8, -17],
        [15, 35, 37, 32, 31, 21, 12, 11, 4, -2, -16, -26, -35, -26, -15, -4, 5, 5, 15],
    ),
    # Madagascar
    (
        [44, 47, 50, 49, 45, 44],
        [-25, -25, -15, -12, -18, -25],
    ),
    # Asia (mainland)
    (
        [
            27,
            36,
            44,
            56,
            66,
            72,
            77,
            81,
            88,
            97,
            103,
            109,
            121,
            129,
            136,
            142,
            160,
            178,
            160,
            130,
            105,
            80,
            60,
            48,
            40,
            27,
        ],
        [
            40,
            36,
            13,
            22,
            25,
            20,
            8,
            16,
            22,
            16,
            2,
            12,
            24,
            35,
            44,
            54,
            62,
            66,
            70,
            72,
            75,
            73,
            70,
            60,
            45,
            40,
        ],
    ),
    # Japan
    (
        [130, 136, 141, 145, 142, 137, 130],
        [31, 34, 38, 44, 43, 37, 31],
    ),
    # Indonesia / Maritime SE Asia
    (
        [96, 106, 116, 128, 138, 140, 126, 114, 104, 96],
        [5, -6, -8, -7, -8, -4, 1, 2, -1, 5],
    ),
    # Australia
    (
        [114, 122, 130, 137, 142, 149, 153, 150, 141, 136, 129, 115, 114],
        [-22, -18, -12, -15, -11, -21, -28, -37, -38, -35, -32, -34, -22],
    ),
    # New Zealand
    (
        [167, 172, 178, 174, 167],
        [-46, -43, -37, -36, -46],
    ),
)


def world_map_chart(ip_df: pl.DataFrame) -> go.Figure:
    """Air-gapped equirectangular world scatter map (zero external topojson/CDN requests)."""
    geo_df = ip_df.filter(
        pl.col("geo_latitude").is_not_null() & pl.col("geo_longitude").is_not_null()
    )
    if geo_df.is_empty():
        return apply_vigil_layout(go.Figure(), height=380)

    if geo_df.height > 800:
        geo_df = geo_df.sort("risk_score", descending=True).head(800)

    lats: list[float] = []
    lons: list[float] = []
    sizes: list[float] = []
    scores: list[float] = []
    hover: list[str] = []

    for row in geo_df.iter_rows(named=True):
        lats.append(float(row["geo_latitude"]))
        lons.append(float(row["geo_longitude"]))
        ev = int(row.get("total_events") or 0)
        sizes.append(max(6.0, min(22.0, 5.0 + math.log10(ev + 1) * 5.0)))
        score = float(row.get("risk_score") or 0.0)
        scores.append(score)
        city = row.get("geo_city") or "Unknown"
        country = row.get("geo_country") or "??"
        hover.append(
            f"<b>{row['src_endpoint_ip']}</b><br>"
            f"{city}, {country}<br>"
            f"Risk: {score:.1f} · Events: {ev:,}"
        )

    traces: list[go.Scatter] = [
        go.Scatter(
            x=poly_lon,
            y=poly_lat,
            mode="lines",
            fill="toself",
            fillcolor=VIGIL_LIGHT["geo_land"],
            line={"color": VIGIL_LIGHT["geo_border"], "width": 0.9},
            hoverinfo="skip",
            showlegend=False,
            meta="world-land",
        )
        for poly_lon, poly_lat in _WORLD_LANDMASSES
    ]
    traces.append(
        go.Scatter(
            x=lons,
            y=lats,
            mode="markers",
            text=hover,
            hovertemplate="%{text}<extra></extra>",
            showlegend=False,
            marker={
                "size": sizes,
                "color": scores,
                "colorscale": "Plasma",
                "cmin": 0,
                "cmax": 100,
                "opacity": 0.85,
                "line": {"width": 0.6, "color": VIGIL_LIGHT["bg"]},
                "colorbar": {"title": "Risk"},
            },
        )
    )

    fig = go.Figure(data=traces)
    return apply_vigil_layout(
        fig,
        height=440,
        margin={"l": 6, "r": 6, "t": 8, "b": 8},
        extra={
            "plot_bgcolor": VIGIL_LIGHT["geo_ocean"],
            "xaxis": {
                "range": [-180, 180],
                "showgrid": True,
                "gridcolor": VIGIL_LIGHT["grid"],
                "zeroline": False,
                "showticklabels": False,
                "fixedrange": False,
            },
            "yaxis": {
                "range": [-60, 84],
                "scaleanchor": "x",
                "scaleratio": 1.0,
                "showgrid": True,
                "gridcolor": VIGIL_LIGHT["grid"],
                "zeroline": False,
                "showticklabels": False,
                "fixedrange": False,
            },
            "meta": "world-map",
        },
    )


def top_countries_bar_chart(countries_df: pl.DataFrame) -> go.Figure:
    """Vertical bar chart of top countries by unique attacker IPs."""
    if countries_df.is_empty():
        return apply_vigil_layout(go.Figure(), height=260)
    countries = [str(c) for c in countries_df.get_column("Country").to_list()]
    ips = [int(v) for v in countries_df.get_column("Unique IPs").to_list()]
    fig = go.Figure(
        data=[
            go.Bar(
                x=countries,
                y=ips,
                marker_color=VIGIL_LIGHT["accent"],
                hovertemplate="%{x}: %{y:,} unique IPs<extra></extra>",
            )
        ]
    )
    return apply_vigil_layout(
        fig,
        height=270,
        margin={"l": 46, "r": 14, "t": 14, "b": 40},
        extra={
            "xaxis": {"title": "Country"},
            "yaxis": {"title": "Unique IPs", "tickformat": ","},
            "showlegend": False,
        },
    )


def stage_scatter_chart(prog_df: pl.DataFrame) -> go.Figure:
    """Scatter plot of per-IP max_stage vs first_seen, split by Automated vs Manual."""
    fig = go.Figure()
    if prog_df.is_empty() or "first_seen" not in prog_df.columns:
        return apply_vigil_layout(fig, height=360)

    for is_auto, label, color in (
        (True, "Automated", VIGIL_LIGHT["important"]),
        (False, "Manual / Unknown", VIGIL_LIGHT["accent"]),
    ):
        subset = prog_df.filter(pl.col("is_automated").fill_null(False) == is_auto)
        if subset.is_empty():
            continue
        xs: list[str] = []
        ys: list[str] = []
        texts: list[str] = []
        for row in subset.iter_rows(named=True):
            xs.append(str(row["first_seen"]))
            stage_num = int(row.get("max_stage") or 1)
            ys.append(_STAGE_LABELS_BY_NUM.get(stage_num, str(stage_num)))
            total_ev = (
                int(row.get("scan_events") or 0)
                + int(row.get("auth_attempts") or 0)
                + int(row.get("commands_executed") or 0)
            )
            texts.append(
                f"<b>{row['src_endpoint_ip']}</b><br>"
                f"Stage: {row.get('stage_label', '')}<br>"
                f"Events: {total_ev:,}"
            )
        fig.add_trace(
            go.Scatter(
                x=xs,
                y=ys,
                mode="markers",
                name=label,
                marker={"size": 7, "opacity": 0.72, "color": color},
                hovertext=texts,
                hovertemplate="%{hovertext}<br>First seen: %{x}<extra></extra>",
            )
        )

    return apply_vigil_layout(
        fig,
        height=370,
        margin={"l": 100, "r": 18, "t": 14, "b": 46},
        extra={
            "xaxis": {"title": "First seen (UTC)"},
            "yaxis": {
                "title": "Max stage",
                "categoryorder": "array",
                "categoryarray": ["Scan", "Credential", "Authenticated", "Interactive"],
            },
            "legend": {"orientation": "h", "y": -0.2},
        },
    )


def velocity_histogram_chart(days_values: list[int]) -> go.Figure:
    """Histogram of progression_velocity_days (> 0) across multi-day attackers."""
    fig = go.Figure(
        data=[
            go.Histogram(
                x=days_values,
                nbinsx=max(max(days_values, default=1), 2),
                marker_color=VIGIL_LIGHT["caution"],
                hovertemplate="Days %{x}: %{y:,} IPs<extra></extra>",
            )
        ]
    )
    return apply_vigil_layout(
        fig,
        height=300,
        margin={"l": 46, "r": 16, "t": 14, "b": 42},
        extra={
            "xaxis": {"title": "Days to max stage", "dtick": 1},
            "yaxis": {"title": "IPs", "tickformat": ","},
            "bargap": 0.1,
            "showlegend": False,
        },
    )


def top_rules_bar_chart(findings_df: pl.DataFrame, *, ip_label: str = "Unique IPs") -> go.Figure:
    """Horizontal bar of top-20 Suricata rules with full titles and SID hover."""
    top = findings_df.sort("event_count", descending=True).head(20)
    if top.is_empty():
        return apply_vigil_layout(go.Figure(), height=320)

    titles = [str(t) for t in top.get_column("finding_title").to_list()]
    counts = [int(c) for c in top.get_column("event_count").to_list()]
    ips = [int(u) for u in top.get_column("unique_ips").to_list()]
    uids = (
        [str(u or "—") for u in top.get_column("finding_uid").to_list()]
        if "finding_uid" in top.columns
        else ["—"] * len(titles)
    )
    hover = [
        f"<b>{t}</b><br>SID: {uid}<br>Events: {c:,}<br>{ip_label}: {u:,}"
        for t, uid, c, u in zip(titles, uids, counts, ips, strict=False)
    ]

    fig = go.Figure(
        data=[
            go.Bar(
                x=counts,
                y=titles,
                orientation="h",
                marker={
                    "color": ips,
                    "colorscale": "Reds",
                    "colorbar": {"title": ip_label},
                },
                hovertext=hover,
                hovertemplate="%{hovertext}<extra></extra>",
            )
        ]
    )
    return apply_vigil_layout(
        fig,
        height=max(360, 28 * len(titles)),
        margin={"l": 16, "r": 20, "t": 14, "b": 42},
        extra={
            "xaxis": {"title": "Events", "tickformat": ","},
            "yaxis": {"automargin": True, "autorange": "reversed", "title": ""},
        },
    )


def pareto_concentration_chart(findings_df: pl.DataFrame) -> go.Figure:
    """Pareto chart: event count bars + cumulative % curve + 80% threshold line."""
    sorted_df = findings_df.sort("event_count", descending=True).head(50)
    if sorted_df.is_empty():
        return apply_vigil_layout(go.Figure(), height=340)

    counts = [int(c) for c in sorted_df.get_column("event_count").to_list()]
    titles = [str(t) for t in sorted_df.get_column("finding_title").to_list()]
    total = sum(counts)
    cum_pct: list[float] = []
    running = 0
    for c in counts:
        running += c
        cum_pct.append(100.0 * running / total if total > 0 else 0.0)
    ranks = list(range(1, len(counts) + 1))

    fig = go.Figure()
    fig.add_bar(
        x=ranks,
        y=counts,
        name="Events",
        marker_color=VIGIL_LIGHT["important"],
        customdata=titles,
        hovertemplate="Rank %{x}<br>%{customdata}<br>Events: %{y:,}<extra></extra>",
    )
    fig.add_scatter(
        x=ranks,
        y=cum_pct,
        name="Cumulative %",
        yaxis="y2",
        mode="lines+markers",
        line={"color": VIGIL_LIGHT["accent"], "width": 2},
        hovertemplate="Rank %{x}<br>Cumulative: %{y:.1f}%<extra></extra>",
    )
    fig.add_hline(
        y=80,
        line_dash="dash",
        line_color=VIGIL_LIGHT["muted"],
        yref="y2",
        annotation_text="80%",
        annotation_position="top right",
    )
    return apply_vigil_layout(
        fig,
        height=360,
        margin={"l": 50, "r": 50, "t": 16, "b": 46},
        extra={
            "xaxis": {"title": "Rule rank (sorted by event count)", "dtick": 5},
            "yaxis": {"title": "Events", "tickformat": ","},
            "yaxis2": {
                "title": "Cumulative %",
                "overlaying": "y",
                "side": "right",
                "range": [0, 105],
                "showgrid": False,
            },
            "legend": {"orientation": "h", "y": -0.22},
        },
    )


def stix_composition_chart(composition: Mapping[str, int]) -> go.Figure:
    """Bar chart summarizing STIX 2.1 bundle objects before download."""
    mapping = [
        ("Inbound IPs (7d)", composition.get("inbound_ips", 0), VIGIL_LIGHT["important"]),
        ("Malware Hashes", composition.get("malware_hashes", 0), "#6f42c1"),
        ("Outbound C2 IPs", composition.get("c2_ips", 0), VIGIL_LIGHT["caution"]),
        ("Stager URLs", composition.get("stager_urls", 0), VIGIL_LIGHT["warning"]),
        ("Stager Domains", composition.get("stager_domains", 0), VIGIL_LIGHT["accent"]),
        ("SSH Keys", composition.get("ssh_keys", 0), VIGIL_LIGHT["tip"]),
        ("Campaigns", composition.get("campaigns", 0), VIGIL_LIGHT["muted"]),
    ]
    labels = [m[0] for m in mapping]
    values = [m[1] for m in mapping]
    colors = [m[2] for m in mapping]
    fig = go.Figure(
        data=[
            go.Bar(
                x=labels,
                y=values,
                marker_color=colors,
                text=[f"{v:,}" for v in values],
                textposition="outside",
                hovertemplate="%{x}: %{y:,}<extra></extra>",
            )
        ]
    )
    return apply_vigil_layout(
        fig,
        height=300,
        margin={"l": 46, "r": 16, "t": 22, "b": 52},
        extra={
            "xaxis": {"title": "STIX 2.1 Object Category"},
            "yaxis": {"title": "Count", "tickformat": ","},
            "showlegend": False,
        },
    )

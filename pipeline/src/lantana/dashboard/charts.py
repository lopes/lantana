"""Pure ``plotly.graph_objects`` chart builders for the Vigil dashboard.

Zero ``plotly.express`` and zero ``.to_pandas()`` calls — every figure takes
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


def world_map_chart(ip_df: pl.DataFrame) -> go.Figure:
    """Natural Earth scatter_geo plot of attacker IPs sized by log10(events+1)."""
    geo_df = ip_df.filter(
        pl.col("geo_latitude").is_not_null() & pl.col("geo_longitude").is_not_null()
    )
    if geo_df.is_empty():
        return apply_vigil_layout(go.Figure(), height=380)

    lats: list[float] = []
    lons: list[float] = []
    sizes: list[float] = []
    scores: list[float] = []
    hover: list[str] = []

    for row in geo_df.iter_rows(named=True):
        lats.append(float(row["geo_latitude"]))
        lons.append(float(row["geo_longitude"]))
        ev = int(row.get("total_events") or 0)
        sizes.append(max(5.0, min(22.0, 4.5 + math.log10(ev + 1) * 5.0)))
        score = float(row.get("risk_score") or 0.0)
        scores.append(score)
        city = row.get("geo_city") or "Unknown"
        country = row.get("geo_country") or "??"
        hover.append(
            f"<b>{row['src_endpoint_ip']}</b><br>"
            f"{city}, {country}<br>"
            f"Risk: {score:.1f} · Events: {ev:,}"
        )

    fig = go.Figure(
        data=[
            go.Scattergeo(
                lat=lats,
                lon=lons,
                mode="markers",
                text=hover,
                hovertemplate="%{text}<extra></extra>",
                marker={
                    "size": sizes,
                    "color": scores,
                    "colorscale": "Plasma",
                    "cmin": 0,
                    "cmax": 100,
                    "opacity": 0.82,
                    "line": {"width": 0.5, "color": VIGIL_LIGHT["bg"]},
                    "colorbar": {"title": "Risk"},
                },
            )
        ]
    )
    fig.update_geos(
        projection_type="natural earth",
        resolution=50,
        showcountries=True,
        countrycolor=VIGIL_LIGHT["geo_border"],
        showland=True,
        landcolor=VIGIL_LIGHT["geo_land"],
        showocean=True,
        oceancolor=VIGIL_LIGHT["geo_ocean"],
        showcoastlines=True,
        coastlinecolor=VIGIL_LIGHT["geo_border"],
        showframe=False,
        bgcolor="rgba(0,0,0,0)",
    )
    return apply_vigil_layout(
        fig,
        height=440,
        margin={"l": 0, "r": 0, "t": 8, "b": 8},
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

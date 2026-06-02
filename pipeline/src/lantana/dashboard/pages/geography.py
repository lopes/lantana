"""Geography page — world map and geographic analysis tables."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import plotly.express as px
import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table
from lantana.notify.explanations import BRIEF_SECTIONS


def _section_caption(name: str) -> str | None:
    triplet = BRIEF_SECTIONS.get(name)
    return triplet.tooltip() if triplet is not None else None


def render(selected_date: date) -> None:
    """Render the geography page for the selected date."""
    st.header(f"Geography — {selected_date.isoformat()}")
    page_caption = _section_caption("Geographic Origin")
    if page_caption:
        st.caption(page_caption)

    df = read_gold_table("ip_reputation", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    # World map — one marker per attacker IP, sized by log10(events) so a
    # single chatty IP doesn't drown out the rest. Country borders + dark
    # theme colors match the Streamlit dark theme.
    geo_df = df.filter(
        pl.col("geo_latitude").is_not_null() & pl.col("geo_longitude").is_not_null()
    ).with_columns(
        (pl.col("total_events").cast(pl.Float64) + 1).log10().alias("_marker_scale"),
    )

    if not geo_df.is_empty():
        map_caption = _section_caption("World Map")
        if map_caption:
            st.caption(map_caption)
        fig = px.scatter_geo(
            geo_df.to_pandas(),
            lat="geo_latitude",
            lon="geo_longitude",
            size="_marker_scale",
            size_max=22,
            color="risk_score",
            color_continuous_scale="Plasma",
            range_color=(0, 100),
            hover_name="src_endpoint_ip",
            hover_data={
                "geo_country": True,
                "geo_city": True,
                "risk_score": ":.0f",
                "total_events": ":,",
                "_marker_scale": False,
                "geo_latitude": False,
                "geo_longitude": False,
            },
            projection="natural earth",
        )
        fig.update_geos(
            resolution=50,
            showcountries=True,
            countrycolor="#3D4044",
            showland=True,
            landcolor="#262730",
            showocean=True,
            oceancolor="#0E1117",
            showcoastlines=True,
            coastlinecolor="#3D4044",
            showframe=False,
            bgcolor="rgba(0,0,0,0)",
        )
        fig.update_traces(marker={"sizemin": 4, "line": {"width": 0.5, "color": "#0E1117"}})
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin={"l": 0, "r": 0, "t": 10, "b": 0},
            height=500,
            coloraxis_colorbar={
                "title": {"text": "Risk", "font": {"color": "#aaa"}},
                "tickfont": {"color": "#aaa"},
            },
        )
        st.plotly_chart(fig, width="stretch")

    st.divider()

    # Two-column layout: Top Countries + Top Cities
    country_col, city_col = st.columns(2)

    with country_col:
        st.subheader("Top Countries")
        countries_caption = _section_caption("Top Countries")
        if countries_caption:
            st.caption(countries_caption)
        countries = (
            df.filter(pl.col("geo_country").is_not_null())
            .group_by("geo_country")
            .agg(
                pl.col("src_endpoint_ip").n_unique().alias("Unique IPs"),
                pl.col("total_events").sum().alias("Total Events"),
            )
            .sort("Unique IPs", descending=True)
            .head(10)
            .rename({"geo_country": "Country"})
            .with_row_index("Rank", offset=1)
        )
        st.dataframe(countries.to_pandas(), hide_index=True, width="stretch")
        st.bar_chart(countries.to_pandas(), x="Country", y="Unique IPs")

    with city_col:
        st.subheader("Top Cities")
        cities_caption = _section_caption("Top Cities")
        if cities_caption:
            st.caption(cities_caption)
        cities = (
            df.filter(pl.col("geo_city").is_not_null() & pl.col("geo_country").is_not_null())
            .group_by("geo_city", "geo_country")
            .agg(
                pl.col("src_endpoint_ip").n_unique().alias("Unique IPs"),
            )
            .sort("Unique IPs", descending=True)
            .head(10)
            .rename({"geo_city": "City", "geo_country": "Country"})
            .with_row_index("Rank", offset=1)
        )
        st.dataframe(cities.to_pandas(), hide_index=True, width="stretch")

    st.divider()

    # Top ASNs/ISPs
    st.subheader("Top ASNs / ISPs")
    asn_caption = _section_caption("Top ASNs")
    if asn_caption:
        st.caption(asn_caption)
    asns = (
        df.filter(pl.col("geo_asn").is_not_null() & pl.col("geo_isp").is_not_null())
        .group_by("geo_asn", "geo_isp")
        .agg(
            pl.col("src_endpoint_ip").n_unique().alias("Unique IPs"),
            pl.col("total_events").sum().alias("Events"),
        )
        .sort("Unique IPs", descending=True)
        .head(10)
        .rename({"geo_asn": "ASN", "geo_isp": "ISP"})
        .with_row_index("Rank", offset=1)
    )
    st.dataframe(asns.to_pandas(), hide_index=True, width="stretch")

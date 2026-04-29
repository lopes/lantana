"""Geography page — world map and geographic analysis tables."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import plotly.express as px
import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table


def render(selected_date: date) -> None:
    """Render the geography page for the selected date."""
    st.header(f"Geography — {selected_date.isoformat()}")

    df = read_gold_table("ip_reputation", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    # World map
    geo_df = df.filter(
        pl.col("geo_latitude").is_not_null() & pl.col("geo_longitude").is_not_null()
    )

    if not geo_df.is_empty():
        fig = px.scatter_geo(
            geo_df.to_pandas(),
            lat="geo_latitude",
            lon="geo_longitude",
            size="total_events",
            color="risk_score",
            color_continuous_scale="YlOrRd",
            hover_name="src_endpoint_ip",
            hover_data=["geo_country", "geo_city", "risk_score", "total_events"],
            projection="natural earth",
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # Two-column layout: Top Countries + Top Cities
    country_col, city_col = st.columns(2)

    with country_col:
        st.subheader("Top Countries")
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
        )
        st.dataframe(countries.to_pandas(), hide_index=True, use_container_width=True)
        st.bar_chart(countries.to_pandas(), x="Country", y="Unique IPs")

    with city_col:
        st.subheader("Top Cities")
        cities = (
            df.filter(
                pl.col("geo_city").is_not_null() & pl.col("geo_country").is_not_null()
            )
            .group_by("geo_city", "geo_country")
            .agg(
                pl.col("src_endpoint_ip").n_unique().alias("Unique IPs"),
            )
            .sort("Unique IPs", descending=True)
            .head(10)
            .rename({"geo_city": "City", "geo_country": "Country"})
        )
        st.dataframe(cities.to_pandas(), hide_index=True, use_container_width=True)

    st.divider()

    # Top ASNs/ISPs
    st.subheader("Top ASNs / ISPs")
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
    )
    st.dataframe(asns.to_pandas(), hide_index=True, use_container_width=True)

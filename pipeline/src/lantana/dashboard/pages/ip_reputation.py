"""IP Reputation page — composite risk_score, decomposition, and table."""

from __future__ import annotations

from datetime import date  # noqa: TC003 — runtime parameter type

import polars as pl
import streamlit as st

from lantana.common.datalake import read_gold_table
from lantana.intel.stix import RISK_HIGH_THRESHOLD, RISK_THRESHOLD
from lantana.notify.explanations import BRIEF_SECTIONS, METRICS

# Long-form risk_score explainer rendered inside an st.expander. The
# canonical reference is ``docs/risk-scoring.md`` — this block is the
# scannable summary an analyst needs without leaving the dashboard.
# Threshold values come from ``intel/stix.py`` so the docstring table,
# ``_risk_label``, and the bucket filters in ``render`` can't drift.
_HIGH: int = int(RISK_HIGH_THRESHOLD)
_MED: int = int(RISK_THRESHOLD)
_RISK_FORMULA_MD: str = f"""
**Scale:** 0-100, higher = worse. The same number drives the STIX
indicator gate, Discord top-N sorting, and the dashboard buckets.

**Risk levels** (used by the metric cards below):

| Level | Threshold | Meaning |
|-------|-----------|---------|
| High | >= {_HIGH} | Pageable; drives Discord top-N and OpenCTI feed |
| Medium | {_MED} - {_HIGH} | At/above STIX Indicator threshold ({_MED}), worth review |
| Low | < {_MED} | Typically scanner noise or behavioral-only signal |

**Formula** (`pipeline/src/lantana/transform/metrics.py`):

```
risk_score = (enrichment_risk_score.fill_null(0) + behavioral_risk_score) / 2
           clipped to [0, 100]

enrichment_risk_score  = mean( abuseipdb_risk_score,
                               virustotal_risk_score,
                               shodan_risk_score,
                               greynoise_risk_score )
                         # only populated providers; nulls skipped

behavioral_risk_score  = honeypot activity (auth pressure + commands run
                         + downloads triggered + Suricata findings)
```

**GreyNoise RIOT override.** When an IP sits on GreyNoise's
Rule-It-Out list (known-benign infrastructure — CDNs, NTP, public
DNS), `greynoise_risk_score = 0` pulls the enrichment mean down. The
row stays in silver with full enrichment context; only the score is
overridden. This is the *only* place in the formula where one signal
can subtract from another.

**STIX gate.** IPs with `risk_score >= {_MED}` become STIX 2.1 Indicators
in the daily bundle (`intel/stix.py:RISK_THRESHOLD`).

Full per-provider formulas, worked examples, and the FAQ live in
[`docs/risk-scoring.md`](https://github.com/lopes/lantana/blob/main/docs/risk-scoring.md).
"""


def _metric_help(name: str) -> str | None:
    triplet = METRICS.get(name)
    return triplet.tooltip() if triplet is not None else None


def _section_caption(name: str) -> str | None:
    triplet = BRIEF_SECTIONS.get(name)
    return triplet.tooltip() if triplet is not None else None


def _risk_label(score: float) -> str:
    """Map composite risk score to High / Medium / Low using the same
    thresholds that drive the bucket filters and the explainer table."""
    if score >= RISK_HIGH_THRESHOLD:
        return "High"
    if score >= RISK_THRESHOLD:
        return "Medium"
    return "Low"


def render(selected_date: date) -> None:
    """Render the IP reputation page for the selected date."""
    st.header(f"IP Reputation — {selected_date.isoformat()}")
    page_caption = _section_caption("Top Attackers")
    if page_caption:
        st.caption(page_caption)

    with st.expander("How risk_score is calculated", expanded=False):
        st.markdown(_RISK_FORMULA_MD)

    df = read_gold_table("ip_reputation", selected_date)
    if df.is_empty():
        st.info("No data available for this date.")
        return

    # Summary metrics — bucket counts mirror the thresholds in the
    # _RISK_FORMULA_MD table.
    cols = st.columns(4)
    cols[0].metric(
        "Total IPs", len(df),
        help=_metric_help("Total Scored IPs"),
    )
    high = df.filter(pl.col("risk_score") >= RISK_HIGH_THRESHOLD).height
    med = df.filter(
        (pl.col("risk_score") >= RISK_THRESHOLD)
        & (pl.col("risk_score") < RISK_HIGH_THRESHOLD)
    ).height
    low = df.filter(pl.col("risk_score") < RISK_THRESHOLD).height
    cols[1].metric("High Risk", high, help=_metric_help("High Risk IPs"))
    cols[2].metric("Medium Risk", med, help=_metric_help("Medium Risk IPs"))
    cols[3].metric("Low Risk", low, help=_metric_help("Low Risk IPs"))

    st.divider()

    # Risk distribution — composite + Phase D.2 decomposition side-by-side.
    st.subheader("Risk Score Distribution")
    dist_caption = _section_caption("Risk Score Distribution")
    if dist_caption:
        st.caption(dist_caption)
    if "enrichment_risk_score" in df.columns and "behavioral_risk_score" in df.columns:
        chart_cols = st.columns(3)
        chart_cols[0].caption("Composite (final risk_score)")
        chart_cols[0].bar_chart(df.select("risk_score").to_pandas(), y="risk_score")
        chart_cols[1].caption("Enrichment half (mean of populated providers)")
        chart_cols[1].bar_chart(
            df.select("enrichment_risk_score").to_pandas(), y="enrichment_risk_score",
        )
        chart_cols[2].caption("Behavioral half (auth + commands + downloads + findings)")
        chart_cols[2].bar_chart(
            df.select("behavioral_risk_score").to_pandas(), y="behavioral_risk_score",
        )
    else:
        # Pre-Phase-D.2 gold partition fallback.
        st.bar_chart(df.select("risk_score").to_pandas(), y="risk_score")

    st.divider()

    # IP table with risk labels
    st.subheader("IP Details")
    st.caption(
        "Per-IP enrichment row from gold. Use the slider to focus on a "
        "risk band; the per-provider sub-scores (`*_risk_score`) make the "
        "composite traceable."
    )

    display_df = df.with_columns(
        pl.col("risk_score").map_elements(_risk_label, return_dtype=pl.Utf8).alias("risk_level"),
    )

    display_cols = [
        "src_endpoint_ip",
        "risk_score",
        "risk_level",
        "enrichment_risk_score",
        "behavioral_risk_score",
        "abuseipdb_risk_score",
        "virustotal_risk_score",
        "shodan_risk_score",
        "greynoise_risk_score",
        "total_events",
        "geo_country",
        "geo_city",
        "auth_attempts",
        "auth_successes",
        "commands_executed",
        "findings_triggered",
        "abuseipdb_score",
        "abuseipdb_reports",
        "greynoise_class",
        "greynoise_name",
        "greynoise_riot",
        "vt_malicious",
        "shodan_ports",
        "shodan_os",
        "shodan_vulns",
        "shodan_org",
    ]
    available_cols = [c for c in display_cols if c in display_df.columns]

    min_risk = st.slider(
        "Minimum risk score",
        0, 100, 0,
        help=(
            f"Filter the table below to IPs with risk_score ≥ this value. "
            f"Default 0 shows everything; set to {int(RISK_THRESHOLD)} "
            "to mirror the STIX Indicator gate."
        ),
    )
    filtered = display_df.filter(pl.col("risk_score") >= min_risk)

    st.dataframe(
        filtered.select(available_cols).to_pandas(),
        hide_index=True,
        width="stretch",
    )

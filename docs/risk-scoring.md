# Risk score composition

This document is the analyst's reference for how Lantana derives `risk_score` for every source IP in the gold layer. Open it when you're staring at a Discord brief or a dashboard row and wondering *why this IP got this score*.

> **Context:** the per-provider sub-scores below land in silver during the enrichment step described in [`pipeline.md`](pipeline.md), populated from the third-party APIs documented in [`integrations.md`](integrations.md). The gold composite (`risk_score`) is the single number consumed by STIX export, the Discord brief, and the dashboard.

## TL;DR

Three numbers per IP, all on the same 0–100 scale:

- **`enrichment_risk_score`** — mean of the per-provider scores that landed for this IP (AbuseIPDB, VirusTotal, Shodan, GreyNoise). Null if no provider contributed.
- **`behavioral_risk_score`** — what the IP actually did on the honeypot (auth attempts, command execution, malware downloads, IDS findings).
- **`risk_score`** — the single composite that drives STIX export, dashboard buckets, and Discord top-5 sorting. Defined as `(enrichment.fill_null(0) + behavioral) / 2`, clipped to 0–100.

Plus four per-provider sub-scores (`abuseipdb_risk_score`, `virustotal_risk_score`, `shodan_risk_score`, `greynoise_risk_score`), each 0–100 or null, so the decomposition is fully traceable down to the source.

## Architecture

```
                ┌──────────────────────────┐
                │  Per-provider enrichment │
   silver       │                          │
   (per-event,  │  abuseipdb_risk_score    │ ← computed by each provider
    one row     │  virustotal_risk_score   │   from its own raw response;
    per         │  shodan_risk_score       │   joined onto every event for
    log line)   │  greynoise_risk_score    │   that source IP via the
                │  (each Float64, 0..100,  │   existing _build_lookup +
                │   nullable)              │   _merge_lookup path.
                └──────────────────────────┘
                          │
                          ▼  (group_by src_endpoint_ip in compute_ip_reputation)
                ┌──────────────────────────────────────┐
   gold         │  enrichment_risk_score = mean of     │
   (per-IP      │     populated per-provider scores    │
    aggregates) │     (null if all four are null)      │
                │                                      │
                │  behavioral_risk_score = honeypot    │
                │     activity signal (auth + commands │
                │      + downloads + findings + atts)  │
                │                                      │
                │  risk_score = mean(enrichment,       │
                │                    behavioral)       │
                │     ← THE single number STIX gate,   │
                │       dashboard buckets, and the     │
                │       Discord report all keep using. │
                └──────────────────────────────────────┘
```

## Per-provider formulas

Each provider's score lives in `pipeline/src/lantana/enrichment/providers/<name>.py:compute_risk_score`. Tests are in `pipeline/tests/test_enrichment/test_<name>.py`.

### AbuseIPDB

```
abuseipdb_risk_score = abuseConfidenceScore  (clamped to 0..100)
```

AbuseIPDB's confidence score is already calibrated to community reporting density on a 0–100 scale, so we pass it through.

| Raw `abuseConfidenceScore` | `abuseipdb_risk_score` |
|---|---|
| 0 | 0.0 |
| 50 | 50.0 |
| 100 | 100.0 |

### VirusTotal (IP)

Bucketed by `last_analysis_stats.malicious` (the engine count):

| `malicious` count | `virustotal_risk_score` | Why this break |
|---|---|---|
| 0 | 0.0 | Clean or not seen |
| 1–2 | 25.0 | Often single-engine noise / false positive |
| 3–5 | 50.0 | Multi-source agreement starts here |
| 6–10 | 75.0 | Broadly flagged |
| >10 | 100.0 | Heavily flagged; uncommon outside known C2 |

Module constant: `VT_IP_RISK_BUCKETS` in `enrichment/providers/virustotal.py`.

### VirusTotal (file hash)

Bucketed by `last_analysis_stats.malicious` on the file endpoint:

| `malicious` count | `vt_file_risk_score` | Why this break |
|---|---|---|
| 0 | 0.0 | Clean / never analysed |
| 1 | 50.0 | Single engine flagging — crosses the cache "malicious" threshold |
| 2–4 | 75.0 | Multi-source agreement |
| ≥5 | 100.0 | Broadly flagged malware |

Module constant: `VT_FILE_RISK_BUCKETS` in `enrichment/providers/virustotal.py`.

The thresholds are tighter than the IP buckets because file-scan FP rates are much lower — a single AV engine flagging a SHA256 is a much stronger signal than a single engine flagging an IP. This score is consumed by the cache classifier (`_classify_ttl` in `enrichment/runner.py`) to assign the 180-day malicious-hash TTL but is **not** part of the IP-side composite blend documented below.

### Shodan

Tri-state from `ports` and `vulns`:

| `vulns` populated? | `ports` populated? | `shodan_risk_score` |
|---|---|---|
| Yes | (any) | 100.0 |
| No | Yes | 25.0 |
| No | No | 0.0 |

A known CVE on the IP is the strongest single Shodan datum: it implies exposed AND scanned AND vulnerable in one fact. Ports without CVEs is a weaker but still real signal (exposed surface). Both empty means Shodan responded but had no scan data — residential / cloud IPs Shodan hasn't indexed.

### GreyNoise (the only provider with a negative override)

| Condition | `greynoise_risk_score` |
|---|---|
| `riot == True` (Rule-It-Out: known-benign infrastructure) | **0.0 (overrides everything else)** |
| `classification == "malicious"` | 75.0 |
| `classification == "benign"` | 0.0 |
| `noise == True` and `classification == "unknown"` | 25.0 |
| `classification == "unknown"`, noise unknown | 10.0 |

**Why RIOT subtracts.** GreyNoise's two flags sound similar but mean opposite things:

- `noise=True` — IP is part of internet-wide background scanning. Could be a malicious botnet, could be legitimate research infrastructure (Censys, Shadowserver, Shodan itself). Ambiguous.
- `riot=True` — IP is on the **Rule-It-Out** list. GreyNoise has *explicitly tagged it as known-benign infrastructure*: CDNs, NTP servers, DNS resolvers, software update endpoints, etc.

When RIOT fires, the IP is benign infrastructure by GreyNoise's verdict. The score drops to 0 to pull the composite down — but the row stays in silver with all enrichment intact. An analyst can still see what the other providers said; they just have one strong "this is probably benign" signal to weigh against them.

## Gold composite

In `pipeline/src/lantana/transform/metrics.py:compute_ip_reputation`:

```python
enrichment_risk_score = pl.mean_horizontal(
    abuseipdb_risk_score,
    virustotal_risk_score,
    shodan_risk_score,
    greynoise_risk_score,
).clip(0, 100)   # null if all four inputs are null

behavioral_risk_score = (
      20.0 if auth_successes > 0     else 0.0
    + 25.0 if commands_executed > 0  else 0.0
    + 15.0 if findings_triggered > 0 else 0.0
    + 20.0 if downloads > 0          else 0.0
    + min(auth_attempts, 100) * 0.1            # max +10
).clip(0, 100)

risk_score = ((enrichment_risk_score.fill_null(0.0) + behavioral_risk_score) / 2.0).clip(0, 100)
```

The `fill_null(0)` on the enrichment side is deliberate: an IP with zero enrichment data still gets behavioral risk attributed, just halved by the missing intel side. Said another way — a known-bad IP that hit interactive shell scores higher than an unknown IP that hit interactive shell, which is the right risk ordering.

## Downstream consumers

The threshold values live as module-level constants in [`intel/stix.py`](../pipeline/src/lantana/intel/stix.py) — `RISK_THRESHOLD = 40.0` (STIX indicator gate, also the dashboard's Medium-bucket floor) and `RISK_HIGH_THRESHOLD = 70.0` (dashboard's High bucket). Every consumer below imports those constants rather than hardcoding the numbers, so a future re-tune is a single edit.

| Consumer | Field read | Threshold / behaviour |
|---|---|---|
| `intel/stix.py:_make_indicators` | `risk_score >= RISK_THRESHOLD` | Gate for STIX Indicator emission. Pre-Phase-D.2 calibration; subject to re-tuning once we see the new distribution. |
| `intel/stix.py:_make_indicators` | `risk_score` | STIX `confidence` field = `min(int(risk_score), 100)`. |
| `dashboard/pages/ip_reputation.py:_risk_label` + bucket counts | `risk_score` | High (`>= RISK_HIGH_THRESHOLD`) / Medium (`>= RISK_THRESHOLD`) / Low buckets. Explainer expander on the page documents the formula and links back here. |
| `dashboard/pages/stix_export.py` | `risk_score >= RISK_THRESHOLD` | "IP Indicators" metric on the Bundle Composition preview; mirrors the STIX gate. |
| `dashboard/pages/geography.py` | `risk_score` | Map color dimension (Plasma scale 0–100). |
| `notify/report.py` | `risk_score` (sort) + `enrichment_risk_score` + `behavioral_risk_score` + 4 per-provider scores | Top Attackers table with decomposition column. |

## Worked examples

### Example 1 — Fully-enriched IP with full escalation

An IP that AbuseIPDB rates at 88, VirusTotal flags with 7 engines, Shodan finds a CVE on, GreyNoise classifies as malicious. The IP also authenticated to the honeypot, executed commands, downloaded a file, and tripped a Suricata rule.

| Score | Value | Math |
|---|---|---|
| `abuseipdb_risk_score` | 88 | pass-through |
| `virustotal_risk_score` | 75 | 7 falls in 6–10 bucket |
| `shodan_risk_score` | 100 | CVE present |
| `greynoise_risk_score` | 75 | classification=malicious |
| `enrichment_risk_score` | 84.5 | mean(88, 75, 100, 75) |
| `behavioral_risk_score` | 80+ | +20 auth +25 cmd +20 dl +15 finding +(small from attempts) |
| **`risk_score`** | **≈ 82** | (84.5 + 80) / 2 |

### Example 2 — GreyNoise RIOT, otherwise hot intel

GreyNoise has this IP on RIOT (it's a Censys scanner). AbuseIPDB gives it 90 (other operators have reported it for scanning behaviour). VT has no record. Shodan shows ports but no CVE. The IP also hit our honeypot's login prompt 20 times.

| Score | Value | Math |
|---|---|---|
| `abuseipdb_risk_score` | 90 | pass-through |
| `virustotal_risk_score` | null | VT didn't enrich this IP |
| `shodan_risk_score` | 25 | ports, no vulns |
| `greynoise_risk_score` | 0 | **RIOT override** |
| `enrichment_risk_score` | 38.3 | mean of populated: (90 + 25 + 0) / 3 |
| `behavioral_risk_score` | 2 | min(20, 100) × 0.1 = 2 (no auth_successes, no commands) |
| **`risk_score`** | **≈ 20** | (38.3 + 2) / 2 |

The RIOT signal correctly pulls this IP below the STIX gate (40) and out of the High/Medium dashboard buckets, even though AbuseIPDB has the IP at 90. A Censys scanner doesn't belong as a threat indicator.

### Example 3 — Only AbuseIPDB enriched

AbuseIPDB returns confidence 100 for an IP. VT, Shodan, GreyNoise were all rate-limited that day (or the IP is unknown to them).

| Score | Value | Math |
|---|---|---|
| `abuseipdb_risk_score` | 100 | |
| Others | null | |
| `enrichment_risk_score` | 100 | mean of populated = AbuseIPDB alone |
| `behavioral_risk_score` | 0 | scanner-only, no honeypot activity |
| **`risk_score`** | **50** | (100 + 0) / 2 |

Half of the maximum — strong intel signal partly cancelled by the absence of any honeypot activity. Lands above the STIX gate, in the Medium dashboard bucket.

### Example 4 — No enrichment at all, high honeypot activity

A fresh IP no provider has seen yet. It logged into the honeypot, ran 5 commands, downloaded a sample, and tripped a finding.

| Score | Value | Math |
|---|---|---|
| All per-provider scores | null | nobody saw it |
| `enrichment_risk_score` | null | mean of all-nulls is null |
| `behavioral_risk_score` | 80+ | +20 +25 +20 +15 +(auth_attempts×0.1) |
| **`risk_score`** | **≈ 40** | (0 + 80) / 2 (enrichment null filled to 0) |

Sits right at the STIX gate — the system flags it but the lack of intel context is visible in the decomposition.

## FAQ

> **Q: My IP has `vt_malicious=15` but only `risk_score=37`. Why isn't it higher?**

The composite halves both sides. VT alone produces `virustotal_risk_score=100`, but if no other provider contributed, `enrichment_risk_score` is still 100. With no honeypot activity, `behavioral_risk_score=0`. Composite = `(100 + 0) / 2 = 50`. If it shows 37, the IP probably also has a `greynoise_risk_score=0` (benign or RIOT) pulling the enrichment mean down.

> **Q: Why is RIOT a negative signal and not just neutral?**

A RIOT IP is one GreyNoise has *actively listed as known-benign infrastructure* (CDNs, NTP, DNS resolvers, software update endpoints). When other providers flag a RIOT IP (which happens — AbuseIPDB has lots of reports against Censys, for instance), GreyNoise's specific intelligence about that infrastructure is the correct authority. Letting it pull the score toward 0 prevents false-positive Indicators in STIX export.

> **Q: How do I tune the formula?**

Bucket boundaries: `VT_IP_RISK_BUCKETS` in `enrichment/providers/virustotal.py`. Per-provider weights: edit the `compute_risk_score` functions directly. Composite blend (currently unweighted mean): edit `compute_ip_reputation` in `transform/metrics.py`. All changes need tests in their corresponding test files.

> **Q: An IP is in gold with all four `*_risk_score` columns null but my composite is non-zero. Why?**

`enrichment_risk_score.fill_null(0)` happens during the composite calculation. The composite uses 0 for the enrichment half, doubles the behavioral half down by half. So you're seeing `behavioral_risk_score / 2`. Worth comparing the raw enrichment columns and the `behavioral_risk_score` column to confirm.

## Adding a new enrichment provider

If a future provider gets added to the pipeline, it must:

1. Emit a `<provider>_risk_score` field in its `EnrichmentResult.data` dict, scaled to 0..100. Implementation goes in a `compute_risk_score(...)` module-level helper for testability.
2. Add the column to the `optional` list in `transform/metrics.py:compute_ip_reputation` so it flows into the `mean_horizontal` in the composite.
3. Add per-provider unit tests in `pipeline/tests/test_enrichment/test_<name>.py`.
4. Update the per-provider section in this document with the formula table.
5. If the provider has a "benign" signal (analogous to GreyNoise's RIOT), follow the same short-circuit-to-0 pattern — don't introduce a separate "skip this IP" flag in the gold composite.

The composite formula needs no change to accommodate a new provider — `mean_horizontal` averages whatever non-null inputs it gets.

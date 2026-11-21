# Risk score composition

This document is the analyst's reference for how Lantana v1.5 derives `risk_score` for every source IP in the gold layer. Open it when you're reading a Discord brief or a Vigil dashboard row and wondering *why this IP got this score*.

> **Context:** per-provider sub-scores land in silver during the enrichment step described in [`pipeline.md`](/docs/pipeline.md), populated from the third-party APIs documented in [`integrations.md`](/docs/integrations.md). The gold composite (`risk_score`) is the single number consumed by STIX export, the Discord brief, and the Vigil dashboard.

## TL;DR

Three numbers per IP, all on the same 0–100 scale:

- **`enrichment_risk_score`** — mean of the non-null per-provider scores that landed for this IP (AbuseIPDB, VirusTotal, Shodan, GreyNoise). HTTP 404 responses emit `null` (not `0` or `10`), so unindexed IPs never dilute scores from other providers. Null if no provider returned a scored verdict.
- **`behavioral_risk_score`** — what the IP actually did on the honeypot (successful auth, commands, non-probe malware/persistence downloads, non-decoder IDS findings, auth volume).
- **`risk_score`** — monotonic behavioral-anchored composite that drives STIX export, dashboard buckets, and Discord top-5 sorting:
  - **Pure scan (`behavioral == 0`)**: `0.0` if GreyNoise RIOT or `benign`; otherwise `enrichment.fill_null(0.0) * 0.35` (capped at `35.0` — never crosses `RISK_THRESHOLD = 40.0` into STIX).
  - **Interactive / credential activity (`behavioral > 0`)**: `behavioral / 2.0` if GreyNoise RIOT or `benign` (false-positive brake); otherwise `max(behavioral, 0.5 * behavioral + 0.5 * enrichment)` when enrichment is present, or `behavioral` when enrichment is null.

Plus four per-provider sub-scores (`abuseipdb_risk_score`, `virustotal_risk_score`, `shodan_risk_score`, `greynoise_risk_score`), each 0–100 or null, so the decomposition is fully traceable down to the source.

## Architecture

```
                ┌──────────────────────────┐
                │  Per-provider enrichment │
   silver       │                          │
   (per-event,  │  abuseipdb_risk_score    │ ← computed by each provider
    one row     │  virustotal_risk_score   │   from its own raw response
    per         │  shodan_risk_score       │   (HTTP 404 -> null, never 0);
    log line)   │  greynoise_risk_score    │   joined onto every event for
                │  (each Float64, 0..100,  │   that source IP via
                │   nullable)              │   _build_lookup + _merge_lookup.
                └──────────────────────────┘
                          │
                          ▼  (group_by src_endpoint_ip in compute_ip_reputation;
                              null/empty src_endpoint_ip rows dropped first)
                ┌────────────────────────────────────────────────────┐
   gold         │  enrichment_risk_score = mean of non-null          │
   (per-IP      │     per-provider scores (null if all four null)    │
    aggregates) │                                                    │
                │  behavioral_risk_score = honeypot activity signal  │
                │     (+25 auth_success +25 cmd +25 non-probe dl     │
                │      +15 real finding +min(auth_attempts,100)*0.1) │
                │                                                    │
                │  risk_score = monotonic behavioral-anchored blend: │
                │     behavioral == 0 -> 0 (benign/RIOT) or          │
                │                        enrichment * 0.35 (<= 35)   │
                │     behavioral >  0 -> behavioral / 2 (benign/RIOT)│
                │                        or max(behavioral,          │
                │                               (behavioral+enrich)/2│
                │                              )                     │
                └────────────────────────────────────────────────────┘
```

## Per-provider formulas

Each provider's score lives in `pipeline/src/lantana/enrichment/providers/<name>.py`. Tests live in `pipeline/tests/test_enrichment/test_<name>.py`.

### Absence (`HTTP 404`) invariant

When a provider returns HTTP 404 ("IOC not in upstream dataset"), Lantana stores explicit `"not_found"` / empty metadata fields and sets **`<provider>_risk_score = None`**. Unindexed residential or fresh cloud IPs never contribute a synthetic `0.0` or `10.0` to `pl.mean_horizontal`, so they cannot dilute a real verdict from another provider.

### AbuseIPDB

```text
abuseipdb_risk_score = abuseConfidenceScore  (clamped to 0..100)
```

AbuseIPDB's confidence score is already calibrated to community reporting density on a 0–100 scale, so we pass it through.

| Raw `abuseConfidenceScore` | `abuseipdb_risk_score` |
|---|---|
| 0 | 0.0 |
| 50 | 50.0 |
| 100 | 100.0 |

### VirusTotal (IP & Domain)

Bucketed by `last_analysis_stats.malicious` (the engine count). HTTP 404 returns `None`.

| `malicious` count | `virustotal_risk_score` / `vt_domain_risk_score` | Why this break |
|---|---|---|
| 404 (not indexed) | `null` | Absence of data is not evidence of benignity |
| 0 | 0.0 | Indexed and clean |
| 1–2 | 25.0 | Often single-engine noise / false positive |
| 3–5 | 50.0 | Multi-source agreement starts here |
| 6–10 | 75.0 | Broadly flagged |
| >10 | 100.0 | Heavily flagged; uncommon outside known C2 |

Module constant: `VT_IP_RISK_BUCKETS` in `enrichment/providers/virustotal.py`.

### VirusTotal (file hash & post-auth stager URL)

Bucketed by `last_analysis_stats.malicious` on `/files/{sha256}` and `/urls/{id}`. HTTP 404 returns `None`.

| `malicious` count | `vt_file_risk_score` / `vt_url_risk_score` | Why this break |
|---|---|---|
| 404 (not indexed) | `null` | Fresh sample / URL not yet seen by VT |
| 0 | 0.0 | Indexed and clean |
| 1 | 50.0 | Single engine flagging — crosses the cache "malicious" threshold |
| 2–4 | 75.0 | Multi-source agreement |
| ≥5 | 100.0 | Broadly flagged malware / stager |

Module constant: `VT_FILE_RISK_BUCKETS` in `enrichment/providers/virustotal.py`.

Thresholds are tighter than the IP buckets because file-scan and post-auth URL FP rates are much lower. These scores drive the cache TTL classifier (`_classify_ttl` in `enrichment/runner.py`, assigning 180d for malicious hashes and 90d for malicious URLs/domains) and surface in `extracted_iocs`, but are **not** mixed into the inbound-IP composite blend below.

### Shodan

Tri-state from `ports` and `vulns` on HTTP 200; HTTP 404 returns `None`.

| Condition | `shodan_risk_score` |
|---|---|
| HTTP 404 (never scanned) | `null` |
| `vulns` populated | 100.0 |
| `ports` populated, no `vulns` | 25.0 |
| HTTP 200, neither populated | 0.0 |

### GreyNoise (false-positive brake)

| Condition | `greynoise_risk_score` |
|---|---|
| HTTP 404 (not in dataset) | `null` |
| `riot == True` (Rule-It-Out: known-benign infrastructure) | **0.0 (overrides everything else)** |
| `classification == "malicious"` | 75.0 |
| `classification == "benign"` | 0.0 |
| `noise == True` and `classification == "unknown"` | 25.0 |
| HTTP 200, `classification == "unknown"`, `noise == False` | 10.0 |

**Why RIOT and `benign` act as a false-positive brake.** GreyNoise distinguishes internet background scanning (`noise=True`, ambiguous) from explicitly vetted infrastructure (`riot=True` or `classification == "benign"` — CDNs, DNS resolvers, Censys, Shadowserver). In the gold composite:

- Pure scanners with RIOT or `benign` drop directly to **`risk_score = 0.0`**.
- Interactive/credential IPs with RIOT or `benign` drop to **`behavioral_risk_score / 2.0`** and are excluded from STIX inbound IP indicators, while remaining visible in silver and gold with full enrichment columns intact.

## Gold composite

In `pipeline/src/lantana/transform/metrics.py:compute_ip_reputation`:

```python
# Rows with null/empty src_endpoint_ip are filtered out before grouping.
# Real findings exclude Suricata decoder anomaly SIDs (2200000..2260999).
# Real downloads exclude Cowrie probe writes (file_intent == "probe").

enrichment_risk_score = pl.mean_horizontal(
    abuseipdb_risk_score,
    virustotal_risk_score,
    shodan_risk_score,
    greynoise_risk_score,
).clip(0.0, 100.0)   # null if all four inputs are null

behavioral_risk_score = (
      25.0 if auth_successes > 0     else 0.0
    + 25.0 if commands_executed > 0  else 0.0
    + 25.0 if real_downloads > 0     else 0.0
    + 15.0 if real_findings > 0      else 0.0
    + min(auth_attempts, 100) * 0.1            # max +10.0
).clip(0.0, 100.0)

is_benign_scanner = greynoise_riot | (greynoise_classification == "benign")

# Monotonic behavioral-anchored composite:
# 1) behavioral == 0 (pure scan):
#      0.0 if is_benign_scanner else (enrichment.fill_null(0.0) * 0.35)  # max 35.0
# 2) behavioral > 0 (credential / interactive / real finding):
#      behavioral / 2.0 if is_benign_scanner
#      else max(behavioral, 0.5 * behavioral + 0.5 * enrichment)  (or behavioral if enrichment is null)
```

**Why monotonic behavioral anchoring?** In v1.0, `(enrichment.fill_null(0) + behavioral) / 2` suffered from two failure modes seen across Operation Alpha's 149-day run:

1. **Scanner inflation:** A passive scanner with `AbuseIPDB = 100` and zero honeypot interaction scored `50.0` and flooded STIX bundles above `RISK_THRESHOLD = 40.0`. Capping pure scans at `enrichment * 0.35` (`<= 35.0`) guarantees no pure scanner ever enters STIX.
2. **Enrichment-gap penalty:** A brand-new interactive attacker (authenticated, ran commands, dropped malware: `behavioral = 80.0`) whose IP had no enrichment data yet (`enrichment = null`) was halved down to `40.0` — lower than a passive AbuseIPDB scanner! Anchoring interactive scores at `max(behavioral, 0.5 * behavioral + 0.5 * enrichment)` guarantees that external enrichment can **confirm and elevate** real attacker behavior, never drag it down when an API is rate-limited or returns 404 (except for explicit GreyNoise RIOT/`benign` FP protection).

## Downstream consumers

Threshold constants live in [`intel/stix.py`](/pipeline/src/lantana/intel/stix.py) — `RISK_THRESHOLD = 40.0` (STIX inbound-IP gate and dashboard Medium-bucket floor) and `RISK_HIGH_THRESHOLD = 70.0` (dashboard High bucket). Every consumer imports these constants rather than hardcoding them.

| Consumer | Field read | Threshold / behaviour |
|---|---|---|
| `intel/stix.py:_make_indicators` | `behavioral_risk_score > 0` AND `risk_score >= RISK_THRESHOLD` (not RIOT/`benign`) | Gate for transient inbound IP indicators (emitted with 7-day `valid_until`). Durable IOCs from `extracted_iocs` (outbound C2 IPs, stager URLs/domains, malware hashes, SSH keys) bypass the inbound IP gate and carry 30–90 day validity. |
| `intel/stix.py:_make_indicators` | `risk_score` | STIX `confidence` field = `min(int(risk_score), 100)`. |
| `dashboard/queries.py` + `dashboard/html.py` (`/ips`, `/overview`) | `risk_score` | High (`>= RISK_HIGH_THRESHOLD`) / Medium (`>= RISK_THRESHOLD`) / Low buckets. Help drawers read from `notify/explanations.py`. |
| `dashboard/queries.py` (`/stix`) | `behavioral_risk_score > 0` AND `risk_score >= RISK_THRESHOLD` | Bundle composition preview mirroring the exact STIX gate. |
| `dashboard/charts.py` (`/geography`) | `risk_score` | World-map color scale (0–100). |
| `notify/report.py` | `risk_score` (sort) + `enrichment_risk_score` + `behavioral_risk_score` + 4 per-provider scores | Top Attackers table with decomposition column. |

## Worked examples

### Example 1 — Fully-enriched interactive attacker

An IP with AbuseIPDB `88`, VirusTotal `7` engines (`75`), Shodan CVE (`100`), GreyNoise `malicious` (`75`). It authenticated, ran commands, dropped a malware sample, and triggered a real Suricata rule (plus 20 auth attempts).

| Score | Value | Math |
|---|---|---|
| `abuseipdb_risk_score` | 88.0 | pass-through |
| `virustotal_risk_score` | 75.0 | 7 falls in 6–10 bucket |
| `shodan_risk_score` | 100.0 | CVE present |
| `greynoise_risk_score` | 75.0 | `classification == "malicious"` |
| `enrichment_risk_score` | 84.5 | mean(88, 75, 100, 75) |
| `behavioral_risk_score` | 92.0 | +25 auth +25 cmd +25 dl +15 finding +2 attempts |
| **`risk_score`** | **92.0** | `max(92.0, (92.0 + 84.5) / 2) = max(92.0, 88.25) = 92.0` |

### Example 2 — Passive scanner with `AbuseIPDB = 100` (no interaction)

An IP hits port 22/445 and disconnects without authenticating or triggering any real IDS rule. AbuseIPDB rates it `100`; VT, Shodan, and GreyNoise return HTTP 404 (`null`).

| Score | Value | Math |
|---|---|---|
| `abuseipdb_risk_score` | 100.0 | pass-through |
| Others | `null` | 404 → `null` (no dilution) |
| `enrichment_risk_score` | 100.0 | mean of populated = AbuseIPDB alone |
| `behavioral_risk_score` | 0.0 | scan-only, no interaction |
| **`risk_score`** | **35.0** | `100.0 * 0.35 = 35.0` (capped below STIX gate `40.0`) |

Tracked in gold and visible on the dashboard, but never pollutes STIX bundles.

### Example 3 — GreyNoise RIOT / benign research scanner

A Censys scanner (`greynoise_riot = True`) with AbuseIPDB `90`, Shodan ports `25`, VT `null`.

- If pure scan (`behavioral = 0`): **`risk_score = 0.0`**.
- If it tried 20 auth probes (`behavioral = 2.0`): **`risk_score = 2.0 / 2.0 = 1.0`**, excluded from STIX inbound IP indicators.

### Example 4 — Brand-new interactive attacker (zero enrichment)

A fresh residential botnet IP never seen by any provider (or providers were rate-limited). It logs in, executes commands, and drops a binary (`+25 auth +25 cmd +25 dl +0.5 attempts = 75.5`).

| Score | Value | Math |
|---|---|---|
| All per-provider scores | `null` | 404 or not queried |
| `enrichment_risk_score` | `null` | mean of all-nulls is null |
| `behavioral_risk_score` | 75.5 | +25 +25 +25 +0.5 |
| **`risk_score`** | **75.5** | enrichment is null → anchored at `behavioral_risk_score` |

Immediate High-bucket visibility and STIX inclusion without waiting for third-party intel feeds to catch up.

## FAQ

> **Q: Why didn't a noisy AbuseIPDB-100 scanner make it into my STIX bundle?**

Pure scans (`behavioral_risk_score == 0`) are intentionally capped at `35.0`, below `RISK_THRESHOLD = 40.0`, and STIX inbound IP indicators additionally require `behavioral_risk_score > 0`. Inbound scanner IPs churn constantly; STIX focuses on durable infrastructure (`extracted_iocs`: outbound C2 IPs, stager URLs/domains, malware hashes, SSH keys) plus short-lived (7-day) indicators for IPs that actually interacted with the honeypot.

> **Q: Why do Suricata decoder alerts (SID `2200000–2260999`) and Cowrie probe files not add behavioral risk?**

Suricata decoder alerts (invalid TCP checksums, malformed headers) are transport noise rather than attack signatures, and Cowrie probe writes (`file_intent == "probe"`, e.g. empty `echo` checks) are not malware drops. Excluding both prevents false escalation of low-signal probes.

> **Q: How do I tune the formula?**

Bucket boundaries live in `VT_IP_RISK_BUCKETS` / `VT_FILE_RISK_BUCKETS` (`enrichment/providers/virustotal.py`). Per-provider weights live in each provider's `compute_risk_score`. Composite rules live in `compute_ip_reputation` (`transform/metrics.py`). Update `pipeline/tests/test_transform/test_metrics.py::TestRiskScoreDecomposition` and this doc alongside any change.

## Adding a new enrichment provider

1. Emit `<provider>_risk_score` in `EnrichmentResult.data` (0..100 float on scored verdicts, `None` on HTTP 404). Put the logic in a module-level `compute_risk_score(...)` helper.
2. Register the field name in `_RISK_SCORE_FIELDS` (`enrichment/runner.py`) so the SQLite cache TTL classifier distinguishes benign (7d) from malicious (60–180d).
3. Add the column to the per-provider list in `transform/metrics.py:compute_ip_reputation` so `pl.mean_horizontal` picks it up automatically.
4. Add unit tests in `pipeline/tests/test_enrichment/test_<name>.py` and document the formula table here.

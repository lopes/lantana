# Lantana: Third-Party Integrations

Lantana enriches honeypot telemetry with external data from **five enrichment integrations** across two stages (plus the **Discord webhook** for daily intelligence briefs and operational notifications — **six third-party services total**, all keyed in `vault.yml` / `secrets.json`):

1. **Wire-speed (Vector, local MMDB) — MaxMind GeoLite2.** The foundational integration. Every event passes through it the moment Vector ingests it, before reaching bronze. Geo + ASN attribution is non-negotiable: the gold geographic_summary, the dashboard map, and the STIX bundle's `country` indicators all assume this data is present.
2. **Daily batch (Python pipeline, HTTP APIs) — AbuseIPDB, Shodan, VirusTotal, GreyNoise.** Run once per day during bronze → silver, only against unique attacker IPs that landed events the previous day. Adds reputation, exposed services, malware history, and scanner classification on top of what MaxMind already produced.

This document is the single reference for how each integration works — endpoints/files, authentication, rate limits, docs links, and how to verify them end-to-end.

For where enrichment fits in the pipeline (bronze → silver, OCSF normalization, OPSEC redaction), see [`pipeline.md`](/docs/pipeline.md). For how the vault carries provider keys, see [`setup.md`](/docs/setup.md#5-create-the-vault).

---

## 1. Provider Summary

### Wire-speed enrichment (Vector, local MMDB)

| Provider | Source | Auth | License-tier limit | Docs |
|---|---|---|---|---|
| [MaxMind GeoLite2](#maxmind-geolite2) | Local MMDB files (City + ASN) downloaded at deploy time | License key required for download (free signup) | Free GeoLite2 license; weekly updates | [MaxMind dev portal](https://dev.maxmind.com/geoip/docs/databases/city-and-country) |

### Daily-batch enrichment (Python pipeline, HTTP APIs)

All HTTP enrichment providers are **optional** — omitting a vault key (or leaving it blank for key-required providers) cleanly skips that provider with `provider_disabled` rather than firing 401 errors.

| Provider | Endpoint | Auth | Free-tier limit | Docs |
|---|---|---|---|---|
| [AbuseIPDB](#abuseipdb)  | `https://api.abuseipdb.com/api/v2/check` | `Key:` header, optional (skips if unset) | 1000 checks/day | [docs.abuseipdb.com](https://docs.abuseipdb.com/) |
| [Shodan](#shodan)        | `https://api.shodan.io/shodan/host/{ip}` | `key=` query param, optional (skips if unset) | ~100 queries/month (Membership) | [developer.shodan.io/api](https://developer.shodan.io/api) |
| [VirusTotal / GTI](#virustotal) | `https://www.virustotal.com/api/v3/{ip_addresses,files,urls,domains}/{id}` | `x-apikey:` header (`x-tool: Lantana`), optional (skips if unset); opt-in commercial GTI via `gti_enabled: true` + `vault_apikey_gti` | 4 req/min, 500 req/day (`VT_FREE_DAILY_REQUEST_BUDGET = 480`) | [docs.virustotal.com](https://docs.virustotal.com/reference/overview) |
| [GreyNoise](#greynoise)  | `https://api.greynoise.io/v3/community/{ip}` | `key:` header, **optional** (`""` = anonymous community, omitted = skipped) | 50 searches per 7 days (unauthenticated) | [Community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api) · [Full v3 API](https://docs.greynoise.io/docs/using-the-greynoise-api) |

All four HTTP providers accept an IPv4 / IPv6 address. VirusTotal / GTI additionally enriches SHA-256 file hashes (Cowrie + Dionaea captures), post-auth stager URLs, and stager domains via a single behavioral-priority queue (`hashes -> outbound C2 IPs -> stager URLs/domains -> inbound IPs`) paced by `_AsyncRateLimiter`. MaxMind accepts only IPs.

---

## 2. Per-Provider Detail

### MaxMind GeoLite2

Free IP→geography and IP→ASN database from MaxMind. Used by **Vector** (not the Python pipeline) to tag every event with `.geo.*` fields at the moment of ingest — country, region, city, lat/long, timezone, ASN, ISP. This happens at wire speed; the daily Python pipeline never queries MaxMind directly.

- **Files:** `/var/lib/lantana/collector/geoip/GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
- **How Vector loads them:** as `enrichment_tables` in [`receive.vector.yaml.j2`](/config/ansible/roles/profile_collector/templates/receive.vector.yaml.j2). The VRL transform `enrich_geo` looks up `.src_ip` against both tables and writes `.geo.*` fields.
- **Download:** Ansible role `profile_collector` downloads the City + ASN tarballs at deploy time using `vault_apikey_maxmind` (see vault layout below). A monthly cron at 02:30 UTC on the 1st refreshes them and restarts Vector.
- **License:** free **with** account signup. See [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup). After signup: Account → Manage License Keys → Generate new license key.
- **Docs:** https://dev.maxmind.com/geoip/docs/databases/city-and-country

**Fields the Vector VRL writes into bronze:**

| Bronze column | Source field | Notes |
|---|---|---|
| `geo.country_code` | `country.iso_code`           | ISO-3166 alpha-2 |
| `geo.region_code`  | `subdivisions[0].iso_code`   | First-level admin division |
| `geo.city`         | `city.names.en`              | English name |
| `geo.latitude`     | `location.latitude`          | Float |
| `geo.longitude`    | `location.longitude`         | Float |
| `geo.timezone`     | `location.time_zone`         | IANA tz |
| `geo.asn`          | `autonomous_system_number`   | From ASN MMDB |
| `geo.isp`          | `autonomous_system_organization` | From ASN MMDB |

**If the vault key is missing.** Ansible's `when:` guards skip the download silently. Vector starts cleanly, but every event omits `.geo.*` fields. Symptom: Vigil's `/geography` view displays a **MaxMind GeoLite2 Not Populated** warning callout, `/health` marks MaxMind as `Not Configured`, and the gold `geographic_summary` table stays empty. Fix: add `vault_apikey_maxmind` to the vault and re-run the collector role.

### AbuseIPDB

Community-driven abuse reporting database. We use it to surface IPs with known abuse history and ISP/country attribution.

- **Endpoint:** `GET https://api.abuseipdb.com/api/v2/check`
- **Auth:** `Key: <api_key>` header
- **Query params:** `ipAddress`, `maxAgeInDays=90`
- **Provider file:** [`abuseipdb.py`](/pipeline/src/lantana/enrichment/providers/abuseipdb.py)
- **Free-tier limit:** 1000 checks/day
- **Docs:** https://docs.abuseipdb.com/

**Fields we extract into silver:**

| Silver column | Source field | Notes |
|---|---|---|
| `abuseipdb_confidence_score` | `data.abuseConfidenceScore` | 0–100 |
| `abuseipdb_total_reports`    | `data.totalReports`         | All-time report count |
| `abuseipdb_risk_score`       | computed                    | = `abuseConfidenceScore` (pass-through 0..100) |

Country/ISP/domain are intentionally NOT extracted — MaxMind GeoIP is the source of truth for geo/network attribution, and duplicates created downstream conflicts (commit `328f3aa`).

**Risk-score derivation:** see [risk-scoring.md § AbuseIPDB](/docs/risk-scoring.md#abuseipdb).

### Shodan

Internet-wide scanner. We use it for open-port + service + ASN attribution on attacker source IPs.

- **Endpoint:** `GET https://api.shodan.io/shodan/host/{ip}`
- **Auth:** `key=<api_key>` query parameter (not a header)
- **Provider file:** [`shodan.py`](/pipeline/src/lantana/enrichment/providers/shodan.py)
- **Free-tier limit:** ~100 host lookups per month on the Membership plan
- **Docs:** https://developer.shodan.io/api

**Fields we extract into silver:**

| Silver column | Source field | Notes |
|---|---|---|
| `shodan_ports`        | `ports[]`            | Joined as comma-separated string |
| `shodan_os`           | `os`                 | Often null |
| `shodan_vulns`        | `vulns[]`            | Joined as comma-separated string; null when no CVEs |
| `shodan_org`          | `org`                | Owning organization |
| `shodan_asn`          | `asn`                | AS number (`AS<n>` form) |
| `shodan_risk_score`   | computed             | Tri-state: 0 / 25 (ports only) / 100 (CVE present) |

**Risk-score derivation:** see [risk-scoring.md § Shodan](/docs/risk-scoring.md#shodan).

### VirusTotal

Multi-vendor aggregator (90+ AV/blocklist engines) with optional commercial **Google Threat Intelligence (GTI)** enrichment (`gti_enabled: true` + `vault_apikey_gti`). Every request sends `x-tool: Lantana` alongside `x-apikey`.

- **Endpoints:**
  - IP:     `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`
  - Hash:   `GET https://www.virustotal.com/api/v3/files/{sha256}`
  - URL:    `GET https://www.virustotal.com/api/v3/urls/{base64url_no_pad}`
  - Domain: `GET https://www.virustotal.com/api/v3/domains/{domain}`
- **Auth:** `x-apikey: <api_key>` header (`vault_apikey_virustotal`, or `vault_apikey_gti` when `gti_enabled: true`) + `x-tool: Lantana`.
- **Provider file:** [`virustotal.py`](/pipeline/src/lantana/enrichment/providers/virustotal.py)
- **Free-tier limit:** 4 requests per minute, 500 per day (`VT_FREE_DAILY_REQUEST_BUDGET = 480`), paced by `_AsyncRateLimiter` across one unified priority queue: malware hashes → outbound C2 IPs → post-auth stager URLs & domains → behaviorally-ranked inbound IPs.
- **Commercial GTI mode (opt-in):** Off by default (`gti_enabled: false`). When enabled with `vault_apikey_gti`, adds GTI relationship queries (`associations,threat_actors,malware_families,vulnerabilities`) and surfaces Mandiant verdicts/associations gated at confidence `>= 75` (`GTI_ASSOCIATION_MIN_CONFIDENCE`). Free-tier deployments never hit commercial-only endpoints.
- **HTTP 404 behaviour:** Returns `"vt_status": "not_found"` with zero counts and `*_risk_score: None` (never `0.0`), preventing dilution of other providers' verdicts.
- **Docs:** https://docs.virustotal.com/reference/overview

**Fields we extract into silver (IP):**

| Silver column | Source field |
|---|---|
| `vt_status`              | `"ok"` / `"not_found"` |
| `vt_malicious_count`     | `data.attributes.last_analysis_stats.malicious` |
| `vt_suspicious_count`    | `data.attributes.last_analysis_stats.suspicious` |
| `vt_ip_reputation`       | `data.attributes.reputation` |
| `vt_as_owner`            | `data.attributes.as_owner` |
| `virustotal_risk_score`  | computed — bucketed from `vt_malicious_count` (`None` on 404) |

**Risk-score derivation:** see [risk-scoring.md § VirusTotal](/docs/risk-scoring.md#virustotal-ip--domain).

**Fields we extract into silver (hash — 7 columns, plus optional GTI fields):**

| Silver column | Source field | Notes |
|---|---|---|
| `vt_file_malicious_count`  | `data.attributes.last_analysis_stats.malicious` | AV engines flagging malicious |
| `vt_file_undetected_count` | `data.attributes.last_analysis_stats.undetected` | AV engines with no detection |
| `vt_file_name`             | `data.attributes.meaningful_name` | Canonical sample name |
| `vt_file_type`             | `data.attributes.type_tag` | File type tag (e.g. `elf`, `peexe`) |
| `vt_file_family`           | `data.attributes.popular_threat_classification` | Top `popular_threat_name` or `suggested_threat_label` |
| `vt_file_vhash`            | `data.attributes.vhash` | Structural similarity hash (free tier; drives `vhash` clustering in Gold & STIX) |
| `vt_file_risk_score`       | computed | Bucketed from `vt_file_malicious_count` (0 / 50 / 75 / 100; `None` on 404; drives 180d cache TTL) |

Post-auth stager URLs and domains populate `vt_url_*` (`vt_url_malicious_count`, `vt_url_suspicious_count`, `vt_url_downloaded_sha256`, `vt_url_risk_score`) and `vt_domain_*` (`vt_domain_malicious_count`, `vt_domain_suspicious_count`, `vt_domain_risk_score`) in the `extracted_iocs` Gold table.

### GreyNoise

Internet background-noise classifier — identifies IPs that scan the entire internet (good / bad / unknown actors) and IPs that belong to known benign services (RIOT).

- **Endpoint:** `GET https://api.greynoise.io/v3/community/{ip}`
- **Auth:** `key: <api_key>` header — **optional**. The community endpoint accepts anonymous requests; a key only raises the rate limit.
- **Provider file:** [`greynoise.py`](/pipeline/src/lantana/enrichment/providers/greynoise.py)
- **Free-tier limit:** 50 searches per 7 days (shared with the Visualizer)
- **Docs:**
  - Community API (what we use): https://docs.greynoise.io/docs/using-the-greynoise-community-api
  - Full v3 API (subscription-only): https://docs.greynoise.io/docs/using-the-greynoise-api

**Fields we extract into silver:**

| Silver column | Source field | Notes |
|---|---|---|
| `greynoise_classification` | `classification`     | `malicious` / `benign` / `unknown` |
| `greynoise_noise`          | `noise`              | Scans the internet |
| `greynoise_riot`           | `riot`               | Known benign service (Google bots, CDN crawlers, ...) |
| `greynoise_name`           | `name`               | Actor label when classified |
| `greynoise_last_seen`      | `last_seen`          | |
| `greynoise_link`           | `link`               | Visualizer URL |
| `greynoise_risk_score`     | computed             | Classification matrix with RIOT short-circuit to 0 |

**HTTP 404 behaviour.** A 404 from this endpoint means "IP not in dataset," not an error. The provider returns a normalized result with `greynoise_classification: "unknown"`, false booleans, and **`greynoise_risk_score: None`** (so unindexed IPs never dilute other providers' scores). Don't treat 404 as a pipeline failure.

**Risk-score derivation:** see [risk-scoring.md § GreyNoise](/docs/risk-scoring.md#greynoise-false-positive-brake). Note: RIOT and `benign` act as the false-positive brake — pure scanners drop to `risk_score=0`, and interactive hits drop to `behavioral/2` and stay out of STIX inbound IP indicators.

---

## 3. Enablement and Vault Layout

The vault key `vault_apikey_<service>` controls per-provider behaviour. The rendered `secrets.json` on the collector uses the same keys verbatim, including `vault_apikey_maxmind`, `vault_apikey_gti`, and `gti_enabled` — see [Vault ↔ secrets.json nomenclature](/docs/pipeline.md#73-vault--secretsjson-nomenclature). Every enrichment provider is **optional**:

| Vault line state | AbuseIPDB / Shodan / VirusTotal | Commercial GTI | GreyNoise | MaxMind |
|---|---|---|---|---|
| Line omitted | **provider skipped** (`provider_disabled` log, zero 401s) | disabled (`gti_enabled: false`) | **provider skipped** (`provider_disabled` log) | **MMDB download skipped at deploy** — Vector starts without `.geo.*` enrichment |
| Line `""` (empty) | **provider skipped** (`provider_disabled` log) | disabled | community endpoint, anonymous (50/week) | same as missing |
| Line `"<key>"` | authenticated | enabled only when `gti_enabled: true` is also set in inventory | community endpoint, key sent in header (higher rate limit) | MMDBs downloaded + refreshed monthly |

The only way to disable GreyNoise is to **omit the vault line entirely** — its unauthenticated community mode takes over when the key is `""`. MaxMind has no unauthenticated download mode, so omitting or blanking the key disables it.

You can inspect every integration's active mode (`Configured`, `Configured (GTI)`, `Anonymous (Free)`, `Not Configured`) and latest run status (`OK`, `Warning (Rate Limit)`, `Error`) without opening `secrets.json` via Vigil's **System Health (`/health`)** view. Unset optional integrations show `Not Configured` and do not degrade Overall Status.

---

## 4. Verifying Integrations

Two probe scripts mirror the two enrichment paths:

- [`scripts/probe-enrichment.py`](/scripts/probe-enrichment.py) — HTTP API providers (AbuseIPDB, Shodan, VirusTotal, GreyNoise).
- [`scripts/probe-mmdb.py`](/scripts/probe-mmdb.py) — local MaxMind MMDB files (GeoLite2 City + ASN).

Both produce raw + normalized output side by side so you can compare against the provider's UI (HTTP) or against another lookup tool (MMDB). The example IPs throughout this section use RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); swap them for an IP your providers will actually have records on when you run the probe.

### `probe-enrichment.py` — HTTP API providers

The script hits each provider's live API with a real payload and prints both the raw upstream response and the normalized `EnrichmentResult.data`. Use it for daily-batch providers.

#### Invocation

```bash
cd pipeline

# All four providers against one IP
uv run python ../scripts/probe-enrichment.py --ip 198.51.100.42

# Specific providers, multiple payloads
uv run python ../scripts/probe-enrichment.py \
  --ip 198.51.100.7 --ip 203.0.113.7 \
  --provider greynoise,virustotal

# Hash against VirusTotal
uv run python ../scripts/probe-enrichment.py \
  --hash <sha256> --provider virustotal

# Local secrets file instead of /etc/lantana/collector/secrets.json
uv run python ../scripts/probe-enrichment.py \
  --ip 192.0.2.4 --secrets ./local-secrets.json

# Workaround for broken workstation TLS (Homebrew Python on macOS, etc.)
uv run python ../scripts/probe-enrichment.py --ip 192.0.2.4 --insecure
```

#### Flags

| Flag | Effect |
|---|---|
| `--ip <addr>`     | IP to query. Repeatable. Routes to every IP-capable provider. |
| `--hash <sha256>` | SHA-256 to query. Repeatable. Routes to VirusTotal only. |
| `--provider <name[,name]>` | Limit to specific providers. Default `all`. Repeatable. |
| `--secrets <path>` | Override the secrets.json path. Also honours `$LANTANA_SECRETS_PATH`. |
| `--no-raw`        | Suppress the raw upstream JSON; only print normalized fields. |
| `--insecure`      | Skip TLS verification. Local testing only — never production. |

Per (provider, payload) pair the probe prints:

```
=== <provider> // <payload> ===
[raw API response] (HTTP <status>)
{ <upstream JSON> }

[normalized EnrichmentResult.data]
{ <fields the pipeline writes to silver> }
```

Errors are printed in-place as `[error] <type>: <message>` and don't abort the run, so a single misconfigured key doesn't mask the other three providers. Exit code is `0` when every pair returned cleanly, `1` if anything errored, `2` for usage errors.

### `probe-mmdb.py` — MaxMind GeoLite2 (full stack)

Exercises the same flow Ansible runs at deploy time: downloads the City + ASN tarballs from MaxMind, extracts the `.mmdb` files, then queries them and prints both the raw MaxMind record and the exact `.geo.*` fields Vector's VRL would emit. The download step is **skipped** when the files already exist at `--mmdb-dir` — useful on the collector where Ansible already populated them.

#### Invocation

The license key is read from the same `secrets.json` as `probe-enrichment.py` — specifically the `vault_apikey_maxmind` field. Only consulted when an MMDB needs to be downloaded; query-only runs on a populated directory don't need `--secrets` at all.

The MMDB directory defaults differ by environment:
- **Collector** (`/var/lib/lantana/collector/geoip` exists): uses the production path so the probe sees what Vector sees.
- **Workstation** (production path doesn't exist): auto-falls back to `/tmp/lantana/mmdb` and prints a stderr note. Override with `--mmdb-dir <path>` if you want files elsewhere.

```bash
cd pipeline

# Workstation — defaults to /tmp/lantana/mmdb, downloads if missing
# (Swap 203.0.113.7 for a live public IP when verifying populated MMDB records.)
uv run python ../scripts/probe-mmdb.py --ip 203.0.113.7 \
    --secrets ./local-secrets.json

# Query-only on the collector (MMDBs already populated by Ansible)
uv run python ../scripts/probe-mmdb.py --ip 203.0.113.7

# Multiple IPs, custom directory
uv run python ../scripts/probe-mmdb.py --ip 198.51.100.7 --ip 203.0.113.7 \
    --mmdb-dir ~/lantana-mmdb --secrets ./local-secrets.json

# Force refresh (re-download even though files exist — mirrors the monthly cron)
uv run python ../scripts/probe-mmdb.py --ip 203.0.113.7 \
    --secrets ./local-secrets.json --force-download

# Workstation TLS workaround (Homebrew Python 3.14 cert chain issue)
uv run python ../scripts/probe-mmdb.py --ip 203.0.113.7 \
    --secrets ./local-secrets.json --insecure
```

#### Flags

| Flag | Effect |
|---|---|
| `--ip <addr>`         | IP to query. Repeatable. |
| `--mmdb-dir <path>`   | Directory containing (or to receive) `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`. Default: `/var/lib/lantana/collector/geoip` if it exists (collector), otherwise `/tmp/lantana/mmdb` (workstation auto-fallback, with a stderr note when it triggers). |
| `--secrets <path>`    | Path to `secrets.json` containing `vault_apikey_maxmind`. Default `$LANTANA_SECRETS_PATH` or `/etc/lantana/collector/secrets.json`. Only read when a download is needed. |
| `--force-download`    | Re-download even if files exist. Requires `vault_apikey_maxmind` in the secrets file. |
| `--no-raw`            | Suppress raw MaxMind records; only print normalized `.geo.*` fields. |
| `--insecure`          | Skip TLS verification during the download. Local-testing only. |

Per IP the probe prints:

```
=== mmdb // <ip> ===
[raw MaxMind record — City]
{ ... }

[raw MaxMind record — ASN]
{ ... }

[normalized geo.* fields (matches Vector's VRL output)]
{ "geo.country_code": "US", "geo.asn": 64496, ... }
```

If an IP isn't in either MMDB (e.g. private/bogon addresses, very fresh allocations), the probe notes that Vector would emit empty `.geo.*` fields and continues. Exit code `0` on clean runs (even when records are missing), `1` on download or lookup failure, `2` on usage errors or missing MMDBs without a license key.

#### What the download step validates

This is the same code path Ansible uses at deploy time and on the monthly cron. A successful run on a workstation confirms:

- The license key is valid and the MaxMind account is active.
- The tarballs are reachable (no Cloudflare / DNS surprises).
- Both tarballs contain a `.mmdb` file where we expect it.
- The extracted files are readable by `maxminddb` (catches corrupted downloads).

Run it once when you generate or rotate a key — you'll find any operational problem before deploy time.

### What to compare

For HTTP providers, open the same payload in the provider's web UI and confirm (1) the raw response matches what the UI shows and (2) the normalized block contains the fields documented in [§2](#2-per-provider-detail). Discrepancies usually mean either (a) the provider changed its response shape and field extraction needs updating, or (b) the endpoint moved.

For MaxMind, cross-check against `mmdblookup --file <path> --ip <ip>` (the `mmdb-bin` package) or a reputable third-party tool like ipinfo.io's web UI. Any mismatch usually means the MMDB is stale — run the deploy task again or wait for the monthly cron.

---

## 5. Historical Incidents

### PhishStats dropped (2026-05)

PhishStats was an unauthenticated phishing-URL feed. Its public endpoint moved off `phishstats.info:2096` to `api.phishstats.info` in early 2026-05 (Cloudflare HTTP 522 symptoms), and then in op_alpha's first live enrichment run on 2026-05-20 it began returning HTTP 401/403 on every request — apparently introducing a previously-undocumented auth requirement. Rather than maintain a fragile provider whose intel value was already marginal (most attacker IPs return zero phishing URLs), Lantana dropped PhishStats support entirely. Silver no longer carries `phishstats_*` columns; gold's risk score no longer includes a phishing-URL signal.

### Workstation TLS verification failures

Homebrew Python builds on macOS sometimes can't chain-validate certs even with `certifi.where()` configured (`curl` works, `httpx` fails with `unable to get local issuer certificate`). Symptom: every provider returns `ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED]`. Workaround: pass `--insecure` to the probe. The production collector on Debian 13 has a working system trust store and is unaffected.

### GreyNoise 404 → "unknown" (`null` risk score)

GreyNoise returns HTTP 404 for IPs not in its dataset rather than an empty 200. The provider treats this as "no info" and emits a normalized result with `greynoise_classification: "unknown"`, false booleans, and `greynoise_risk_score: None` — not an error, and never diluting scores from other providers. This is the most common GreyNoise response for honeypot attacker IPs that aren't part of mass-scanning campaigns.

### MaxMind silent skip on missing license key

If `vault_apikey_maxmind` is omitted or empty, Ansible's `when:` guards silently skip the MMDB download, extraction, ownership, and cron-update tasks. Vector starts fine — it just emits empty `.geo.*` fields for every event. Symptom: Vigil's `/geography` view shows the **MaxMind GeoLite2 Not Populated** warning callout, `/health` reports MaxMind as `Not Configured`, gold's `geographic_summary` is empty, and STIX bundles lack geo context. Fix: add `vault_apikey_maxmind` to the vault and re-run `deploy_single.yml` with the `vector` or `collector` tag.

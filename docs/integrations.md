# Lantana: Third-Party Integrations

Lantana enriches honeypot telemetry with external data from six third-party integrations across two stages:

1. **Wire-speed (Vector, local MMDB) — MaxMind GeoLite2.** The foundational integration. Every event passes through it the moment Vector ingests it, before reaching bronze. Geo + ASN attribution is non-negotiable: the gold geographic_summary, the dashboard map, and the STIX bundle's `country` indicators all assume this data is present.
2. **Daily batch (Python pipeline, HTTP APIs) — AbuseIPDB, Shodan, VirusTotal, GreyNoise, PhishStats.** Run once per day during bronze → silver, only against unique attacker IPs that landed events the previous day. Adds reputation, exposed services, malware history, phishing context, and scanner classification on top of what MaxMind already produced.

This document is the single reference for how each integration works — endpoints/files, authentication, rate limits, docs links, and how to verify them end-to-end.

For where enrichment fits in the pipeline (bronze → silver, OCSF normalization, OPSEC redaction), see [`pipeline.md`](pipeline.md). For how the vault carries provider keys, see [`runbook.md`](runbook.md#5-create-the-vault).

---

## 1. Provider Summary

### Wire-speed enrichment (Vector, local MMDB)

| Provider | Source | Auth | License-tier limit | Docs |
|---|---|---|---|---|
| [MaxMind GeoLite2](#maxmind-geolite2) | Local MMDB files (City + ASN) downloaded at deploy time | License key required for download (free signup) | Free GeoLite2 license; weekly updates | [MaxMind dev portal](https://dev.maxmind.com/geoip/docs/databases/city-and-country) |

### Daily-batch enrichment (Python pipeline, HTTP APIs)

| Provider | Endpoint | Auth | Free-tier limit | Docs |
|---|---|---|---|---|
| [AbuseIPDB](#abuseipdb)  | `https://api.abuseipdb.com/api/v2/check`                              | `Key:` header, required        | 1000 checks/day                          | [docs.abuseipdb.com](https://docs.abuseipdb.com/) |
| [Shodan](#shodan)        | `https://api.shodan.io/shodan/host/{ip}`                              | `key=` query param, required   | ~100 queries/month (Membership)          | [developer.shodan.io/api](https://developer.shodan.io/api) |
| [VirusTotal](#virustotal)| `https://www.virustotal.com/api/v3/ip_addresses/{ip}` · `/files/{sha256}` | `x-apikey:` header, required   | 4 req/min, 500 req/day                   | [docs.virustotal.com](https://docs.virustotal.com/reference/overview) |
| [GreyNoise](#greynoise)  | `https://api.greynoise.io/v3/community/{ip}`                          | `key:` header, **optional**    | 50 searches per 7 days (unauthenticated) | [Community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api) · [Full v3 API](https://docs.greynoise.io/docs/using-the-greynoise-api) |
| [PhishStats](#phishstats)| `https://api.phishstats.info/api/phishing?_where=(ip,eq,{ip})`        | none                           | 20 req/min                               | [phishstats.info/api-docs](https://phishstats.info/api-docs) |

All five HTTP providers accept an IPv4 / IPv6 address. Only VirusTotal also accepts a SHA-256 file hash (used for cowrie/dionaea downloads). MaxMind accepts only IPs.

---

## 2. Per-Provider Detail

### MaxMind GeoLite2

Free IP→geography and IP→ASN database from MaxMind. Used by **Vector** (not the Python pipeline) to tag every event with `.geo.*` fields at the moment of ingest — country, region, city, lat/long, timezone, ASN, ISP. This happens at wire speed; the daily Python pipeline never queries MaxMind directly.

- **Files:** `/var/lib/lantana/collector/geoip/GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
- **How Vector loads them:** as `enrichment_tables` in [`receive.vector.yaml.j2`](../config/ansible/roles/profile_collector/templates/receive.vector.yaml.j2). The VRL transform `enrich_geo` looks up `.src_ip` against both tables and writes `.geo.*` fields.
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

**If the vault key is missing.** Ansible's `when:` guards skip the download silently. Vector starts cleanly but every event is missing `.geo.*` fields. Symptom: dashboard shows all attacks as "unknown country," gold geographic_summary table is empty. Fix: add `vault_apikey_maxmind` to the vault and re-run the collector role.

### AbuseIPDB

Community-driven abuse reporting database. We use it to surface IPs with known abuse history and ISP/country attribution.

- **Endpoint:** `GET https://api.abuseipdb.com/api/v2/check`
- **Auth:** `Key: <api_key>` header
- **Query params:** `ipAddress`, `maxAgeInDays=90`
- **Provider file:** [`abuseipdb.py`](../pipeline/src/lantana/enrichment/providers/abuseipdb.py)
- **Free-tier limit:** 1000 checks/day
- **Docs:** https://docs.abuseipdb.com/

**Fields we extract into silver:**

| Silver column | Source field | Notes |
|---|---|---|
| `abuseipdb_confidence_score` | `data.abuseConfidenceScore` | 0–100; >25 flags as suspicious in gold scoring |
| `abuseipdb_total_reports`    | `data.totalReports`         | All-time report count |
| `abuseipdb_country`          | `data.countryCode`          | ISO-3166 alpha-2 |
| `abuseipdb_isp`              | `data.isp`                  | |
| `abuseipdb_domain`           | `data.domain`               | |

### Shodan

Internet-wide scanner. We use it for open-port + service + ASN attribution on attacker source IPs.

- **Endpoint:** `GET https://api.shodan.io/shodan/host/{ip}`
- **Auth:** `key=<api_key>` query parameter (not a header)
- **Provider file:** [`shodan.py`](../pipeline/src/lantana/enrichment/providers/shodan.py)
- **Free-tier limit:** ~100 host lookups per month on the Membership plan
- **Docs:** https://developer.shodan.io/api

**Fields we extract into silver:**

| Silver column | Source field | Notes |
|---|---|---|
| `shodan_ports`  | `ports[]`            | Joined as comma-separated string |
| `shodan_os`     | `os`                 | Often null |
| `shodan_vulns`  | `vulns[]`            | Joined as comma-separated string; null when no CVEs |
| `shodan_org`    | `org`                | Owning organization |
| `shodan_asn`    | `asn`                | AS number (`AS<n>` form) |

### VirusTotal

Multi-vendor aggregator (90+ AV/blocklist engines). We query both IPs and file hashes (cowrie/dionaea downloads).

- **Endpoints:**
  - IP:   `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`
  - Hash: `GET https://www.virustotal.com/api/v3/files/{sha256}`
- **Auth:** `x-apikey: <api_key>` header
- **Provider file:** [`virustotal.py`](../pipeline/src/lantana/enrichment/providers/virustotal.py)
- **Free-tier limit:** 4 requests per minute, 500 per day, 15.5k per month
- **Docs:** https://docs.virustotal.com/reference/overview

**Fields we extract into silver (IP):**

| Silver column | Source field |
|---|---|
| `vt_malicious_count`  | `data.attributes.last_analysis_stats.malicious` |
| `vt_suspicious_count` | `data.attributes.last_analysis_stats.suspicious` |
| `vt_ip_reputation`    | `data.attributes.reputation` |
| `vt_as_owner`         | `data.attributes.as_owner` |

**Fields we extract into silver (hash):**

| Silver column | Source field |
|---|---|
| `vt_malicious_count`  | `data.attributes.last_analysis_stats.malicious` |
| `vt_undetected_count` | `data.attributes.last_analysis_stats.undetected` |
| `vt_name`             | `data.attributes.meaningful_name` |
| `vt_type`             | `data.attributes.type_tag` |

### GreyNoise

Internet background-noise classifier — identifies IPs that scan the entire internet (good / bad / unknown actors) and IPs that belong to known benign services (RIOT).

- **Endpoint:** `GET https://api.greynoise.io/v3/community/{ip}`
- **Auth:** `key: <api_key>` header — **optional**. The community endpoint accepts anonymous requests; a key only raises the rate limit.
- **Provider file:** [`greynoise.py`](../pipeline/src/lantana/enrichment/providers/greynoise.py)
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

**HTTP 404 behaviour.** A 404 from this endpoint means "IP not in dataset," not an error. The provider returns a normalized result with `greynoise_classification: "unknown"` and all booleans false. Don't treat 404 as a pipeline failure.

### PhishStats

Free phishing-URL feed. Returns recent phishing URLs hosted on a given IP, with scores and metadata.

- **Endpoint:** `GET https://api.phishstats.info/api/phishing?_where=(ip,eq,{ip})`
- **Auth:** none (any `api_key` value is accepted but silently dropped)
- **Provider file:** [`phishstats.py`](../pipeline/src/lantana/enrichment/providers/phishstats.py)
- **Free-tier limit:** 20 requests per minute
- **Docs:** https://phishstats.info/api-docs

**Fields we extract into silver:**

| Silver column | Source | Notes |
|---|---|---|
| `phishstats_url_count` | `len(response)` | Number of phishing URLs reported for this IP |
| `phishstats_last_seen` | `max(entry.date)` | Most recent report timestamp |

---

## 3. Enablement and Vault Layout

The vault key `vault_apikey_<service>` controls per-provider behaviour. The rendered `secrets.json` on the collector uses the same keys verbatim, including `vault_apikey_maxmind` — see [Vault ↔ secrets.json nomenclature](pipeline.md#vault--secretsjson-nomenclature). The HTTP daily-batch providers consume their fields from `SecretsConfig` at runtime; MaxMind's field is consumed only by the probe script (`probe-mmdb.py`) and ignored by the Python pipeline. Ansible reads `vault_apikey_maxmind` straight from the vault at deploy time to download the MMDBs.

| Vault line state | AbuseIPDB / Shodan / VirusTotal | GreyNoise | PhishStats | MaxMind |
|---|---|---|---|---|
| Line omitted          | provider runs with empty key → 401 (misconfiguration) | **provider skipped** (`provider_disabled` log) | **provider skipped** (`provider_disabled` log) | **MMDB download skipped at deploy** — Vector starts without `.geo.*` enrichment |
| Line `""` (empty)     | same as above                                          | community endpoint, anonymous (50/week)        | public endpoint, no auth                       | same as missing (Ansible `when:` guard fails the truthiness check) |
| Line `"<key>"`        | authenticated                                          | community endpoint, key sent in header (higher rate limit) | public endpoint, key silently dropped | MMDBs downloaded + refreshed monthly |

The only way to disable GreyNoise or PhishStats is to **omit the vault line entirely** — both have working unauthenticated modes that take over when the key is empty. MaxMind has no unauthenticated mode for download, so omitting the key disables it.

---

## 4. Verifying Integrations

Two probe scripts mirror the two enrichment paths:

- [`scripts/probe-enrichment.py`](../scripts/probe-enrichment.py) — HTTP API providers (AbuseIPDB, Shodan, VirusTotal, GreyNoise, PhishStats).
- [`scripts/probe-mmdb.py`](../scripts/probe-mmdb.py) — local MaxMind MMDB files (GeoLite2 City + ASN).

Both produce raw + normalized output side by side so you can compare against the provider's UI (HTTP) or against another lookup tool (MMDB). The example IPs throughout this section use RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); swap them for an IP your providers will actually have records on when you run the probe.

### `probe-enrichment.py` — HTTP API providers

The script hits each provider's live API with a real payload and prints both the raw upstream response and the normalized `EnrichmentResult.data`. Use it for daily-batch providers.

#### Invocation

```bash
cd pipeline

# All five providers against one IP
uv run python ../scripts/probe-enrichment.py --ip 198.51.100.42

# Specific providers, multiple payloads
uv run python ../scripts/probe-enrichment.py \
  --ip 198.51.100.7 --ip 203.0.113.7 \
  --provider greynoise,phishstats

# Hash against VirusTotal
uv run python ../scripts/probe-enrichment.py \
  --hash <sha256> --provider virustotal

# Local secrets file instead of /etc/lantana/collector/secrets.json
uv run python ../scripts/probe-enrichment.py \
  --ip 1.2.3.4 --secrets ./local-secrets.json

# Workaround for broken workstation TLS (Homebrew Python on macOS, etc.)
uv run python ../scripts/probe-enrichment.py --ip 1.2.3.4 --insecure
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

Errors are printed in-place as `[error] <type>: <message>` and don't abort the run, so a single misconfigured key doesn't mask the other four providers. Exit code is `0` when every pair returned cleanly, `1` if anything errored, `2` for usage errors.

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
uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8 \
    --secrets ./local-secrets.json

# Query-only on the collector (MMDBs already populated by Ansible)
uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8

# Multiple IPs, custom directory
uv run python ../scripts/probe-mmdb.py --ip 1.1.1.1 --ip 203.0.113.7 \
    --mmdb-dir ~/lantana-mmdb --secrets ./local-secrets.json

# Force refresh (re-download even though files exist — mirrors the monthly cron)
uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8 \
    --secrets ./local-secrets.json --force-download

# Workstation TLS workaround (Homebrew Python 3.14 cert chain issue)
uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8 \
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
{ "geo.country_code": "US", "geo.asn": 15169, ... }
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

For HTTP providers, open the same payload in the provider's web UI and confirm (1) the raw response matches what the UI shows and (2) the normalized block contains the fields documented in [§2](#2-per-provider-detail). Discrepancies usually mean either (a) the provider changed its response shape and field extraction needs updating, or (b) the endpoint moved (see PhishStats below).

For MaxMind, cross-check against `mmdblookup --file <path> --ip <ip>` (the `mmdb-bin` package) or a reputable third-party tool like ipinfo.io's web UI. Any mismatch usually means the MMDB is stale — run the deploy task again or wait for the monthly cron.

---

## 5. Historical Incidents

### PhishStats endpoint migration (2026-05)

PhishStats retired its `phishstats.info:2096` origin and moved the public API to `api.phishstats.info` on standard port 443. Symptom: Cloudflare HTTP 522 "Connection timed out" on every request, indefinitely. Fixed in [`phishstats.py`](../pipeline/src/lantana/enrichment/providers/phishstats.py) by updating `_BASE_URL`.

If you see 522 against PhishStats again, check the docs URL above — the host may have moved again.

### Workstation TLS verification failures

Homebrew Python builds on macOS sometimes can't chain-validate certs even with `certifi.where()` configured (`curl` works, `httpx` fails with `unable to get local issuer certificate`). Symptom: every provider returns `ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED]`. Workaround: pass `--insecure` to the probe. The production collector on Debian 13 has a working system trust store and is unaffected.

### GreyNoise 404 → "unknown"

GreyNoise returns HTTP 404 for IPs not in its dataset rather than an empty 200. The provider treats this as "no info" and emits a normalized result with `greynoise_classification: "unknown"` and false booleans — not an error. This is the most common GreyNoise response for honeypot attacker IPs that aren't part of mass-scanning campaigns.

### MaxMind silent skip on missing license key

If `vault_apikey_maxmind` is omitted or empty, Ansible's `when:` guards silently skip the MMDB download, extraction, ownership, and cron-update tasks. Vector starts fine — it just emits empty `.geo.*` fields for every event. Symptom: dashboard's geographic page shows "unknown" for every attacker, gold's `geographic_summary` is empty, STIX bundles lack geo context. Fix: add the vault key and re-run `deploy_single.yml` with the `vector` or `collector` tag.

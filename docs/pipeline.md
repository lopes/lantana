# Lantana: Data Pipeline

The Lantana data pipeline is a Python application that processes honeypot telemetry through a three-tier datalake (bronze, silver, gold), producing enriched Parquet datasets, threat intelligence reports, STIX bundles, and an operator dashboard. It runs on the Collector zone as a set of daily batch jobs orchestrated by cron.

---

## 1. Overview

Vector writes raw honeypot logs to the **bronze** layer as NDJSON files. The Python pipeline reads bronze, enriches it with external threat intelligence APIs, normalizes events to [OCSF](https://ocsf.io/) (Open Cybersecurity Schema Framework), redacts infrastructure IPs (OPSEC), and writes the result to the **silver** layer as Parquet. A second stage aggregates silver into the **gold** layer for dashboards and intelligence output.

```
                        Vector (Rust)                          Python Pipeline
                   ~~~~~~~~~~~~~~~~~~~~~~          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Raw Logs ──> Parse ──> Filter ──> GeoIP ──> Bronze ──> API Enrich ──> OCSF Normalize ──> Redact ──> Silver
 (sensor)    (VRL)    (OPSEC     (MMDB)    (NDJSON)   (AbuseIPDB,    (field mapping,    (OPSEC      (Parquet)
              +tag     Layer 1)                        GreyNoise,     class dispatch)    Layer 2)
                                                       Shodan, VT)
                                                                                             │
                                                                                             ▼
                                                                              Gold ──> STIX / Reports / Dashboard
                                                                            (Parquet)   (intelligence output)
```

### Why Python instead of Vector for enrichment and normalization?

Vector handles high-throughput ingest, parsing, noise filtering, and GeoIP enrichment at wire speed. The Python pipeline handles work that doesn't fit a streaming model:

- **API enrichment** requires rate-limited HTTP calls with caching, retries, and backoff -- better suited to async Python with SQLite cache than VRL.
- **OCSF normalization** involves conditional class dispatch (which OCSF event class each raw event maps to) based on event type -- complex branching logic that's easier to test and maintain in Python.
- **OPSEC redaction** is a safety-critical step that benefits from Pydantic validation and comprehensive test coverage.
- **Gold aggregation** produces cross-dataset correlations (behavioral progression, campaign clustering) that require Polars DataFrame operations.

Bronze stays raw. This preserves the option to re-normalize if the OCSF mapping changes without re-ingesting from the honeypots.

---

## 2. Datalake Structure

All data lives under `/var/lib/lantana/datalake/` in Hive-style partitions:

```
/var/lib/lantana/datalake/
├── bronze/                                    # Raw NDJSON (Vector writes)
│   └── dataset={name}/date={YYYY-MM-DD}/server={hostname}/events.json
├── silver/                                    # Enriched + OCSF-normalized Parquet
│   └── dataset={name}/date={YYYY-MM-DD}/server={hostname}/events.parquet
└── gold/                                      # Aggregated intelligence Parquet
    └── {table_name}/date={YYYY-MM-DD}/summary.parquet
```

- **Bronze**: One NDJSON file per dataset/date/server combination. Written by Vector. Contains raw event fields plus Vector-added tags (`dataset`, `server`, `operation`) and GeoIP fields (`geo.*`).
- **Silver**: One Parquet file per partition. Events have OCSF-normalized column names, API enrichment data, and infrastructure IPs replaced with pseudonyms.
- **Gold**: Four aggregated tables per date: `daily_summary`, `ip_reputation`, `behavioral_progression`, `campaign_clusters`. Read exclusively from silver.

Multiple operations coexist via the `operation` column tag, not filesystem partitions.

---

## 3. Pipeline Stages

### 3.1 Bronze to Silver (daily enrichment)

Entry point: `lantana-enrich` (cron: 01:00 UTC, processes yesterday's data).

For each dataset (cowrie, suricata, nftables, dionaea):

1. **Read bronze** NDJSON into a Polars DataFrame
2. **Extract unique source IPs** from attacker events
3. **Query enrichment providers** sequentially (respecting rate limits):
   - AbuseIPDB (abuse confidence, report count, ISP)
   - GreyNoise (classification, noise/riot status)
   - Shodan (open ports, services, vulns)
   - VirusTotal (file hash reputation, for cowrie/dionaea downloads)
   - PhishStats (phishing URL count per IP)
4. **Cache results** in SQLite (7-day TTL) to avoid re-querying
5. **Merge enrichment** columns back into the event DataFrame by source IP
6. **OCSF normalize** -- rename columns and add OCSF metadata (see Section 4)
7. **Redact infrastructure IPs** (OPSEC Layer 2) -- replace destination IPs with pseudonyms
8. **Validate no leaks** -- assert zero infrastructure IPs in any string column
9. **Write silver** Parquet partitioned by dataset/date/server

### 3.2 Silver to Gold (daily aggregation)

Entry point: `lantana-transform` (cron: 02:00 UTC, processes yesterday's data).

Reads all silver Parquet for the target date (cross-dataset), collects into a single DataFrame, and computes 5 gold tables:

#### daily_summary (1 row per date)
Aggregate counts and top-10 lists: total events, unique IPs, unique sessions, auth attempts/successes/failures, commands executed, findings detected, network events, downloads captured. Top-N lists for usernames, passwords, commands, source countries, source IPs, download URLs, and download hashes (SHA256).

#### ip_reputation (1 row per unique source IP)
Per-IP risk profile. Risk score (0-100) weighted composite: AbuseIPDB confidence (30%), auth success (+20), command execution (+25), detection finding (+15), malware download (+20), volume (+10 capped). Includes GeoIP, enrichment data, and dataset cross-references.

#### behavioral_progression (1 row per unique source IP)
Escalation tracking -- the project's core intelligence feature. Classifies each IP into stages:

| Stage | Label | Criteria |
| --- | --- | --- |
| 1 | scan | Only network events (nftables) |
| 2 | credential | Login attempts present |
| 3 | authenticated | At least one successful login |
| 4 | interactive | Commands executed post-auth |

Includes escalation timing (seconds between stages), session counts, and automated bot detection heuristic (rapid credential stuffing with >10 attempts and >5 unique passwords within 120 seconds, or GreyNoise noise flag).

#### behavioral_progression_multiday (1 row per unique source IP, 7-day lookback)
Cross-day escalation tracking. Extends single-day progression by reading a 7-day lookback window of silver data. Detects slow-burn attackers who scan on day 1, attempt credentials on day 3, and go interactive on day 5. Includes:

- `first_seen_date` / `last_seen_date`: calendar day range
- `active_days`: count of distinct days with events
- `progression_velocity_days`: days between first scan and highest stage
- `is_slow_burn`: true if escalation spans 2+ calendar days
- Per-stage first date: when each stage was first reached

#### campaign_clusters (1 row per cluster)
Groups IPs by shared credential pairs (username + password). Only clusters with >= 2 unique IPs. Surfaces botnet-scale credential stuffing campaigns.

### 3.3 Intelligence Output

#### STIX 2.1 Bundles

Generated from gold data via `intel/stix.py`. Each bundle contains:

- **Identity**: Operator identity from `reporting.json`
- **Indicators**: Attacker IPs with risk score >= 40, including STIX patterns (`[ipv4-addr:value = '...']`), confidence scores, and stage-based labels. Slow-burn IPs (multi-day escalation) get a `slow-burn-escalation` label. When multi-day progression data is available, `valid_from` uses the IP's `first_seen_date`.
- **Malware**: Captured file hashes from `daily_summary.top_download_hashes`, with `stix2.Malware` objects and file-hash indicators (`[file:hashes.'SHA-256' = '...']`)
- **Campaigns**: Credential clusters mapped to STIX Campaign objects
- **Relationships**: Links indicators to their associated campaigns
- **Report**: Wraps all objects for the date with TLP marking from config

OPSEC enforcement: the bundle serializer asserts no infrastructure IPs appear in the output. Gold reads only from redacted silver, providing defense in depth.

Available via the Streamlit dashboard (download button) or programmatic API.

#### Discord Intel Reports

Generated from gold data via `notify/report.py`, sent via `lantana-report`.

**Daily brief** (Markdown file attached to Discord embed):
- Key metrics table (events, IPs, auth, commands, findings, downloads)
- Mermaid escalation funnel chart (scan -> credential -> authenticated -> interactive)
- Top 5 attackers by risk score with country and stage
- Notable escalations (IPs reaching stage 3+)
- Campaign clusters (shared credential pairs)
- Malware captured (download count, top URLs, top SHA256 hashes)
- Top credentials and commands

The Discord embed contains a short summary; the full Markdown report is attached as a `.md` file.

#### Streamlit Dashboard

Entry point: `lantana-dashboard`. Five pages:

1. **Overview** -- Metric cards, event type distribution, auth breakdown, top-N tables
2. **IP Reputation** -- Risk distribution, filterable IP table with enrichment details, risk slider
3. **Behavioral Progression** -- Escalation funnel, stage scatter plot, automated vs manual breakdown, multi-day progression (slow-burn IPs, velocity distribution)
4. **Credentials** -- Campaign cluster table, top username/password pairs
5. **STIX Export** -- Bundle preview, generate button, JSON download

The dashboard is the operator's personal console -- never shared externally. Peers receive Discord reports and STIX bundles.

---

## 4. OCSF Normalization

The pipeline normalizes bronze events to OCSF v1.3.0 during the bronze-to-silver transition. Each raw event is classified into an OCSF event class based on its source dataset and event type. The normalization adds OCSF metadata columns, renames fields to OCSF equivalents, and preserves enrichment/partition/GeoIP columns untouched.

### Event Class Dispatch

| Source | Event Filter | OCSF Class | class_uid |
| --- | --- | --- | --- |
| Cowrie `cowrie.login.*` | `eventid starts with "cowrie.login"` | Authentication | 3002 |
| Cowrie `cowrie.command.*` | `eventid starts with "cowrie.command"` | Process Activity | 1007 |
| Cowrie `cowrie.session.file_download` | `eventid == "cowrie.session.file_download"` | File Activity | 1001 |
| Cowrie (other) | fallback | Network Activity | 4001 |
| Suricata alert | `event_type == "alert"` | Detection Finding | 2004 |
| Suricata (other) | fallback | Network Activity | 4001 |
| nftables (all) | all rows | Network Activity | 4001 |
| Dionaea (credential) | `credential_username` present | Authentication | 3002 |
| Dionaea (FTP command) | `ftp_command` present | Process Activity | 1007 |
| Dionaea (other) | fallback | Network Activity | 4001 |

### Cowrie Field Mapping

| Raw Field | OCSF Field | Action | Notes |
| --- | --- | --- | --- |
| `timestamp` | `time` | rename | Event timestamp |
| `src_ip` | `src_endpoint_ip` | rename | Attacker source IP |
| `dst_ip` | `dst_endpoint_ip` | rename | Honeypot destination IP |
| `src_port` | `src_endpoint_port` | rename | Attacker source port |
| `dst_port` | `dst_endpoint_port` | rename | Honeypot destination port |
| `eventid` | `class_uid` | map | Dispatches to OCSF class; consumed |
| `username` | `user_name` | conditional | Login events only; null for others |
| `password` | `unmapped_password` | conditional | Login only; credential intel |
| `input` | `actor_process_cmd_line` | conditional | Command events only; null for others |
| `protocol` | `auth_protocol` / `connection_info_protocol_name` | conditional | Login: auth_protocol. Others: protocol name |
| `shasum` | `file_hash_sha256` | conditional | File download events only; SHA256 hash |
| `url` | `file_url` | conditional | File download events only; download source URL |
| `outfile` | `file_path` | conditional | File download events only; local file path |
| `session` | `session` | preserve | Session ID for behavioral progression |
| `message` | `message` | preserve | Human-readable event description |
| `sensor` | `sensor` | preserve | Source sensor hostname |

Generated OCSF columns: `class_uid`, `category_uid`, `severity_id`, `activity_id`, `type_uid`, `status_id`, `metadata_version`, `metadata_product_name`, `is_cleartext`.

### Suricata Field Mapping

| Raw Field | OCSF Field | Action | Notes |
| --- | --- | --- | --- |
| `timestamp` | `time` | rename | Event timestamp |
| `src_ip` | `src_endpoint_ip` | rename | Attacker source IP |
| `dest_ip` | `dst_endpoint_ip` | rename | Suricata uses dest_ip |
| `src_port` | `src_endpoint_port` | rename | Source port |
| `dest_port` | `dst_endpoint_port` | rename | Destination port |
| `event_type` | `class_uid` | map | Dispatches to OCSF class; consumed |
| `alert_signature` | `finding_title` + `message` | map | Alert: finding_title |
| `alert_signature_id` | `finding_uid` | conditional | Alert events only; cast to string |
| `alert_severity` | `severity_id` | map | Suricata 1=high->4, 2=medium->3, 3=low->2 |
| `proto` | `connection_info_protocol_name` | rename | L4 protocol name |
| `alert_category` | `finding_category` | conditional | Alert classification |
| `alert_action` | `finding_action` | conditional | Allowed/blocked |
| `flow_id` | `flow_id` | preserve | Flow tracking ID |

### nftables Field Mapping

| Raw Field | OCSF Field | Action | Notes |
| --- | --- | --- | --- |
| `timestamp` | `time` | rename | Event timestamp |
| `src_ip` | `src_endpoint_ip` | rename | Source IP |
| `dst_ip` | `dst_endpoint_ip` | rename | Destination IP |
| `src_port` | `src_endpoint_port` | rename | Source port |
| `dst_port` | `dst_endpoint_port` | rename | Destination port |
| `action` | `activity_id` + `message` | map | accept->1 (Open), drop/reject->5 (Refuse) |
| `chain` | `message` | map | Combined with action into message; consumed |
| `protocol` | `connection_info_protocol_num` + `connection_info_protocol_name` | map | Name preserved, also mapped to IANA number |
| `interface_in` | `interface_in` | preserve | Ingress interface |
| `interface_out` | `interface_out` | preserve | Egress interface |
| `length` | `traffic_bytes_in` | rename | Packet length |

### Dionaea Field Mapping

Bronze fields are pre-flattened by Vector: `connection.*` -> `connection_*`, `credentials[]` -> `credential_username`/`credential_password`, `ftp.commands[]` -> `ftp_command`.

| Raw Field | OCSF Field | Action | Notes |
| --- | --- | --- | --- |
| `timestamp` | `time` | rename | Event timestamp |
| `src_ip` | `src_endpoint_ip` | rename | Attacker source IP |
| `dst_ip` | `dst_endpoint_ip` | rename | Honeypot destination IP |
| `src_port` | `src_endpoint_port` | rename | Attacker source port |
| `dst_port` | `dst_endpoint_port` | rename | Honeypot destination port |
| `connection_protocol` | `connection_info_protocol_name` | rename | Service protocol (smbd, httpd, ftpd, mysqld, mssqld, SipSession) |
| `connection_transport` | `connection_transport` | preserve | TCP/UDP/TLS transport |
| `credential_username` | `user_name` | conditional | Login events only; null for plain connections |
| `credential_password` | `unmapped_password` | conditional | Login events only; credential intel |
| `ftp_command` | `actor_process_cmd_line` | conditional | FTP command events only |
| `connection_type` | consumed | map | Only `accept` events reach bronze (filtered in Vector) |
| `src_hostname` | `src_hostname` | preserve | Reverse DNS hostname if available |

Generated OCSF columns: `class_uid`, `category_uid`, `severity_id`, `activity_id`, `type_uid`, `status_id`, `metadata_version`, `metadata_product_name`, `is_cleartext`, `message`.

### Columns Preserved Through Normalization

These columns pass through untouched regardless of dataset:

- **Vector tags**: `dataset`, `server`, `operation`
- **GeoIP** (from Vector MMDB enrichment): `geo.country_code`, `geo.region_code`, `geo.city`, `geo.latitude`, `geo.longitude`, `geo.timezone`, `geo.asn`, `geo.isp`
- **API enrichment** (from Python providers): `abuseipdb_*`, `greynoise_*`, `phishstats_*`, `shodan_*`, `virustotal_*`

---

## 5. OPSEC: Three-Layer IP Redaction Model

Lantana produces shareable intelligence (Discord reports, STIX bundles). The primary OPSEC concern is **external/WAN IP leakage** -- the public-facing addresses that identify the honeypot on the internet. If an attacker or peer discovers these, they can blacklist the honeypot, fingerprint the setup, or map the operator's infrastructure. Only the honeypot owner should know these addresses.

Three layers enforce this, each catching what the previous layer might miss:

### Layer 1: Vector Noise Filter (Sensor/Honeywall)

**Where**: VRL transforms in each honeypot's Vector pipeline, before data leaves the sensor.

**What**: Drops events where the source IP is not an external attacker. Filtered sources: loopback (`127.0.0.0/8`, `::1`), internal network prefixes (`network.prefixes.ipv4`, `network.prefixes.ipv6`). This catches health check probes, inter-zone traffic, and operational noise.

**Why here**: Eliminating noise at the earliest point reduces data volume, prevents internal IPs from reaching the datalake, and avoids polluting enrichment queries with non-attacker IPs.

**Pattern**: Each honeypot role's Vector config includes a `filter_<honeypot>` transform using `ip_cidr_contains!()` against the operation's network prefixes. Every new honeypot role must replicate this filter.

### Layer 2: Silver Redaction (Python Pipeline)

**Where**: `common/redact.py`, called during bronze-to-silver enrichment.

**What**: Replaces infrastructure **destination** IPs with pseudonyms. External/WAN IPs are the primary target (e.g., `172.31.99.129` -> `honeypot-wan`), but internal IPs are also redacted for defense in depth. After replacement, `validate_no_leaks()` scans every string column and asserts zero infrastructure IPs remain -- both direct matches and CIDR containment checks.

**Why here**: Layer 1 filters by source IP; Layer 2 handles destination IPs that appear in event data (the honeypot's own address). This is the last point where the pipeline has access to the real IPs (via `reporting.json` pseudonym map).

**Configuration**: Controlled by `reporting.json` -> `redact.infrastructure_ips`, `redact.infrastructure_cidrs`, and `redact.pseudonym_map`. The Ansible template merges infrastructure IPs from `network.yml` at deploy time.

### Layer 3: Gold/Reports/STIX Absence (Python Pipeline)

**Where**: Gold aggregation, Discord reports, STIX bundles.

**What**: Gold reads exclusively from silver (already redacted). The STIX bundle serializer asserts no infrastructure IPs in the output JSON. Discord reports are generated from gold data only. Reports never contain: honeypot WAN IPs, internal IPs, server hostnames, network topology, SSH admin port, interface names, or CIDRs.

**Why here**: Defense in depth. Even if a bug in Layer 2 allowed a leak into silver, Layer 3 would catch it at output time. The STIX assertion is an explicit programmatic check, not just a data flow guarantee.

---

## 6. Operational Tools

### lantana-prune (retention and disk monitoring)

Entry point: `lantana-prune` (cron: 00:15 UTC daily).

1. **Standard prune**: Delete datalake date partitions and sensor artifacts (downloads, TTY recordings) older than 180 days
2. **Disk check**: Measure filesystem usage on the datalake volume
3. **Warning** (>70%): Send Discord notification via `lantana-notify`
4. **Critical** (>80%): Emergency prune -- delete sensor artifacts older than 14 days (preserves recent forensic evidence), then send critical alert with before/after usage percentages

### lantana-notify (Discord notifications)

Entry point: `lantana-notify --level <info|warning|critical> --title "..." --message "..."`

General-purpose Discord webhook notification utility. Used by:
- `lantana-prune` for disk alerts
- `lantana-report` for daily intel briefs

Webhook URL resolution chain: `--webhook-url` CLI flag > `LANTANA_DISCORD_WEBHOOK` env var > `discord_webhook` in `secrets.json`.

Notifications use Discord embeds with color-coded severity (green=info, orange=warning, red=critical) and optional file attachments. Retries 3 times with exponential backoff on failure.

---

## 7. Deployment

The pipeline is deployed by Ansible as part of the `profile_collector` role:

1. **Source sync**: `pipeline/` directory synced to `/opt/lantana/pipeline/src/`
2. **Virtual environment**: Python 3.13 venv at `/opt/lantana/pipeline/venv/`
3. **Package install**: `pip install` into the venv
4. **Cron schedule** (`/etc/cron.d/lantana-pipeline`):

| Time (UTC) | Command | Description |
| --- | --- | --- |
| 00:15 | `lantana-prune` | Retention + disk monitoring |
| 01:00 | `lantana-enrich` | Bronze -> Silver (yesterday) |
| 02:00 | `lantana-transform` | Silver -> Gold (yesterday) |

All cron jobs run as the `nectar` user (UID 2002), which owns the datalake directories. The pipeline reads `secrets.json` and `reporting.json` from `/etc/lantana/collector/`.

---

## 8. CLI Entry Points

| Command | Module | Description |
| --- | --- | --- |
| `lantana-enrich` | `lantana.enrichment.runner` | Bronze-to-silver daily enrichment |
| `lantana-transform` | `lantana.transform.runner` | Silver-to-gold aggregation |
| `lantana-prune` | `lantana.prune` | Datalake retention + disk monitoring |
| `lantana-notify` | `lantana.notify.cli` | Discord webhook notification |
| `lantana-report` | `lantana.notify.discord` | Generate and send Discord intel reports |
| `lantana-dashboard` | `lantana.dashboard.app` | Streamlit operator console |

---

## 9. Project Layout

```
pipeline/
├── pyproject.toml                    # Dependencies, scripts, tool config
├── src/lantana/
│   ├── common/
│   │   ├── config.py                 # Load secrets.json and reporting.json
│   │   ├── datalake.py               # Read/write bronze, silver, gold partitions
│   │   └── redact.py                 # OPSEC Layer 2: pseudonymization + leak validation
│   ├── models/
│   │   ├── ocsf.py                   # OCSF Pydantic models (schema contract)
│   │   ├── normalize.py              # Bronze -> OCSF normalization functions
│   │   └── schema.py                 # Bronze Polars schema definitions
│   ├── enrichment/
│   │   ├── runner.py                 # Main enrichment orchestrator
│   │   └── providers/                # AbuseIPDB, GreyNoise, PhishStats, Shodan, VirusTotal
│   ├── transform/
│   │   ├── runner.py                 # Gold aggregation orchestrator
│   │   └── metrics.py                # 5 metric functions (summary, reputation, progression, multiday progression, clusters)
│   ├── intel/
│   │   └── stix.py                   # STIX 2.1 bundle generation
│   ├── notify/
│   │   ├── cli.py                    # Discord webhook CLI
│   │   ├── discord.py                # Notification sending + report CLI entry
│   │   └── report.py                 # Markdown daily brief generation
│   ├── dashboard/
│   │   ├── app.py                    # Streamlit entry point + navigation
│   │   └── pages/                    # 5 pages: overview, ip_reputation, progression, credentials, stix_export
│   └── prune.py                      # Retention and disk monitoring
└── tests/                            # 140 tests mirroring src/ structure
```

---

## 10. Dependencies

**Core**: Polars (DataFrames), httpx (async HTTP), Pydantic (validation), tenacity (retries), structlog (logging), stix2 (STIX 2.1), Streamlit (dashboard).

**Dev**: pytest, pytest-asyncio, ruff (lint + format), mypy (strict type checking).

**Target runtime**: Python 3.13+ (Debian 13 native). **Package manager**: uv.

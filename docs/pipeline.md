# Lantana: Data Pipeline

The Lantana data pipeline is a Python application that processes honeypot telemetry through a three-tier datalake (bronze, silver, gold), producing enriched Parquet datasets, threat intelligence reports, and STIX bundles. It runs on the Collector zone as a set of daily batch jobs.

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
- **Gold**: Aggregated metrics tables (daily summaries, IP reputation, behavioral progression, campaign clusters). Read exclusively from silver.

Multiple operations coexist via the `operation` column tag, not filesystem partitions.

---

## 3. Pipeline Stages

### 3.1 Bronze to Silver (daily enrichment)

Entry point: `lantana-enrich` (runs for yesterday's data by default).

For each dataset (cowrie, suricata, nftables):

1. **Read bronze** NDJSON into a Polars DataFrame
2. **Extract unique source IPs** from attacker events
3. **Query enrichment providers** sequentially (respecting rate limits):
   - AbuseIPDB (abuse confidence, report count, ISP)
   - GreyNoise (classification, noise/riot status)
   - Shodan (open ports, services, vulns)
   - VirusTotal (file hash reputation, for cowrie downloads)
4. **Cache results** in SQLite (7-day TTL) to avoid re-querying
5. **Merge enrichment** columns back into the event DataFrame by source IP
6. **OCSF normalize** -- rename columns and add OCSF metadata (see Section 4)
7. **Redact infrastructure IPs** (OPSEC Layer 2) -- replace destination IPs with pseudonyms
8. **Validate no leaks** -- assert zero infrastructure IPs in any string column
9. **Write silver** Parquet partitioned by dataset/date/server

### 3.2 Silver to Gold (daily aggregation)

Entry point: `lantana-transform` (runs for yesterday's data by default).

Reads all silver Parquet for the target date (cross-dataset), collects into a single DataFrame, and computes 4 gold tables:

#### daily_summary (1 row per date)
Aggregate counts and top-10 lists: total events, unique IPs, auth attempts/successes/failures, commands executed, findings detected, network events. Top-N lists for usernames, passwords, commands, source countries, and source IPs.

#### ip_reputation (1 row per unique source IP)
Per-IP risk profile. Risk score (0-100) weighted composite: AbuseIPDB confidence (30%), auth success (+20), command execution (+25), detection finding (+15), volume (+10 capped). Includes GeoIP, enrichment data, and dataset cross-references.

#### behavioral_progression (1 row per unique source IP)
Escalation tracking -- the project's core intelligence feature. Classifies each IP into stages:

| Stage | Label | Criteria |
| --- | --- | --- |
| 1 | scan | Only network events (nftables) |
| 2 | credential | Login attempts present |
| 3 | authenticated | At least one successful login |
| 4 | interactive | Commands executed post-auth |

Includes escalation timing (seconds between stages), session counts, and automated bot detection heuristic (rapid credential stuffing with >10 attempts and >5 unique passwords within 120 seconds, or GreyNoise noise flag).

#### campaign_clusters (1 row per cluster)
Groups IPs by shared credential pairs (username + password). Only clusters with >= 2 unique IPs. Surfaces botnet-scale credential stuffing campaigns.

### 3.3 Intelligence Output

- **STIX bundles**: Machine-readable threat intelligence (indicators, attack patterns, campaigns)
- **Discord reports**: Daily brief + weekly summary with Markdown and Mermaid charts
- **Streamlit dashboard**: Operator console with 5 pages (overview, IP deep-dive, credentials, timeline, STIX export)

---

## 4. OCSF Normalization

The pipeline normalizes bronze events to OCSF v1.3.0 during the bronze-to-silver transition. Each raw event is classified into an OCSF event class based on its source dataset and event type. The normalization adds OCSF metadata columns, renames fields to OCSF equivalents, and preserves enrichment/partition/GeoIP columns untouched.

### Event Class Dispatch

| Source | Event Filter | OCSF Class | class_uid |
| --- | --- | --- | --- |
| Cowrie `cowrie.login.*` | `eventid starts with "cowrie.login"` | Authentication | 3002 |
| Cowrie `cowrie.command.*` | `eventid starts with "cowrie.command"` | Process Activity | 1007 |
| Cowrie (other) | fallback | Network Activity | 4001 |
| Suricata alert | `event_type == "alert"` | Detection Finding | 2004 |
| Suricata (other) | fallback | Network Activity | 4001 |
| nftables (all) | all rows | Network Activity | 4001 |

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

### Columns Preserved Through Normalization

These columns pass through untouched regardless of dataset:

- **Vector tags**: `dataset`, `server`, `operation`
- **GeoIP** (from Vector MMDB enrichment): `geo.country_code`, `geo.region_code`, `geo.city`, `geo.latitude`, `geo.longitude`, `geo.timezone`, `geo.asn`, `geo.isp`
- **API enrichment** (from Python providers): `abuseipdb_*`, `greynoise_*`, `shodan_*`, `virustotal_*`

---

## 5. OPSEC Layers

Lantana's primary OPSEC concern is external/WAN IP leakage. Three layers enforce this:

| Layer | Where | What |
| --- | --- | --- |
| **Layer 1: Vector noise filter** | Sensor/Honeywall | Drops events from non-attacker source IPs (loopback, internal prefixes) before forwarding to collector |
| **Layer 2: Silver redaction** | Python pipeline | Replaces infrastructure destination IPs with pseudonyms (e.g., `10.50.99.100` -> `honeypot-sensor-01`) + validates zero leaks |
| **Layer 3: Gold/Reports absence** | Python pipeline | Gold reads only from silver (already redacted). STIX and Discord reports assert no infrastructure addresses |

---

## 6. CLI Entry Points

| Command | Module | Description |
| --- | --- | --- |
| `lantana-enrich` | `lantana.enrichment.runner` | Bronze-to-silver daily enrichment pipeline |
| `lantana-transform` | `lantana.transform.runner` | Silver-to-gold aggregation (planned) |
| `lantana-prune` | `lantana.prune` | Datalake retention and disk monitoring (planned) |
| `lantana-notify` | `lantana.notify.cli` | Discord webhook notification utility |
| `lantana-report` | `lantana.notify.discord` | Generate and send Discord intel reports (planned) |
| `lantana-dashboard` | `lantana.dashboard.app` | Streamlit operator console (planned) |

---

## 7. Project Layout

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
│   │   └── providers/                # AbuseIPDB, GreyNoise, Shodan, VirusTotal
│   ├── transform/
│   │   ├── runner.py                 # Gold aggregation orchestrator (planned)
│   │   └── metrics.py                # Aggregation functions (planned)
│   ├── intel/
│   │   └── stix.py                   # STIX 2.1 bundle generation (planned)
│   ├── notify/
│   │   ├── cli.py                    # Discord webhook CLI
│   │   └── discord.py                # Report generation + sending (planned)
│   ├── dashboard/                    # Streamlit app (planned)
│   └── prune.py                      # Retention and disk monitoring (planned)
└── tests/                            # Mirrors src/ structure
```

---

## 8. Dependencies

Core: Polars (DataFrames), httpx (async HTTP), Pydantic (validation), tenacity (retries), structlog (logging), stix2 (STIX 2.1), Streamlit (dashboard).

Dev: pytest, pytest-asyncio, ruff (lint + format), mypy (strict type checking).

Target runtime: Python 3.13+ (Debian 13 native). Package manager: uv.

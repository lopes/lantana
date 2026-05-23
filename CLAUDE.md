# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Lantana is a honeypot-as-code platform built on Ansible that deploys and operates IPv4/IPv6 dual-stack honeypots aligned with MITRE Engage principles. It supports single-node (all-in-one) and multi-node (distributed) deployment models using a zoned architecture (Honeywall, Sensor, Collector).

## Deployment Commands

All commands run from `config/ansible/`.

**Single-node deployment:**

```bash
ansible-playbook -i inventories/op_single/inventory.yml playbooks/deploy_single.yml --ask-vault-pass
```

**Multi-node deployment:**

```bash
ansible-playbook -i inventories/op_multi/inventory.yml playbooks/deploy_multi.yml --ask-vault-pass
```

**Deploy honeypots (after base deployment):**

```bash
ansible-playbook -i inventories/<operation>/inventory.yml playbooks/deploy_honeypots.yml
```

**Validate single-node deployment:**

```bash
ansible-playbook -i inventories/op_single/inventory.yml tests/validate-single-node.yml -vvv
```

## Architecture

### Zoned Model

- **Honeywall Zone**: Network control, nftables firewalling, Suricata IDS, egress containment. Never hosts honeypots.
- **Sensor Zone**: Runs honeypots in rootless Podman containers (low-interaction) or as full VMs (high-interaction, multi-node only). Managed by `stigma` user (UID 2001).
- **Collector Zone**: Data ingestion, OCSF normalization, Parquet storage, enrichment via external APIs. Managed by `nectar` user (UID 2002).

In single-node mode, all zones coexist on one host with a dummy interface (`ltn0`) simulating the private network. In multi-node mode, zones run on separate hosts with the honeywall as SSH bastion.

### Operation-as-Inventory

Each deployment is an Ansible inventory under `config/ansible/inventories/op_*`. Clone `op_single` or `op_multi` to create new operations. Each operation has its own `group_vars/all/` with:

- `main.yml` - platform mode, system users, connection settings
- `network.yml` - IP addressing, interface assignments
- `narrative.yml` - deception story, fake host profiles, service versions
- `vault.yml` - encrypted API keys (VirusTotal, AbuseIPDB, GreyNoise, Shodan, Discord)

### Role Hierarchy

- **Atomic roles** do one thing: `base`, `cowrie`, `dionaea`, `suricata`, `firewall`, `network`
- **Composite roles** (`profile_*`) group atomic roles into zone archetypes via meta-dependencies: `profile_honeywall`, `profile_collector`, `profile_sensor_low`
- **Playbooks** select a "Plate" (e.g., `deploy_single.yml`) then add "Toppings" (honeypots via `deploy_honeypots.yml`)

### Honeypots as Plugins

Each honeypot role self-registers by dropping files into three locations:

- Config: `/etc/lantana/sensor/`
- Telemetry: `/etc/vector/conf.d/`
- Firewall rules: `/etc/lantana/honeywall/nftables/sensors/` (auto-included by nftables on reload)

### Network Addressing

- IPv4: `10.50.99.0/24` | IPv6 ULA: `fd99:10:50:99::/64`
- Collector: `.10` | Sensor: `.100` | Honeywall gateway (multi-node): `.1`
- SSH admin: user `lantana`, key-based auth, operator-chosen random ephemeral port (see the deployment contract in `docs/runbook.md`)

### Telemetry Pipeline

Datadog Vector runs across all zones. Logs centralize in `/var/log/lantana/{honeywall,sensor,collector}`. Log rotation is managed via `/etc/cron.d/lantana-logs` triggering configs in `/etc/lantana/logrotate.d/`.

Raw logs in `/var/log/lantana/` are a transient forwarding buffer for Vector, not a system of record. Bronze NDJSON on the collector is the durable copy: raw retention is short (days), lake retention is long (180d). Disk-safety circuit breakers belong at the lake layer (`prune.py`), not in logrotate — size-triggered truncation can drop bytes Vector hasn't yet shipped.

## Project Structure

```
lantana/
  config/ansible/     # Host configuration (Ansible roles, playbooks, inventories)
  infra/terraform/    # Infrastructure provisioning (Proxmox VMs)
  pipeline/           # Data processing pipeline (Python: enrichment, analysis, dashboard)
  scripts/            # Operational scripts (VPS data fetch, injection, dashboard, malware quarantine)
  docs/               # Project documentation
```

## Key Conventions

- Target OS is Debian 13 exclusively
- Ansible config lives at `config/ansible/ansible.cfg` (roles_path, collections_path, pipelining enabled)
- Jinja2 templates (`.j2`) generate nftables rules, Vector pipelines, Cowrie configs, and SSH settings
- Sensors run as rootless Podman containers under `stigma` using Quadlet `.container` files managed by user-scoped systemd
- Firewall rules use `inet` family (dual-stack) in nftables; avoid `ip`-only matches when IPv6 is needed
- `sensor_honeypots` list variable in inventory controls which honeypot roles are dynamically included
- Single-node is the primary deployment model; multi-node exists as an architectural design principle for zone separation

## Python Code Standards (pipeline/)

- **Python 3.13+** (Debian 13 native)
- **Pylance strict mode**: all types declared, no `Any` escape hatches, full type annotations on all function signatures and return types
- **TDD**: write tests first, then implement. Every module has a corresponding test file mirroring the `src/` structure
- **Functional programming style**: pure functions for data transforms, Pydantic models for structured data, push IO to the edges. Prefer Polars expression chains over imperative loops. Minimize side effects.
- **Boring, reliable tooling only**: Polars, httpx, Pydantic, tenacity, structlog, stix2, Streamlit, Plotly. No exotic or trendy dependencies.
- **Linting/formatting**: `ruff` for linting + formatting, `mypy` strict for type checking, `pytest` for tests
- **Package manager**: `uv`

## Shell Script Standards

- Plain POSIX-compatible patterns, standard coreutils only
- No exotic tools or fancy constructs
- Readable and auditable

## Pipeline fail-safe principles

Op_alpha's first end-to-end production run (2026-05-20) surfaced eight distinct defects in sequence, six of which were variations on the same theme: production bronze data didn't match the shape the code assumed. The pipeline now has explicit guards against that whole class of bug, codified as principles that all new pipeline code must follow:

### 1. No single defect cancels more than its scope

A bug in any one dataset's normalize/redact/write must affect only that dataset's silver, never cancel the work for subsequent datasets in the loop. A provider outage must affect only that provider's enrichment columns. A row with malformed data drops just that row.

**Implementation pattern:** `run_enrichment` in `enrichment/runner.py` wraps each dataset's Phase C body in try/except, logging `dataset_processing_failed` with `repr(exc)` and continuing. Use the same pattern in any loop that processes datasets / providers / IOCs independently.

### 2. Failures are loud and structured

Every skip / drop / fallback emits a structlog event with `dataset` (where applicable), `reason`, `count`, and `repr(exc)`. Errors are accumulated into `/var/lib/lantana/datalake/enrichment_errors.json` for daily review. Silence is not success.

**Implementation pattern:** never `except Exception: pass`. The catch-all in `_enrich_iocs_with_provider` records `error_type="unknown"` with `repr(exc)` (not `str(exc)`) so the exception class name reaches the log. Mirror this pattern in any new error path.

### 3. Schema variation is tolerated by construction

Four sub-patterns, all proven necessary by 2026-05-20/21 defects:

- **Nested → flat at dispatcher boundaries.** Vector ships structured fields (`geo`, `alert`) as nested structs; downstream code uses flat dotted names (`geo.country_code`, `alert_severity`). Conversion happens once, in the normaliser's dispatcher (`_flatten_geo_struct` after `normalize_dataset`, `_flatten_suricata_alert_struct` at the top of `normalize_suricata`). Both helpers handle three input shapes: `pl.Struct` (test fixtures construct it that way), `pl.Utf8` JSON-encoded (production path — `read_bronze_ndjson` indiscriminately JSON-stringifies dict-valued fields to stabilise schema inference across heterogeneous rows), and absent (fill with typed nulls).
- **Optional provider columns must be tolerated everywhere.** Any column that exists only when a specific provider succeeded that day (`abuseipdb_*`, `greynoise_*`, `shodan_*`, `vt_*`) is *optional* in every gold metric function. Use the `_optional_first` helper in `transform/metrics.py` — it returns a typed null literal when the column is absent. Never call `pl.col("provider_specific_field")` in `core_aggs`.
- **Cross-dataset columns must be tolerated too.** Cowrie-only columns (`session`, `user_name`, `unmapped_password`, `actor_process_cmd_line`, `file_*`) and suricata-only columns (`finding_title`, `finding_uid`, `finding_category`, `flow_id`) disappear from the diagonal-concat when their dataset's silver write fails. Every gold metric function that references them must call `_ensure_gold_columns(silver)` at the top — that helper backfills typed nulls. Skipping this is defect #10 (2026-05-21 transform crash with `ColumnNotFoundError: session`).
- **Defensive normalize: detect missing required fields, return empty.** When bronze lacks the parser fields a normaliser expects (e.g. nftables without action/chain/src_ip), return `df.clear()` so the runner logs `silver_skipped_empty_after_normalize` and continues. Do not crash, do not write half-formed silver.

### 4. Tests must mirror production shape, not the convenient shape

Test fixtures must not pre-flatten what Vector ships nested. If a future test fixture uses `{"geo.country_code": "BR"}` (dotted-key dict), the test is asserting against the *post-normaliser* shape — make sure the test exercises `normalize_dataset`, not a function that bypasses it. Production-shape fixtures must use `{"geo": {"country_code": "BR", ...}}` (nested struct).

The load-bearing regression test that pipes production-shape fixtures through the whole bronze → silver → gold path lives at `pipeline/tests/test_integration_production_shape.py`. Its fixtures under `pipeline/tests/fixtures/production_shape/bronze/dataset=*/...` are the canonical reference for "what Vector actually produces."

### 5. Rate-limit handling: never retry, dual circuit-breaker

429s mean the provider's quota window (daily/weekly/monthly) is exhausted; tenacity's 2-30 s exponential backoff cannot outwait that. `is_retryable_http_error` in `enrichment/providers/base.py` excludes 429 — the provider raises `httpx.HTTPStatusError` immediately on rate-limit, and the runner's circuit-breaker decides when to bail.

Two thresholds, both required:
- **Consecutive (`CIRCUIT_BREAKER_RATE_LIMIT_THRESHOLD = 5`)** — fast path for fully-exhausted providers with sparse cache: trips on the first 5 IPs in the queue, skips the rest.
- **Cumulative (`CIRCUIT_BREAKER_RATE_LIMIT_CUMULATIVE_THRESHOLD = 30`)** — safety net for providers whose cache holds ~25% of the day's IPs scattered through the sort order (Shodan post-multi-day cache accumulation). Cache hits would otherwise reset the consecutive counter every 4-5 misses and the loop would grind through every IP. Cumulative trips regardless of intervening hits.

Defect #11 (2026-05-21): without these, a Shodan re-run with 4670 IPs / 1243 cache-warm hung for hours stacking up tenacity backoff on the remaining 3427 misses.

### 6. Risk score composition is explicit

`risk_score` is the single number STIX gate, dashboard buckets, and Discord top-5 read. It is composed in two layers — never re-derived ad-hoc:

- **Per-provider sub-scores live in silver.** Every enrichment provider must expose a `<provider>_risk_score` field on a 0..100 scale alongside its raw fields, computed by a module-level `compute_risk_score(...)` helper. Tests for the helper live in the provider's test file. Adding a new provider without a sub-score means the gold composite silently ignores it.
- **Gold composite is mean-of-two.** `enrichment_risk_score` is `pl.mean_horizontal` of the four per-provider scores (skipping nulls). `behavioral_risk_score` is honeypot-activity (auth + commands + downloads + findings). Final `risk_score = (enrichment.fill_null(0) + behavioral) / 2`, clipped 0..100.
- **GreyNoise RIOT short-circuits to 0.** RIOT means the IP is on the Rule-It-Out list (known-benign infrastructure — CDNs, NTP, DNS). When set, `greynoise_risk_score=0` overrides classification, pulling the enrichment mean down. The row stays in silver with full enrichment intact; only the score is overridden. This prevents false-positive Indicators in STIX export and is the only place in the formula where one signal can subtract from another.

Full reference (including all per-provider formulas, worked examples, and the FAQ): [docs/risk-scoring.md](docs/risk-scoring.md). Any change to the formula must update that doc and the test fixtures in `pipeline/tests/test_transform/test_metrics.py::TestRiskScoreDecomposition`.

## Pipeline verification discipline

End-to-end pipeline runs on a live operation consume real provider budget and real time. They are a final verification step, never a feedback loop.

**Free-tier cost model** (no cached IOCs, ~1100 unique attacker IPs/day on op_alpha):

- AbuseIPDB: 1000/day → exhausts before all IPs covered.
- Shodan: 100/month → exhausts in minutes.
- VirusTotal: 4/min throttle + 500/day → dominates wall-clock time (hours).
- GreyNoise Community: 50/week → exhausts fast on busy days.

**Discipline:**

- **Mock first.** `tests/test_enrichment/` patterns (`AsyncMock` + `patch.object(provider._client, "get", ...)`) cover status codes, sparse responses, retries, RetryError unwrapping, and parse errors without an API call. If a change can be validated against mocked unit tests, it must be — before any live run.
- **Gate the live run.** `uv run pytest && uv run ruff check && uv run mypy --strict` must be clean before touching the VPS.
- **Inspect the cache before a re-run.** `sqlite3 /var/lib/lantana/datalake/.enrichment_cache.db "SELECT provider, ioc_type, COUNT(*) FROM cache GROUP BY provider, ioc_type"` tells you how much fresh budget the re-run will burn.
- **Use `--date YYYY-MM-DD` for targeted re-runs** rather than waiting for the 01:00 UTC cron. `write_silver_partition` overwrites the date partition, so a re-run cleanly replaces a partial earlier write.
- **A failed live run is expensive.** It may have burned the day's / month's quota for the providers it reached, blocking the next attempt for 24h+ on AbuseIPDB, until UTC midnight on VT, until the monthly reset on Shodan, and 7 days on GreyNoise.
- **Mid-run hotfix protocol.** If a defect surfaces during an active live run, do not kill the run and do not redeploy mid-flight. Silver write is the last phase — killing means no silver. Let it finish, deploy the fix, then targeted re-run with `--date` after the relevant rate-limit windows reset.
- **Two validation playbooks codify the post-deploy invariants** so verification is mechanical, not eyeball-driven:
  - `config/ansible/tests/validate-single-node.yml` — runs immediately after `deploy_single.yml`. Asserts users, network, firewall, log directories, and (post-2026-05-22) the five `lantana-*.timer` units installed + enabled.
  - `config/ansible/tests/validate-pipeline-cycle.yml` — runs after the first 06:00 UTC cycle. Asserts each pipeline unit's last `Result=success`, `run_summary` in journal, silver+gold parquet presence, `.provider_state.json` exists, no API-key residue in `enrichment_errors.json`, per-provider risk_score columns in silver, gold composite + sub-scores + the GreyNoise RIOT invariant. Defaults `target_date` to yesterday UTC; override with `-e target_date=...`.
  - Visual checks (Discord report rendering, dashboard pages, STIX bundle) stay manual — see `docs/runbook.md` §11.

## Vector deployment discipline

Vector configs span multiple files: `/etc/vector/vector.yaml` (main, with the keepalive blackhole sink) plus every `conf.d/*.yaml` (honeypot pipelines, firewall, receiver). Vector loads them as a single merged tree at startup, but `vector validate <file>` on a single conf.d file usually fails on "No sinks defined" — sinks live in the honeywall's `forward.yaml`, sources/transforms live elsewhere.

A broken VRL fragment renders fine via Ansible's `template` module, the `Restart Vector` task succeeds (systemd starts the process), then Vector exits 78/CONFIG, systemd's restart-on-failure policy kicks in, and you get a crashloop with no source ingestion (2026-05-21 10:47 outage — every cowrie/suricata/nftables event for ~4 hours sat in the source files unshipped).

**Every Ansible task that renders a Vector config must be followed by a merged-tree validation BEFORE Vector restarts:**

```yaml
- name: "Validate full Vector config tree"
  ansible.builtin.shell: >-
    vector validate --no-environment
    /etc/vector/vector.yaml /etc/vector/conf.d/*.yaml
  changed_when: false
```

This is `shell:` (not `command:`) because `vector validate` doesn't accept directory arguments — the glob must be shell-expanded. `firewall/tasks/main.yml` and `profile_collector/tasks/main.yml` already have this task; new roles that render Vector configs must add their own. If the validate fails, the play stops, Vector keeps running on whatever config was previously loaded, and the operator gets the VRL compile error in Ansible output rather than discovering it from a silently-stopped pipeline hours later.

## Daily alerter

`lantana-alert` (CLI + cron at 05:00 UTC) reads `/var/lib/lantana/datalake/enrichment_errors.json`, classifies rows by severity, and posts a Discord embed when the target date is non-clean. Idempotent via `/var/lib/lantana/datalake/.last_alerted` (one date per line); `--force` overrides for debugging. CLI accepts `--date YYYY-MM-DD` for replay.

Severity:
- **Critical** = anything that prevented file creation: `dataset_processing_failed`, `transform_failed` (the latter is appended by `lantana-transform`'s `main()` wrapper when `run_transform` raises).
- **Warning** = everything else — provider degradation, transient errors, rate-limits. Visible in the embed's grouped warning section.

Clean days produce no Discord output. The pipeline never takes a Discord dependency in the hot path — alerter reads the existing NDJSON file the runners already write.

## OPSEC Requirements

Lantana produces shareable intelligence (Discord reports, STIX bundles). The primary OPSEC concern is **external/WAN IP leakage** — the public-facing addresses that identify the honeypot on the internet. If an attacker or peer discovers these, they can blacklist the honeypot, fingerprint the setup, or map the operator's infrastructure. Only the honeypot owner should know these addresses. OPSEC is enforced at every layer:

### Layer 0: Source code, docs, and examples (placeholders only)

The repository is **public on GitHub** (`github.com/lopes/lantana`). Anything committed under `docs/`, `README.md`, `scripts/`, `config/ansible/` (except untracked operation inventories), code comments, or playbook examples is world-readable and search-indexable. Real operator-identifying values must never appear in these files.

- **Never paste a real WAN IP, IPv6 address, hostname, MAC, ASN, domain, server provider account ID, or SSH fingerprint into any tracked file.** This applies to runbooks, READMEs, troubleshooting guides, code comments, commit messages, and PR descriptions.
- **Use reserved documentation ranges in every example:**
  - IPv4 → RFC 5737 TEST-NET blocks: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
  - IPv6 → RFC 3849: `2001:db8::/32`
  - Domains → `example.com`, `example.org`, `example.net` (RFC 2606)
  - ASNs → RFC 5398: `64496–64511`, `65536–65551`
  - Hostnames → archetype-generic (`vps-01`, `sn-01`) — never the real production hostname
- **Real values belong only in operation inventories** (`config/ansible/inventories/op_<name>/group_vars/all/`). These directories are either gitignored or vault-encrypted; treat any path outside them as public.
- **Public IPs as probe payloads are fine** (e.g. `8.8.8.8`, attacker IPs already in OSINT) — they don't identify the operator. The rule is operator-identifying values, not all real IPs.
- **Before editing any doc that includes an IP, hostname, or domain, verify it falls inside one of the reserved ranges above.** When in doubt, ask the user before committing.
- **Heuristic for spotting a real one:** if an example IP isn't in an RFC documentation range, it's almost certainly real. Allocations registered to commercial VPS/cloud providers (OVH, Hetzner, DigitalOcean, Linode, AWS, GCP, Azure, …) are the most common slip — replace any such address with the appropriate reserved range before committing.

### Layer 1: Vector telemetry (noise suppression)

- Every honeypot Vector pipeline must include a `filter_<honeypot>` transform that drops events from non-attacker source IPs before forwarding to the collector
- Dropped sources: loopback (`127.0.0.0/8`, `::1`), internal network prefixes (`network.prefixes.ipv4`, `network.prefixes.ipv6`), and the honeypot's own WAN addresses (`network.honeywall.wan.ipv4`, `network.honeywall.wan.ipv6`)
- This catches health check probes, inter-zone traffic, operational noise, AND outbound-response packets from the honeypot itself (Suricata sees both flow directions, so these would otherwise leak the WAN IP into `src_endpoint_ip` and trip the silver-layer leak validator)
- Pattern: use non-aborting VRL `ip_cidr_contains()` + `?? false` for CIDR checks, exact-match `src != "{{ network.honeywall.wan.ipv4.split('/')[0] }}"` for WAN addresses
- **Every new honeypot role must replicate this filter** — see `suricata.vector.yaml.j2` as the reference (most complete)

### Layer 2: Silver datalake (pseudonymization)

- During bronze-to-silver enrichment, all operation-related IPs are replaced with pseudonyms (e.g., `honeypot-sensor-01`)
- **External/WAN IPs are the primary redaction target** — these are the public addresses in `network.honeywall.wan.ipv4/ipv6` that appear as destination IPs in attacker events
- Internal IPs (`network.prefixes.*`, sensor/collector addresses) are also redacted for defense in depth
- Controlled by `reporting.yml` → `redact.infrastructure_ips` and `redact.pseudonym_map`
- **Redaction runs in two passes:**
  - IP-typed columns (`src_endpoint_ip`, `dst_endpoint_ip`, ...) get exact-match pseudonym swap.
  - Attacker-content columns (`unmapped_password`, `actor_process_cmd_line`, `file_url`, `message`, ...) get substring replacement, because attackers can put the WAN address into any free-text field (defect #9: WAN-as-password) and Vector preserves raw kernel logs in `message` with `DST=<wan>` embedded.
- `validate_no_leaks` is scoped to IP-typed columns only — attacker-content columns can legitimately contain IP-shaped strings (RFC1918 in a password, embedded URLs, etc.) and false-positives there were dropping cowrie silver entirely on busy days.

### Layer 3: Gold / Reports / STIX (complete absence)

- Gold aggregation reads only from silver (already redacted)
- STIX bundles assert no operation-related addresses in any indicator object
- Discord reports generated exclusively from gold data
- Reports never contain: honeypot WAN IPs, internal IPs, server hostnames, network topology, SSH admin port, interface names, CIDRs

## Datalake Architecture

- Per-instance singleton. Multiple operations coexist via `operation` column tag (not filesystem partition)
- Partition scheme (Hive-style): `dataset={name}/date={YYYY-MM-DD}/server={hostname}/`
- Bronze = raw NDJSON (Vector writes). Silver = enriched Parquet (OCSF, redacted). Gold = correlated intelligence (Parquet)
- Cross-honeypot correlation happens ONLY at the gold layer

## Third-Party Integrations

Six integrations across two stages, all keyed in the vault (`vault_apikey_<service>` / `vault_webhook_<service>`):

- **Wire-speed (Vector, local MMDB):** MaxMind GeoLite2 (City + ASN). Foundational integration — every event passes through it before reaching bronze. Ansible downloads the MMDBs at deploy time and refreshes monthly via cron. License key required for download; lookup is offline.
- **Daily batch (Python pipeline, HTTP APIs):** AbuseIPDB, Shodan, VirusTotal (required keys); GreyNoise (free Community endpoint, optional key).

Validation tooling:

- `scripts/probe-mmdb.py` — full-stack MaxMind validation. Reads `vault_apikey_maxmind` from `--secrets <secrets.json>`, downloads the City + ASN tarballs if not already on disk, queries them, and prints raw + Vector-VRL-normalized output. Auto-falls back to `/tmp/lantana/mmdb` when the collector path isn't present.
- `scripts/probe-enrichment.py` — hits each HTTP provider's live API; prints raw upstream response + normalized `EnrichmentResult.data`.

See [docs/integrations.md](docs/integrations.md) for endpoints, free-tier limits, field-extraction tables, and enablement rules.

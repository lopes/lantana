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
- SSH admin: user `lantana`, key-based auth, operator-chosen random ephemeral port (see the deployment contract in `docs/setup.md`)

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
- **Package manager**: `uv`. **Local sync**: `cd pipeline && uv sync --frozen --extra dev` — the `--extra dev` is required because pytest/ruff/mypy live in `[project.optional-dependencies.dev]` and a bare `uv sync --frozen` strips them. The Ansible deploy on the collector intentionally omits `--extra dev`; production runtime deps (polars, plotly, httpx, stix2, …) sit in `[project.dependencies]` and install unconditionally.

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

Full reference (including all per-provider formulas, worked examples, and the FAQ): [docs/risk-scoring.md](/docs/risk-scoring.md). Any change to the formula must update that doc and the test fixtures in `pipeline/tests/test_transform/test_metrics.py::TestRiskScoreDecomposition`.

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
- **Three validation playbooks codify the post-deploy invariants** so verification is mechanical, not eyeball-driven:
  - `config/ansible/tests/validate-single-node.yml` — runs immediately after `deploy_single.yml`. Asserts users, network, firewall, log directories, and the four `lantana-*.timer` units installed + enabled.
  - `config/ansible/tests/validate-sensor-runtime.yml` — runs after `deploy_honeypots.yml` (or `deploy_single.yml`) with a ~30 s settle window. Asserts the cowrie + dionaea Quadlet ownership invariants (`UserNS=keep-id` for cowrie, no `,U` for either), container Status/Health/RestartCount, no log-plugin failure tracebacks since each container's `StartedAt`, the worker holds a write FD on `cowrie.json` / `dionaea.json`, today's bronze NDJSON is fresh within `sensor_freshness_window_seconds` (default 120 s), and no orphan-UID files under the sensor state trees. The executable counterpart to the post-restart manual check pattern from the 2026-06-08 → 2026-06-11 incident loop.
  - `config/ansible/tests/validate-pipeline-cycle.yml` — runs after the first 06:00 UTC cycle. Asserts each pipeline unit's last `Result=success`, `run_summary` in journal, silver+gold parquet presence, `.provider_state.json` exists, no API-key residue in `enrichment_errors.json`, per-provider risk_score columns in silver, gold composite + sub-scores + the GreyNoise RIOT invariant. Defaults `target_date` to yesterday UTC; override with `-e target_date=...`.
  - Visual checks (Discord report rendering, dashboard pages, STIX bundle) stay manual — see `docs/setup.md` §11.

## Vector deployment discipline

Vector configs span multiple files: `/etc/vector/vector.yaml` (main, with the keepalive blackhole sink) plus every `conf.d/*.yaml` (honeypot pipelines, firewall, receiver). Vector loads them as a single merged tree at startup, but `vector validate <file>` on a single conf.d file usually fails on "No sinks defined" — sinks live in `forward-honeywall.yaml` / `forward-sensor.yaml`, sources/transforms live elsewhere.

A broken VRL fragment renders fine via Ansible's `template` module, the `Restart Vector` task succeeds (systemd starts the process), then Vector exits 78/CONFIG, systemd's restart-on-failure policy kicks in, and you get a crashloop with no source ingestion (2026-05-21 10:47 outage — every cowrie/suricata/nftables event for ~4 hours sat in the source files unshipped).

**Every Ansible role that renders a Vector config must `notify:` the merged-tree validate handler BEFORE the Vector restart fires.** The handler lives once in `roles/base/handlers/main.yml`:

```yaml
- name: "Validate Vector config tree"
  become: true
  ansible.builtin.shell: |
    set -e
    extra_files=$(find /etc/vector/conf.d -maxdepth 1 -name '*.yaml' 2>/dev/null || true)
    vector validate --no-environment /etc/vector/vector.yaml $extra_files
  changed_when: false
```

`find` enumerates the conf.d files rather than relying on a shell glob because on a **fresh install** the handler can fire from the base role before any `conf.d/*.yaml` has been templated. In that state the glob `/etc/vector/conf.d/*.yaml` is left literal by the shell, Vector receives a path that doesn't exist, and exits 78/CONFIG — the crashloop the validate is supposed to prevent (2026-05-22 fresh-install regression). When `find` returns empty, `vector validate` runs against just `vector.yaml`, which is fine: no sources/transforms exist yet to interact with the sinks.

Every role that renders Vector configs must `notify:` this handler immediately after the render task, ordered before the "Restart Vector" handler. If the validate fails, the play stops, Vector keeps running on whatever config was previously loaded, and the operator gets the VRL compile error in Ansible output rather than discovering it from a silently-stopped pipeline hours later. The 2026-05-21 10:47 outage (every cowrie/suricata/nftables event for ~4 hours sat in the source files unshipped) is the failure mode being prevented.

## Honeypot deployment discipline

v1.0.0 ships two honeypots: Cowrie (SSH+Telnet) and Dionaea (FTP, HTTP, EPMAP, SMB, MSSQL, MySQL). Several Dionaea decisions are load-bearing — silent failures (status 133, zero bound ports, no log lines) result if any are reverted. The full rationale is in `docs/honeypots.md` and the failure-mode debug recipes are in `docs/troubleshooting.md` — this section is the "don't break it" summary for future contributors.

- **Dionaea image is pinned to `docker.io/dinotools/dionaea:nightly`, not `:latest`.** `:latest` was frozen at 2020-11-30 (0.11.0 release) and has a half-empty config tree; `:nightly` is the actively-rebuilt tag from the same 0.11.0 source. Never switch to `:latest`.
- **Per-service directory overlay, not single-file.** The image's bundled `dionaea.cfg` globs `services-enabled/*.yaml` and `ihandlers-enabled/*.yaml`; a single-file overlay at `dionaea.yaml` is invisible. Lantana renders one `services-enabled/<svc>.yaml` per catalog entry and mounts the dir `:ro` over the image's, replacing the bundled 16 services with our 6.
- **Service catalog drives everything.** `roles/dionaea/defaults/main.yml::dionaea_service_catalog` is the single source of truth — templates iterate it for the per-service yamls, Quadlet `PublishPort` lines, nftables DNAT rules, and the validate-single-node port assertion. Drop or add a protocol by editing the catalog; the rest follows.
- **All service yaml content must be 7-bit ASCII.** The dinotools image runs Python 3.6 + PyYAML, which falls back to the ASCII codec without a BOM. One non-ASCII byte (em-dash, arrow, smart quote) in any `services-enabled/*.yaml` triggers `UnicodeDecodeError` and the *entire* service-registration loop aborts — zero ports bind. Use `--` instead of `—`, `->` instead of `→`. The `dionaea.container.j2` and `dionaea.nft.j2` templates are exempt (their consumers handle UTF-8).
- **Five capabilities must stay added.** Quadlet drops all then adds back `NET_BIND_SERVICE` (privileged ports inside the container), `SETUID` + `SETGID` (entrypoint drops privs via `-u dionaea -g dionaea` — without these dionaea exits 133 silently), `CHOWN` + `FOWNER` (clean `cp -a` ownership preservation during `init_lib`).
- **`ReadOnly=true` is incompatible.** The entrypoint must write seeded configs into `/opt/dionaea/etc/dionaea/`. The Dionaea Quadlet intentionally omits `ReadOnly=true`; containment comes from `DropCapability=ALL` + explicit cap allowlist + rootless user namespace + `NoNewPrivileges=true`.
- **`DIONAEA_FORCE_INIT_CONF=1` + `DIONAEA_FORCE_INIT_DATA=1` env vars must stay set.** Our bind-mounts create the entrypoint's "does the config dir exist?" target as a side-effect, defeating the `test ! -d` check. The two env vars force the seed every boot.
- **SIP is intentionally absent from the v1.0.0 catalog.** The bundled SIP module hits an unfixable sqlite ownership race between the supervisor (container root) and the worker (dionaea user). `:memory:` doesn't help — additional on-disk state in the SIP module fails the same way. The `templates/services-enabled/sip.yaml.j2` template stays in the repo so a future image fix lets us re-enable SIP by adding the catalog entry back. The fintech persona doesn't lose meaningful intel from this gap.
- **Cowrie sub-protocol toggle is via `cowrie.cfg`, not inventory.** Cowrie's SSH (22) and Telnet (23) are governed by `[ssh] enabled` / `[telnet] enabled` flags in `cowrie.cfg.j2`. Cowrie is intentionally simpler than Dionaea — no catalog, no per-protocol directory overlay. Stick with the upstream's single-cfg model.
- **Cowrie health check must use `CMD prefix` format, not `CMD-SHELL`.** The cowrie image has no shell (`sh`) and no `nc` — `CMD-SHELL` silently exits 1 on every check (OCI runtime error goes to stderr, Podman swallows it). The JSON array format `["CMD","python3","..."]` is also broken in Podman 5.4.2: Quadlet passes it as a single-element string array instead of parsing the JSON. The only working format is `HealthCmd=CMD python3 /healthcheck.py` with the probe script mounted from the host. Verify with `podman inspect sensor-cowrie --format "{{json .Config.Healthcheck.Test}}"` — must show `["CMD","python3","/healthcheck.py"]`, not a single-element array. The probe lives at `roles/cowrie/files/healthcheck.py`. Every Quadlet deploy task must `notify:` a restart handler or the running container keeps the old health check config — see `roles/cowrie/handlers/main.yml`.
- **Cowrie ownership flows via `UserNS=keep-id:uid=999,gid=999`, not `,U`.** The `,U` volume flag only chowns at first volume init; when the upstream `cowrie/cowrie:latest` image rebased and bumped the `cowrie` user UID (998 → 999 around 2026-06-08), `,U` did not re-fire and every command session crashed silently on TTY transcript write (`PermissionError: tty/<sid>-Ne.log`). Cowrie still logged login events but Twisted aborted the exec path before emitting `cowrie.command.input` — four days of attacker command intel lost before the symptom surfaced as a downstream pipeline crash. `UserNS=keep-id:uid=999,gid=999` makes the rootless host user (stigma) appear inside the container as cowrie (UID 999), so stigma-owned bind-mount paths are writable by cowrie regardless of `,U`'s init-time semantics. The `999` literal is the only image-UID coupling — review it whenever `cowrie/cowrie:latest` rebases.
- **Dionaea ownership flows from the entrypoint, not `,U`.** Dionaea's image has a two-user runtime — supervisor as container root (UID 0) for privileged setup, worker as dionaea (UID 1000) for everything else, dropped via `-u dionaea -g dionaea`. The entrypoint chowns `/opt/dionaea/var/log/dionaea` and `/opt/dionaea/var/lib/dionaea` to `dionaea:dionaea` on every start, but only the directories — not files inside them. With `,U` on the bind-mount, Podman would race the entrypoint by re-chowning the source tree (including files) back to the container `User=` (root → host stigma) on every start, leaving the worker (UID 1000) unable to truncate-and-open its log files. The Quadlet has no `,U`; the entrypoint is the single source of ownership truth. Recovery for a host with mismatched ownership (worker can't open `dionaea.json`): delete the stale log file and restart the container — see [docs/troubleshooting.md](/docs/troubleshooting.md) "Dionaea Sensor — log_json silent fail" for the full recipe. `UserNS=keep-id` does NOT work here: mapping host stigma → container UID 1000 would break the supervisor's setup phase that expects to be container UID 0.
- **The structural fragility is rolling-tag upstream images + bind-mount ownership flags.** Both incidents above traced back to the same combination: a `:latest` / `:nightly` image rebase (which we silently pull) shifts in-container UIDs, and a `,U` or similar volume flag that fires every container start interacts badly with what the image's own entrypoint expects. The right long-term answer is to build our own images from a pinned upstream git ref and own the in-container UID/GID as a repo constant — see [TODO.md](/TODO.md) "Self-built honeypot images." Until then, every upstream rebase is an operational risk that may surface only days later via the runner-kill-blind-spot path (silent failure → pipeline reads as "no events" → green Discord brief → 4+ days to detect).

## Daily Discord report

`lantana-report` (systemd timer at 06:00 UTC, also runnable on demand) is the **merged daily flow** that absorbed the previous `lantana-alert` step. It reads gold tables for yesterday's date, loads `/var/lib/lantana/datalake/enrichment_errors.json` and classifies rows by severity, then posts a single Discord embed whose color follows the maximum severity (red=critical, yellow=warning, green=clean) with the full Markdown brief attached as a `.md` file. The brief always posts — there's no longer a separate "silent on clean days" alerter step.

Pipeline-health severity (driven by `notify/alerts.py`):
- **Critical** = anything that prevented file creation: `dataset_processing_failed`, `transform_failed` (the latter is appended by `lantana-transform`'s `main()` wrapper when `run_transform` raises).
- **Warning** = provider degradation: timeouts, parse errors, transient HTTP errors.
- **Info** = routine rate-limit exhaustion (`rate_limit`); kept grouped but doesn't turn the embed yellow on its own.

The `lantana-alert` CLI still exists (`lantana.notify.alerts:main`) for off-cycle replay/debug — `sudo systemctl start lantana-alert.service` or `lantana-alert --force --date YYYY-MM-DD` — but its timer was retired when the daily brief absorbed the flow. The pipeline never takes a Discord dependency in the hot path; the report runner reads the NDJSON file the runners already write.

The brief itself is a **reading document, not an IOC dump.** The long-tail IOC inventory was lifted to the dashboard's STIX Export page in 2026-05-26 (one Plotly metric breakdown + a Raw IOC CSV.gz button); the brief footer now points to it. Brief and dashboard widgets share their explanation strings via `notify/explanations.py` (`BRIEF_SECTIONS` + `METRICS` dicts of `WhatWhyHow` triplets) — never add inline `help=` or `st.caption()` literals on a dashboard page when the brief might surface the same widget.

## Enrichment cache lifecycle

The SQLite enrichment cache at `/var/lib/lantana/datalake/.enrichment_cache.db` uses a **tiered per-row TTL** keyed off the provider's own risk_score (`enrichment/runner.py:_classify_ttl`). Numbers match OpenCTI's default decay-rule durations:

| Classification | IPs    | Domains | Hashes  |
|---|---|---|---|
| Benign         | 7 days | 7 days  | 7 days  |
| Malicious      | 60d    | 90d     | 180d    |

A row is "malicious" iff its per-provider `<provider>_risk_score` field (set by the provider's `compute_*_risk_score` helper) is ≥ `RISK_SCORE_MALICIOUS_THRESHOLD` (50.0). Classification happens per-row at write time; `expires_at` is persisted on the row so policy changes don't retroactively re-tier existing entries. The read path filters on `expires_at > NOW()`. Rows with NULL `expires_at` (only possible for entries written before the write path was migrated) read as misses by SQL three-valued logic — exactly the behavior we want.

Adding a new enrichment provider: expose a `<provider>_risk_score` field in the result data and register the field name in `_RISK_SCORE_FIELDS` (`enrichment/runner.py`). Without that the cache classifier can't distinguish malicious from benign and every row falls into the 7-day benign tier.

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

See [docs/integrations.md](/docs/integrations.md) for endpoints, free-tier limits, field-extraction tables, and enablement rules.

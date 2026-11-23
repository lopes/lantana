# AGENTS.md: Guide for AI Agents & Contributors

Lantana is an open-source, honeypot-as-code platform aligned with MITRE Engage, targeting **Debian 13** via **Ansible**, **rootless Podman Quadlets**, **Datadog Vector**, **Suricata**, **nftables**, and a **Python >= 3.13** data pipeline managed with **`uv`**. It enforces **strict TDD**, **mypy `--strict`**, **stdlib-first** tooling (zero Streamlit/Pandas), and **four-layer OPSEC** (public repo placeholders -> Vector edge filter -> Silver pseudonymization -> `127.0.0.1` air-gapped Vigil dashboard). **Never add, install, or import any new Python package or OS tool without explicit maintainer approval.**

---

## 1. Orientation & Documentation Tracks

| Track | Primary Guides |
| :--- | :--- |
| **Architecture & Setup** | [`docs/architecture.md`](docs/architecture.md) · [`docs/setup.md`](docs/setup.md) · [`docs/glossary.md`](docs/glossary.md) |
| **Sensors & Images** | [`docs/honeypots.md`](docs/honeypots.md) · [`containers/`](containers/) (self-owned pinned `ghcr.io/lopes/lantana-{cowrie,dionaea}:v1.5.1`) |
| **Data Pipeline & Intel** | [`docs/pipeline.md`](docs/pipeline.md) · [`docs/risk-scoring.md`](docs/risk-scoring.md) · [`docs/integrations.md`](docs/integrations.md) |
| **Validation & Ops** | [`docs/validation.md`](docs/validation.md) · [`docs/troubleshooting.md`](docs/troubleshooting.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| **Agent Skills** | [`.agents/skills/deploy-sensors/SKILL.md`](.agents/skills/deploy-sensors/SKILL.md) · [`.agents/skills/verify-pipeline/SKILL.md`](.agents/skills/verify-pipeline/SKILL.md) · [`.agents/skills/scaffold-narrative/SKILL.md`](.agents/skills/scaffold-narrative/SKILL.md) |

---

## 2. Workspace & Zoned Architecture Map

| Path | Layer & Responsibility | Key Invariants |
| :--- | :--- | :--- |
| [`config/ansible/roles/`](config/ansible/roles/) | **Zoned Provisioning:** Atomic roles (`base`, `network`, `firewall`, `suricata`, `cowrie`, `dionaea`) composed into `profile_{honeywall,sensor_low,collector}`. | Single-node coexists on `ltn0` (`10.50.99.0/24`, `fd99:10:50:99::/64`); `filter_*` routes directly to `enrich_geo` in memory (no local forwarders). |
| [`config/ansible/inventories/`](config/ansible/inventories/) | **Operation-as-Inventory:** Clone `op_single` / `op_multi` into gitignored `op_<name>` (`main.yml`, `network.yml`, `narrative.yml`, `reporting.yml`, `vault.yml`). | Only `op_<name>/group_vars/all/` holds real WAN IPs, hostnames, or API keys. |
| [`containers/`](containers/) | **Pinned Honeypot Images:** Self-built offline Cowrie (`UID 999`, `patch_offline.py`) & Dionaea (`UID 1000`, `modules=python,emu`, `processors=filter_emu`, `patch_http.py`, `patch_ftp.py`, `lantana_json.py`, non-destructive `entrypoint.sh`). | Built and smoke-tested by `.github/workflows/build-{cowrie,dionaea}.yml`. All Dionaea config/Python files must be 7-bit ASCII. |
| [`pipeline/src/lantana/common/`](pipeline/src/lantana/common/) | **Core I/O & OPSEC:** `config.py`, streaming `\x00`-safe `datalake.py` (atomic Parquet + `read_gold_range`), two-pass `redact.py` (WAN variants + hostnames + SHA-256-only leak errors). | Strictly one-way isolation: `stigma` (UID 2001) prunes its own scratch via `/usr/local/libexec/lantana-sensor-prune` (`lantana-sensor-prune.timer`); `nectar` (UID 2002) never touches `/var/lib/lantana/sensor` and prunes only `nectar`-owned datalake tiers (`prune.py`). |
| [`pipeline/src/lantana/enrichment/`](pipeline/src/lantana/enrichment/) | **Enrichment & IOCs:** Optional providers (`abuseipdb`, `shodan`, `greynoise`, `virustotal` + opt-in commercial GTI), token-bucket `rate_limit()`, behavioral priority queue, SQLite tiered cache. | 429 never retried (dual circuit breaker: `5` consecutive / `30` cumulative); `404` emits `None` risk score (never dilutes). |
| [`pipeline/src/lantana/models/`](pipeline/src/lantana/models/) & [`transform/`](pipeline/src/lantana/transform/) | **OCSF Silver & 7 Gold Tables:** `daily_summary`, `ip_reputation`, `behavioral_progression`, `campaign_clusters`, `geographic_summary`, `detection_findings`, `extracted_iocs`. | Pure Polars transforms, explicit Gold schemas, decoder SIDs `2200000-2260999` excluded, monotonic behavioral-anchored `risk_score`. |
| [`pipeline/src/lantana/intel/`](pipeline/src/lantana/intel/) & [`notify/`](pipeline/src/lantana/notify/) | **STIX 2.1, Discord Brief & Dead-Man's-Switch:** Durable IOC pivot + 7d interactive inbound IPs, stateless D-1/D-2 liveness, live `statvfs` disk %, shared `explanations.py`. | Zero bogus HTTP rules; benign GreyNoise scanners excluded from Threat Actors; `lantana-report` always posts. |
| [`pipeline/src/lantana/dashboard/`](pipeline/src/lantana/dashboard/) | **Air-Gapped Vigil Console:** Stdlib `ThreadingHTTPServer` (`127.0.0.1:8501`), 5 CTI views (`/overview`, `/attackers`, `/behavior`, `/intel`, `/health` + `302` legacy redirects), local `static/vigil.css` & `/static/plotly.min.js`, pure `plotly.graph_objects` (zero Streamlit/Pandas). | Strict `connect-src 'none'` CSP; zero external URLs (`lopes.id`, CDNs, Google Fonts); zero secret values exposed on `/health`. |
| [`config/ansible/tests/`](config/ansible/tests/) & [`pipeline/tests/`](pipeline/tests/) | **Verification Suites:** `validate-{single-node,canaries,sensor-runtime,pipeline-cycle}.yml`, `audit-host-integrity.yml` + mocked unit & production-shape tests (`test_integration_production_shape.py`). | Fixtures mirror nested Vector production shape (`{"geo": {...}}`, `{"alert": {...}}`). |

---

## 3. Golden Rules

### 1. OPSEC Is Non-Negotiable (Layers 0–3)
- **Layer 0 (Public Repo):** Never commit real WAN IPs, IPv6 addresses, hostnames, MACs, ASNs, SSH fingerprints, or credentials. Use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`), RFC 2606 (`example.com`), and RFC 5398 (`64496-64511`).
- **Layer 1 (Vector Edge):** Every sensor/honeywall Vector pipeline strips `^::ffff:` and drops loopback, RFC 1918, link-local, ULA, internal prefixes, and WAN IPs before ingestion.
- **Layer 2 (Silver Redaction):** `redact_infrastructure_ips` scrubs IP columns AND attacker-controlled text (including non-dotted WAN variants, PTR reversals, expanded IPv6, and `infrastructure_hostnames`). `validate_no_leaks` and `_assert_no_infra_leaks` never embed raw leaked values in exception text (SHA-256 prefix only).
- **Layer 3 (Local Dashboard):** `lantana-dashboard` binds strictly to `127.0.0.1:8501` over SSH tunnel (`ssh -L 8501:localhost:8501`).

### 2. Pipeline Fail-Safe Principles
- **Scoped failure isolation:** A single dataset or provider failure never aborts remaining datasets/providers; `transform/runner.py` records `transform_failed` and exits non-zero if any Gold table fails.
- **Loud, structured errors:** Never `except Exception: pass`. Log via `structlog` and persist sanitized errors to `enrichment_errors.json`.
- **Schema variation tolerated by construction:** Flatten nested Vector structs (`geo`, `alert`) at dispatcher boundaries (`pl.Struct`, JSON `pl.Utf8`, or absent); backfill optional/cross-dataset columns via `_ensure_gold_columns()` and `_optional_first()`.
- **Rate limits:** Exclude HTTP `429` from tenacity retries; honor `provider.rate_limit()` via `_AsyncRateLimiter` and trip on `5` consecutive / `30` cumulative 429s.

### 3. One-Way Privilege Boundary, Zero-Egress & Sensor Discipline
- **Security direction:** Strictly one-way (`stigma` -> `vector` -> `nectar`). `stigma` (sensors) has `EACCES` on `nectar`/datalake/secrets, and `nectar` (collector) has zero write ACLs or filesystem reads under `/var/lib/lantana/sensor/` (`lantana-grant-read` is permanently removed). `stigma` prunes its own 14d scratch (3d emergency `>80%`) hourly via root-owned `lantana-sensor-prune.timer` running as `User=stigma` with `O_NOFOLLOW` + `dir_fd`; `nectar` (`lantana-prune`, `00:15 UTC`) prunes only `nectar`-owned datalake tiers (14d verified Bronze, 3d emergency `>80%`, 180d Silver/Gold).
- **100% dark runtime egress:** Both `:v1.5.1` sensor images are non-egressing at the app layer (`patch_offline.py` + `out_addr = 127.0.0.1` for Cowrie; `modules=python,emu` + `patch_ftp.py` for Dionaea), Quadlets enforce `Pull=never` with offline `root` `podman save | runuser -u stigma -- podman load` import, and `firewall-single.nft.j2` logs + `counter drop`s all `meta skuid stigma ct state new` packets across WAN, loopback, and `ltn0`. Non-canary drops escalate to Critical (`sensor_egress_blocked`) via `notify/egress.py` without leaking host WAN IPs.
- **Vector & Quadlets:** Load [`deploy-sensors`](.agents/skills/deploy-sensors/SKILL.md) before editing Ansible roles/Vector/Quadlets. Every Vector template must `notify: "Validate Vector config tree"` before `"Restart Vector"`. Both sensors enforce app-layer `healthcheck.py` + `HealthOnFailure=kill`. Suricata runs non-root (`suricata:suricata` systemd drop-in), disables NIC offloads (`ethtool`), disables raw alert payload/packet dumps + `pcap-log` & `file-store` by default, and host logs enforce `maxsize 100M` + `journald` `SystemMaxUse=200M`.

### 4. Risk Score & STIX 2.1 Invariants
- **Monotonic behavioral-anchored formula** ([`docs/risk-scoring.md`](docs/risk-scoring.md)): pure scanners (`behavioral == 0`) cap at `enrichment * 0.35 <= 35.0` (0.0 if RIOT/benign); interactive attackers (`behavioral > 0`) score `max(behavioral, 0.5 * behavioral + 0.5 * enrichment)` (halved if RIOT/benign).
- **STIX 2.1 pivot:** Durable IOCs come from `extracted_iocs` (malware hashes + `vhash` clusters, outbound C2 IPs, stager URLs/domains, SSH keys). Inbound IPs require `behavioral > 0` AND `risk_score >= 40` (non-RIOT/non-benign) with 7-day `valid_until`.

### 5. Strict TDD, Stdlib-First & Dependency Gate
- Write failing tests first (`Red -> Green -> Refactor`). Keep pure Polars transforms separate from I/O. Zero `Any` escape hatches or `.to_pandas()` calls.
- Sync local dev env with `cd pipeline && uv sync --frozen --extra dev` (Ansible production deploy omits `--extra dev`). Never add OS packages or Python dependencies without confirmation.

---

## 4. Checklists ("How to Add X")

- **Honeypot Sensor Role:** Create `config/ansible/roles/<name>/` dropping config (`/etc/lantana/sensor/<name>`), Vector VRL with Layer-1 OPSEC filter (`/etc/vector/conf.d/<name>.yaml` notifying validate -> restart), dual-stack `inet` nftables (`/etc/lantana/honeywall/nftables/sensors/<name>.nft`), app-layer `healthcheck.py`, `Pull=never` + offline `import_sensor_image.yml`, and read-only `u:vector:rX` POSIX ACL on logs -> register normalizer in `models/normalize.py` + `enrichment/runner.py` + `tests/test_models/test_normalize.py`.
- **Enrichment Provider:** Implement `enrichment/providers/<name>.py` returning `<name>_risk_score` (`None` on `404`, never `0.0`) + `rate_limit()` -> register optional key in `common/config.py`, `secrets.json.j2`, and `_RISK_SCORE_FIELDS` in `enrichment/runner.py` -> update `docs/risk-scoring.md` and `tests/test_enrichment/`.
- **Gold Table / Vigil View:** Add pure metric builder in `transform/metrics.py` + explicit schema + registration in `transform/runner.py` & `validate-pipeline-cycle.yml` -> add rollup in `dashboard/queries.py`, pure `go.*` chart in `dashboard/charts.py`, shared `WhatWhyHow` text in `notify/explanations.py`, route in `dashboard/app.py`, and air-gap test in `tests/test_dashboard/`.

---

## 5. Verification, Branching & Safety Gates

All gates must return **0 errors** before completing work or opening a PR:

```bash
cd pipeline && uv sync --frozen --extra dev
uv run ruff format --check . ../scripts/*.py ../config/ansible/roles/profile_sensor_low/files/lantana-sensor-prune ../containers/cowrie/patch_offline.py
uv run ruff check . ../scripts/*.py ../config/ansible/roles/profile_sensor_low/files/lantana-sensor-prune ../containers/cowrie/patch_offline.py
uv run mypy --strict src tests ../scripts/*.py ../config/ansible/roles/profile_sensor_low/files/lantana-sensor-prune ../containers/cowrie/patch_offline.py
uv run pytest
cd ../config/ansible && ansible-lint playbooks roles tests
cd ../.. && shellcheck scripts/*.sh containers/dionaea/entrypoint.sh
```

- **Pipeline live runs:** Load [`verify-pipeline`](.agents/skills/verify-pipeline/SKILL.md) before touching live API quota or datalake partitions.
- **Git hygiene:** Never commit directly to `main`. Use GPG-signed Scoped Commits (`<scope>: <description>`, no `feat:`/`fix:`/`chore:`/`update:`, no trailing period, no AI trailers). Keep `config/ansible/inventories/op_<name>/` untracked/gitignored.

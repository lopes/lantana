# Lantana pipeline — operational status & next-session hand-off

**Status:** op_alpha pipeline is healthy. 2026-05-22 01:00 UTC cron produced clean silver + gold for 2026-05-21 (all three datasets, all seven gold tables, geographic_summary populated with real countries/cities). No SEV-class issues open.

**Last update:** 2026-05-22 — daily-cron verification, #4 (cron stdout to journal) implemented locally, GreyNoise root-cause understood.

---

## Current production state (op_alpha, sn-01)

**Vector:** active since 2026-05-21 15:06 UTC. Ingesting cowrie + suricata + nftables. Phase 2 nftables parser + Phase 3 City MMDB enrichment confirmed working end-to-end.

**Datalake:** bronze + silver + gold current for 5-21. Historical gap: 5-19 / 5-20 silver have null `geo.country_code/city/region_code/latitude/longitude/timezone` (bronze ingested under broken VRL; not recoverable). ASN was always fine.

**Cron** (`/etc/cron.d/lantana-pipeline`):

| UTC | Job |
|---|---|
| 00:15 | `lantana-prune` |
| 01:00 | `lantana-enrich` |
| 04:00 | `lantana-transform` |
| 05:00 | `lantana-alert` |

After the #4 deploy below, all four pipe stdout+stderr through `logger -t <tag>` — query with `journalctl -t lantana-enrich --since '<date>'`.

**Test suite:** 297 tests, ruff clean, mypy strict clean. `pipeline/tests/test_integration_production_shape.py` is the load-bearing regression harness for the schema-shape bug class.

---

## Recent local changes (committed, awaiting deploy)

### #4 — pipeline jobs migrated from cron to systemd timers

Two Jinja templates in `config/ansible/roles/profile_collector/templates/` (`lantana-pipeline-job.service.j2`, `lantana-pipeline-job.timer.j2`) are looped over the four jobs (prune/enrich/transform/alert) to produce per-job `.service` + `.timer` units in `/etc/systemd/system/`. Schedule unchanged (00:15 / 01:00 / 04:00 / 05:00 UTC). The legacy `/etc/cron.d/lantana-pipeline` is removed by the same play.

**Why this beats the `| logger -t` interim:** native journal capture (no pipe needed), exit code preserved (`systemctl status lantana-enrich.service` shows the real return), `Persistent=true` catches up after downtime (a missed day fires on next boot), and `journalctl -u lantana-enrich.service` is the idiomatic query.

```bash
ansible-playbook -i inventories/op_alpha/inventory.yml playbooks/deploy_single.yml \
  --tags collector,pipeline --ask-vault-pass
```

**Verify after deploy:**
```bash
# Timers active, with next-fire timestamps
ssh sn-01 'sudo systemctl list-timers | grep lantana'

# Cron file gone
ssh sn-01 'sudo cat /etc/cron.d/lantana-pipeline 2>&1 | head'   # → No such file

# After next 01:00 UTC:
ssh sn-01 "sudo journalctl -u lantana-enrich.service --since today | grep run_summary"
```

### AbuseIPDB result trimmed to verdict-only

`enrichment/providers/abuseipdb.py` now returns only `abuseipdb_confidence_score` and `abuseipdb_total_reports`. Dropped: `abuseipdb_country`, `abuseipdb_isp`, `abuseipdb_domain` — MaxMind GeoIP is the source of truth for geo/network attribution, and the duplicates created downstream confusion (which `country` is authoritative if they disagree?). AbuseIPDB now answers only the question we care about: *what's their verdict on this IP?*

**Cache transition:** existing cached rows still contain the dropped fields and will progressively expire over the 7-day TTL. Silver during the transition will retain the columns as sparse data; gold doesn't reference them so nothing breaks. The user-scheduled server wipe will fully reset this; no manual cleanup needed.

### Sensitive query-string redaction in `enrichment_errors.json`

`enrichment/runner.py` now has `_sanitize_error_message` that strips known sensitive URL query parameters (`key`, `api_key`, `apikey`, `token`, `access_token`) before persisting. Applied unconditionally in `_record_error`. Shodan was the immediate motivator (URL-query auth → API key in error strings → into the alerter-readable JSON). Headers-based auth (AbuseIPDB, VT, GreyNoise) was never exposed; the redactor is also forward-looking for future providers.

### Per-provider IP-selection policy + cross-run rate-limit memory

`enrichment/runner.py` gained two complementary mechanisms for tight-quota providers:

* **`subsample_top_n`** — pre-filter the IP list to the N highest-event-count IPs before any HTTP call. GreyNoise policy: 40 IPs (50/week with 10-IP safety margin). Event counts sum across all datasets — a single attacker IP appearing in both cowrie and suricata counts double, matching operator intuition.

* **`skip_window_days`** — persist the last rate-limit trip date per provider to `/var/lib/lantana/datalake/.provider_state.json`. Future runs short-circuit the provider until the window elapses. GreyNoise: 6 days (1-day margin under 7-day quota). Shodan: 28 days (2-day margin under monthly quota). No more burning the same 5 IPs every morning to trip the breaker.

AbuseIPDB and VirusTotal opt out: their daily / per-minute quotas refresh fast enough that skipping isn't useful. Future providers can add policy entries by editing `_PROVIDER_POLICY`.

---

## What's open

### 1. Daily report does not surface enrichment data

**Confirmed gap** after reading `pipeline/src/lantana/notify/report.py` (260 lines, `lantana-report` CLI bound to `notify/discord.py:generate_and_send`):

The `generate_daily_brief` Markdown report consumes these gold tables: `summary`, `reputation`, `progression`, `clusters`, `geographic`, `detection`. Enrichment surfacing audit:

| Provider | Direct surfacing in report | Indirect (via `risk_score`) |
|---|---|---|
| MaxMind | ✓ `top_countries`, `top_asns` (Geographic Origin section) | yes |
| GreyNoise | ✓ `greynoise_name`, `greynoise_class` (Threat Actor Attribution section) | yes |
| AbuseIPDB | ✗ never shown raw | yes — drives `risk_score` × 0.3 |
| Shodan | ✗ never shown raw | yes — `+10` if `vulns` present |
| VirusTotal | ✗ never shown raw | yes — `+10` if `malicious >= 3` |

This explains the operator's "I don't recall seeing Shodan data before" observation. The signal IS computed; the report just hides it. The "Top Attackers" table has columns IP / Risk / Country / Events / Stage — perfect place to add `AbuseIPDB:100 | VT:13 | Shodan:port22+CVE` as a compact "Enrichment" column.

**Fix scope:** add an "Enrichment" column to "Top Attackers", or a separate "Threat Intel Highlights" section. Open design question on which.

### 2. Design proposal — pure-enrichment `risk_score`

**Idea:** add an `enrichment_risk_score` that answers *only* "what do our four threat-intel providers think of this IP?" — separate from the existing `risk_score` in `compute_ip_reputation`, which blends enrichment with behavioural signals (auth attempts, commands executed, downloads). Two scores, two angles.

**Where to compute:** in the enrichment phase (`_build_lookup` post-processing, before `_merge_lookup`). Add it as a per-IP synthesised field alongside the provider columns. Joins onto every event for that IP. Gold can reference it directly without recomputing.

**Proposed formula (sketch, open for iteration):**

```
enrichment_risk_score = 0   # starts at 0, clipped to [0, 100]
  + abuseipdb_confidence_score * 0.4        # max 40 — AbuseIPDB's verdict, our strongest single signal
  + vt_score(vt_malicious_count)            # max 35 — graduated:
                                            #   0:0,  1-2:10,  3-5:20,  6-10:30,  >10:35
  + 15 if shodan_vulns is non-empty         # +15 — known CVE on the IP per Shodan
  + greynoise_score                         # max 20 — see below
  clip(0, 100)
```

**GreyNoise sub-score (where the user's phrasing needs unpacking):**

```
greynoise_classification == "malicious" : +15
greynoise_noise == true AND riot == false: +5      # noise alone is ambiguous (could be Censys / Shadowserver)
greynoise_riot   == true                : -25     # RIOT is BENIGN — known good service IP
```

**Why RIOT is a *negative* signal, not positive:**

GreyNoise has two flags that sound similar but mean opposite things:
- `noise=true` — IP is part of internet-wide background scanning. Could be malicious botnet, could be legitimate research (Censys, Shadowserver, Shodan itself). Ambiguous.
- `riot=true` — IP is on the **Rule-It-Out** list. GreyNoise has explicitly tagged it as known-benign infrastructure: CDNs, NTP servers, DNS resolvers, software update endpoints, etc.

The user's framing "noise and riot from GN" as worst-case is intuitive but inverted for `riot`. The actual GreyNoise worst-case is `classification=malicious` and `riot=false` (never on the rule-it-out list). The pipeline currently uses only `greynoise_noise` (in `compute_behavioral_progression.is_automated`); `classification` and `riot` are stored but not consumed.

**Open questions for this design:**
- Should the existing `risk_score` (combined enrichment+behavior) stay as-is, or be re-derived as `enrichment_risk_score + behavioral_risk_score` (sum, each capped at 50)?
- Should `enrichment_risk_score` live in silver (per-event, joined like other enrichments) or only in gold (per-IP aggregate)?
- Tie-breaker between conflicting signals: if AbuseIPDB says 100 but GreyNoise RIOT says benign, who wins? Current proposal nets out via subtraction (100 × 0.4 = 40, minus 25 from RIOT = 15) — feels right, but worth a real example before locking it.

**Not implemented yet** — landing this requires test fixtures for each scoring branch, decisions on the open questions above, and probably a refactor of `compute_ip_reputation` to consume the new column. Slot it in after #1-#4 are deployed and stable.

---

## Hand-off pointers (for a cold session)

**Read in this order:**
1. `CLAUDE.md` — design principles, especially the redaction layers, `_ensure_gold_columns`, dual circuit-breaker contract, Vector deploy discipline, alerter sketch.
2. `~/.config/claude/projects/-Users-jose-lopes-Projects-lantana/memory/project_progress.md` — point-in-time state, auto-loaded.
3. `git log --oneline --since="2026-05-20 00:00"` — last week's incident response + hardening. Commit messages are the historical record.

**Critical files for pipeline work:**

```
pipeline/src/lantana/
  enrichment/providers/{abuseipdb,shodan,virustotal,greynoise}.py
  enrichment/providers/base.py     # is_retryable_http_error (NO 429!)
  enrichment/runner.py             # circuit breakers, per-dataset try/except
  common/redact.py                 # two-pass redaction (IP + attacker-content)
  models/normalize.py              # geo/alert struct→flat flattening at dispatcher
  transform/metrics.py             # _ensure_gold_columns + _optional_first
  notify/alerts.py                 # severity model + Discord embed
pipeline/tests/
  test_integration_production_shape.py    # load-bearing regression harness
config/ansible/roles/
  profile_collector/tasks/main.yml         # cron + alerter cron entries
  firewall/templates/firewall.vector.yaml.j2    # Phase 2 nftables parser
  base/handlers/main.yml                   # centralised Vector validate→restart
```

**Deploy tags:**
- `--tags pipeline` → Python code only (clone + uv sync + cron).
- `--tags collector` → Vector receiver template + alerter cron + (this PR) updated cron.
- `--tags nftables` / `--tags cowrie` / `--tags suricata` → respective Vector pipelines.

**Ops one-liners:**

```bash
# Cache state per provider
sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c "
import sqlite3
conn = sqlite3.connect('/var/lib/lantana/datalake/.enrichment_cache.db')
for p, t, c in conn.execute('SELECT provider, ioc_type, COUNT(*) FROM cache GROUP BY provider, ioc_type ORDER BY provider'):
    print(f'{p:12} {t:6} {c}')
"

# Force alerter for a specific date
sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-alert --date YYYY-MM-DD --force

# Targeted re-run after rate-limit windows reset (overwrites date partition)
sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-enrich --date YYYY-MM-DD
sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-transform --date YYYY-MM-DD

# Journal-side health checks (post-#4 deploy)
journalctl -t lantana-enrich --since 'today' | grep -E 'run_summary|provider_done'
journalctl -u vector --since '2 hours ago' | grep -iE 'error|warn|enrichment'
```

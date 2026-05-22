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

### `lantana-report` scheduled + missing gold tables wired in

Two more gaps closed in the same pass:

* The report had never been scheduled — only the alerter (non-clean days) fired on a timer. Adds `lantana-report.service` / `.timer` at 06:00 UTC, after the alerter. The operator now gets a daily intel brief regardless of whether the day was clean.
* `notify/discord.py:generate_and_send` previously read only `daily_summary / ip_reputation / behavioral_progression / campaign_clusters` from gold, omitting `geographic_summary` and `detection_findings`. Those tables are `Optional` parameters of `generate_daily_brief`, so the Geographic Origin and Detection Highlights sections were silently dropped from every actual report. Wires both in.

### Phase D — `risk_score` redesign (per-provider sub-scores + composite)

The single `risk_score` column lives on, but its derivation is now two-layered for full traceability. Five commits (`afb266a` → `8b2b3d4`):

* **D.1** — Every enrichment provider emits a `<provider>_risk_score` (0..100) alongside its raw fields. AbuseIPDB passes confidence through; VirusTotal buckets the malicious-engine count; Shodan is tri-state (0 / 25 / 100); GreyNoise has the RIOT short-circuit override.
* **D.2** — `compute_ip_reputation` aggregates the per-provider scores into `enrichment_risk_score` (horizontal mean, skipping nulls) and computes `behavioral_risk_score` separately (auth + commands + downloads + findings). Final `risk_score = (enrichment.fill_null(0) + behavioral) / 2`. The composite is now decomposable, not opaque.
* **D.3** — Discord report's Top Attackers table grew a "Risk" cell showing `composite (enrichment+behavioral)/2` and an "A/V/S/G" column with the four per-provider scores. STIX descriptions include the breakdown. Streamlit dashboard splits into three side-by-side distribution charts. Phase E's stop-gap formatters (`_fmt_abuseipdb` / `_fmt_vt` / `_fmt_shodan`) were dropped — per-provider risk_scores are the cleaner permanent surfacing.
* **D.4** — New `docs/risk-scoring.md` is the analyst's reference (formulas, value tables, four worked examples, FAQ). `docs/pipeline.md` §3.2.1 documents the gold composite. `docs/integrations.md` per-provider sections show the `<provider>_risk_score` column + cross-reference. `CLAUDE.md` gained principle #6 "Risk score composition is explicit" in the pipeline fail-safe section.
* **D.5** — Load-bearing regression test: a GreyNoise RIOT IP with AbuseIPDB=90 and VT=15-malicious comes out at `risk_score ≈ 31.67`, below the STIX gate (40), while still carrying all enrichment in silver/gold. The test will fail loudly if a future refactor accidentally drops the RIOT override.

---

## Post-wipe verification checklist (tomorrow, 2026-05-23)

This is the gating walk-through for the fresh-server deploy. Run the immediate checks within minutes of the Ansible run completing; the "first cycle" checks need to wait for the 06:00 UTC timer fan-out to finish. Everything is read-only.

Replace `<SN01>` with the new sensor IP and `<PORT>` with the SSH port from the new inventory's `group_vars/all/main.yml`.

### Immediate post-deploy (within minutes of `ansible-playbook` finishing)

```bash
# (1) Systemd timers active — five entries with next-fire timestamps.
ssh -p <PORT> lantana@<SN01> "sudo systemctl list-timers --all | grep lantana"
# Expect: lantana-prune.timer / -enrich / -transform / -alert / -report

# (2) Cron file gone (the cron→timer migration removed it).
ssh -p <PORT> lantana@<SN01> "sudo cat /etc/cron.d/lantana-pipeline 2>&1 | head"
# Expect: cat: ... : No such file or directory

# (3) AbuseIPDB provider in the venv reflects today's verdict-only shape.
ssh -p <PORT> lantana@<SN01> "sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c '
from lantana.enrichment.providers.abuseipdb import AbuseIPDBProvider
import inspect, re
src = inspect.getsource(AbuseIPDBProvider.enrich_ip)
print(re.search(r\"data=\{[^}]+\}\", src).group(0))
'"
# Expect: only abuseipdb_confidence_score and abuseipdb_total_reports.

# (4) Vector active and ingesting.
ssh -p <PORT> lantana@<SN01> "sudo systemctl is-active vector && sudo journalctl -u vector --since '5 min ago' | grep -iE 'error|warn' | head"

# (5) Datalake layout present.
ssh -p <PORT> lantana@<SN01> "sudo find /var/lib/lantana/datalake -maxdepth 2 -type d | sort"
# Expect: bronze/, silver/, gold/ — empty until the first events arrive.
```

### After the first full cycle (i.e. after 06:00 UTC on 2026-05-23)

```bash
# (6) Each systemd unit shows last-run success.
ssh -p <PORT> lantana@<SN01> "for u in lantana-prune lantana-enrich lantana-transform lantana-alert lantana-report; do
  echo == \$u ==; sudo systemctl status \$u.service --no-pager | head -10
done"
# Expect each: Loaded: loaded, ActiveState: inactive (dead), Result: success.

# (7) journalctl captures structlog run_summary for enrich + transform.
ssh -p <PORT> lantana@<SN01> "sudo journalctl -u lantana-enrich.service --since '01:00 UTC' | grep run_summary"
ssh -p <PORT> lantana@<SN01> "sudo journalctl -u lantana-transform.service --since '04:00 UTC' | grep run_summary"
# Expect: one structured line per service with silver_rows + provider stats.

# (8) Silver written for active datasets (cowrie + suricata + nftables once Phase 2 events land).
ssh -p <PORT> lantana@<SN01> "sudo find /var/lib/lantana/datalake/silver -name '*.parquet'"

# (9) Gold present, all 7 tables.
ssh -p <PORT> lantana@<SN01> "sudo find /var/lib/lantana/datalake/gold -name '*.parquet' | awk -F/ '{print \$7}' | sort -u"
# Expect: behavioral_progression / behavioral_progression_multiday / campaign_clusters /
#         daily_summary / detection_findings / geographic_summary / ip_reputation

# (10) Provider state file created with shape `{provider: {last_rate_limited: 'YYYY-MM-DD'}}`.
ssh -p <PORT> lantana@<SN01> "sudo cat /var/lib/lantana/datalake/.provider_state.json"
# Empty `{}` is fine on day-1 if no provider tripped its rate-limit breaker.

# (11) enrichment_errors.json contains no API-key residue (Phase B sanitiser working).
ssh -p <PORT> lantana@<SN01> "sudo grep -E 'key=[A-Za-z0-9]{20,}' /var/lib/lantana/datalake/enrichment_errors.json | head"
# Expect: NO output. Any match here is a sanitiser regression.

# (12) Silver contains the expected enrichment columns AND per-provider risk_scores.
ssh -p <PORT> lantana@<SN01> "sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c '
import polars as pl
df = pl.read_parquet(\"/var/lib/lantana/datalake/silver/dataset=cowrie/date=2026-05-22/server=sn-01/events.parquet\")
print({k: any(c.startswith(k) for c in df.columns) for k in [
    \"abuseipdb_\", \"shodan_\", \"vt_\", \"greynoise_\", \"geo.\",
    \"abuseipdb_risk_score\", \"virustotal_risk_score\",
    \"shodan_risk_score\", \"greynoise_risk_score\",
]})
'"
# Expect on a fresh server: greynoise_ may be False (50/week quota tight).
# The other raw fields and the four <provider>_risk_score columns should be True.

# (13) Gold ip_reputation has the Phase D.2 sub-scores + composite.
ssh -p <PORT> lantana@<SN01> "sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c '
import polars as pl
df = pl.read_parquet(\"/var/lib/lantana/datalake/gold/ip_reputation/date=2026-05-22/summary.parquet\")
top = df.sort(\"risk_score\", descending=True).head(5)
print(top.select([
    \"src_endpoint_ip\", \"risk_score\", \"enrichment_risk_score\", \"behavioral_risk_score\",
    \"abuseipdb_risk_score\", \"virustotal_risk_score\",
    \"shodan_risk_score\", \"greynoise_risk_score\",
    \"greynoise_riot\",
]))
'"
# Expect: risk_score ≈ (enrichment + behavioral) / 2 for each row.
# If any IP shows greynoise_riot=True, its greynoise_risk_score MUST be 0.0
# (Phase D.5 short-circuit verification).

# (14) Discord report received at 06:00 UTC with:
#   - Geographic Origin section (top countries + ASNs from MaxMind)
#   - Top Attackers table — "Risk" cell shows `composite (enrichment+behavioral)/2`,
#     "A/V/S/G" column shows per-provider scores (`-` for offline providers)
#   - Threat Actor Attribution section (if any GN data this day)
#   - Detection Highlights section (if Suricata fired)
# Visual check; nothing to ssh.
```

### Acceptance gate

If checks 1-13 all return the expected output: pipeline is healthy on the new server.

If any check fails: don't roll back the wipe — diagnose in place. The most likely failure modes are:
- **(1) failed** → ansible deploy didn't complete; rerun `--tags collector,pipeline`.
- **(6) `Result: failed`** → check journal for that unit; the structured error event names what broke.
- **(9) missing tables** → transform run died after silver. Look for `dataset_processing_failed` in journal.
- **(13) no report** → either secrets.discord_webhook is unset (logs `no_discord_webhook`), or the unit ran but the webhook itself is rate-limited / mis-configured. `systemctl status lantana-report.service` and the journal will say.

---

## What's open

(Empty — Phase D landed across commits afb266a..8b2b3d4. The previous risk_score
design proposal has been implemented end-to-end. See `docs/risk-scoring.md` for
the analyst reference and the "Recent local changes" section above for the
phase-by-phase summary.)

---

## Archive — earlier design proposals (now implemented)

### 1. Design proposal — pure-enrichment `risk_score`

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

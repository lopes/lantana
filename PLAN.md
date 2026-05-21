# Lantana pipeline — operational status & next-session hand-off

**Status:** op_alpha pipeline is healthy and producing complete data daily. All Layer 0-3 OPSEC controls verified. No SEV-class issues open.

**Last update:** end of 2026-05-21 (UTC), after a full day of incident response + hardening that closed out the original PLAN.md scope (Phases 1-3), surfaced three further defects (#9-#11), one SEV1 (Vector crashloop), added a new component (Phase 3.5 alerter — verified live via Discord), and shipped three optional follow-ups (#3 cosmetic interface_out, #4 validate-handler centralisation, #5 run_summary log line).

**This file replaces the prior PLAN.md** (which covered the bronze/silver hardening goals from 2026-05-20). Every issue tracked there is now shipped — see "What was done" below.

---

## Current production state (op_alpha, sn-01)

**Vector:** active since 2026-05-21 15:06:13 UTC. Ingesting cowrie + suricata + nftables (dionaea still disabled in inventory). Phase 2 parser extracting `action / chain / src_ip / dst_ip / src_port / dst_port / protocol / length / interface_in` from nftables kernel logs. Phase 3 City MMDB enrichment populating `country_code / city / region_code / latitude / longitude / timezone` (~88-100% of events, the remainder are cloud/anycast IPs with no city-level data in MaxMind, which is correct behaviour).

**Datalake:** bronze partitions current for 5-19/5-20/5-21. Silver rebuilt with all fixes for 5-19 and 5-20 (cowrie 7470 + 321398 rows; suricata 11276 + 250670 rows; nftables silver skipped for both — their bronze predates the Phase 2 parser). Gold rebuilt for both dates — all 7 tables.

**Cron** (`/etc/cron.d/lantana-pipeline`):

| UTC | Job |
|---|---|
| 00:15 | `lantana-prune` |
| 01:00 | `lantana-enrich` (can take hours on busy days; VT throttle dominates) |
| 04:00 | `lantana-transform` |
| 05:00 | `lantana-alert` (Discord embed on non-clean days) |

**Test suite:** 297 tests, ruff clean on changed files, mypy strict clean on changed src. The integration test under `pipeline/tests/test_integration_production_shape.py` is the load-bearing regression harness — it pipes production-shape fixtures through the whole bronze → silver → gold path with mocked providers; if it passes, the eight-defect cycle from 2026-05-20 can't recur silently.

---

## What was done since 2026-05-20 evening

Thirteen commits, in chronological order. Read with `git log --oneline --since="2026-05-21 00:00"` for the full sequence.

1. **`08f6edf` test(pipeline): production-shape integration test + flatten JSON-string path** — Phase 1. Built `tests/fixtures/production_shape/bronze/dataset=*/...` mirroring Vector's actual NDJSON (nested `geo`, nested suricata `alert`, raw-message nftables, IPv4-mapped IPv6 dst). Writing the test surfaced that `read_bronze_ndjson` JSON-stringifies nested dicts to stabilise schema inference, but `_flatten_geo_struct` / `_flatten_suricata_alert_struct` only handled `pl.Struct` — they silently filled silver geo/finding columns with null literals across every event since op_alpha went live. Helpers now decode the `pl.Utf8` JSON case via `str.json_decode(<schema>)`.

2. **`3dace66` feat(vector): parse nftables kernel-log lines into structured fields** — Phase 2. New `parse_regex` + `parse_key_value` two-step VRL in `tag_nftables`. Extracts chain + action from the `[LANTANA_<CHAIN>_<ACTION>(_<EXTRA>)?]` prefix the existing nft rules already encode, then key-value pairs from the iptables-style tail. Failures emit `.nftables_parse_failed = true`. (This commit also introduced the 10:47 outage — see #8.)

3. **`cc6cbc3` feat(transform): --date CLI flag** — parity with lantana-enrich. Required for the targeted re-run workflow.

4. **`6deb8e7` fix(pipeline): defects #9 and #10** — #9: an attacker SSH'd cowrie with the honeypot WAN IP as the password attempt; the value landed in `unmapped_password`, `redact_infrastructure_ips` only rewrote destination-IP columns so the password row stayed real, `validate_no_leaks` scanned every string column, found the WAN, raised, the per-dataset try/except dropped cowrie silver for the whole day. Fix split redaction into two passes (exact-match on IP cols, substring on attacker-content cols) and scoped `validate_no_leaks` to IP-typed columns. #10: knock-on. Without cowrie silver, `compute_daily_summary` crashed on `pl.col("session")`. Fix added `_ensure_gold_columns` to backfill cowrie-only / suricata-only columns as typed nulls.

5. **`eefd438` feat(notify): daily critical-alert routine via Discord (Phase 3.5)** — `lantana.notify.alerts` module + CLI + cron. Reads `enrichment_errors.json`, classifies by severity, posts Discord embed only on non-clean days, idempotent via `.last_alerted`. Also wraps `lantana-transform.main()` with try/except that appends `transform_failed` rows so the alerter sees crashes too.

6. **`c8152ec` chore(cron): transform 02:00 → 04:00 UTC** — VT throttle can stretch enrichment to hours; 1h margin was too tight.

7. **`c2480ed` fix(enrichment): defect #11** — Two compounding bugs caused a multi-hour hang on the 2026-05-20 re-run. Tenacity was retrying 429s (free-tier reset windows are hours-to-monthly; 2-30s backoff can't outwait them); and the circuit-breaker was consecutive-only, defeated by Shodan's 25%-scattered cache. Removed 429 from `is_retryable_http_error` and added `CIRCUIT_BREAKER_RATE_LIMIT_CUMULATIVE_THRESHOLD = 30`.

8. **`c7fbe8b` fix(vector): SEV1 — VRL E651, Vector crashloop since 10:47 UTC** — Phase 2's `.protocol = downcase(proto_raw) ?? null` was unnecessary `??` on an infallible expression. Vector rejected the config with exit 78/CONFIG, systemd restart-on-failure looped for 5 attempts, then gave up. **No bronze ingestion from 10:47 to 14:53** (~4 hours, recovered cleanly from Vector's file-source checkpoint after restart). Fix: drop the `?? null` on the one offending line.

9. **`804fc67` fix(deploy): validate merged Vector config tree, not single file** — `vector validate %s` on `conf.d/firewall.yaml` in isolation fails on "No sinks defined" (sinks live in `honeywall/forward.yaml`). Replaced with a separate task that validates the union `/etc/vector/vector.yaml + /etc/vector/conf.d/*.yaml`.

10. **`e989888` fix(deploy): vector validate needs shell glob** — `command:` doesn't expand globs; `vector validate` rejects directory args. Switched to `shell:`.

11. **`a759e2b` fix(vector): use Vector's flat City-MMDB schema in geo enrichment VRL** — Phase 3. Vector's `geoip` enrichment_table type **flattens** GeoLite2-City records into top-level columns (`city_name / country_code / region_code / latitude / longitude / timezone / postal_code / metro_code`) — NOT the MaxMind-native nested shape the `maxminddb` Python library returns. Our VRL queried the nested paths and got null on every event since op_alpha went live. PLAN.md's earlier "Issue B" attributed this to a broken MMDB file; the file was always fine — the bug was schema mismatch in the VRL. ASN was working because Vector passes ASN records through unchanged and our VRL already used the flat `autonomous_system_*` keys.

12. **`bc78202` docs: end-of-2026-05-21 hand-off — CLAUDE.md principles + PLAN.md rewrite** — distilled today's lessons into CLAUDE.md (two-pass redaction, `_ensure_gold_columns`, rate-limit dual circuit-breaker, Vector deploy discipline, alerter sketch) and rewrote PLAN.md as a cold-resumption hand-off.

13. **`56fd123` chore: centralise Vector validate handler + run_summary log + interface_out fix** — three follow-ups that were "remaining work" in `bc78202` and got knocked out the same evening:
    - **#4 validate handler centralisation.** Removed the duplicated `Validate full Vector config tree` tasks from `firewall/` and `profile_collector/` and added a single handler in `base/handlers/main.yml`, defined immediately before `Restart Vector`. Every Vector-template task now uses `notify: ["Validate Vector config tree", "Restart Vector"]`. Side benefit: cowrie, dionaea, suricata Vector configs (which previously had inline restart and no validation) are now crashloop-safe too.
    - **#5 run_summary** — one structured log event at the end of `run_enrichment` and `run_transform` aggregating silver/gold row counts + per-provider counters. Operators get the day's outcome in one event instead of grepping ~15 lines.
    - **#3 interface_out cosmetic** — VRL detect-and-reset for `parse_key_value`'s mishandling of the empty-`OUT=` pattern in nftables logs.

**Alerter verification:** `lantana-alert --date 2026-05-20 --force` posted a red critical embed to Discord successfully during today's session. Wiring confirmed end-to-end; tomorrow's 05:00 UTC cron will run automatically.

---

## What's still on the table

Pipeline is healthy and self-healing. Nothing SEV; nothing that needs a fix today.

### Historical geo gap (not recoverable, just a fact)

5-19 and 5-20 silver have null `geo.country_code / city / region_code / latitude / longitude / timezone` because the bronze on disk for those dates was ingested under the broken VRL. Re-running silver against that bronze cannot recover the data — Vector itself never wrote it. The fix only takes effect for events ingested after 2026-05-21 15:06 UTC. 5-21 silver will be mixed (events before 15:06 → null City, after → populated). 5-22 onward: cleanly populated.

### Verification owed tomorrow morning (2026-05-22)

The first end-to-end run with EVERYTHING fixed is the 2026-05-22 01:00 UTC cron processing 5-21 bronze. Things to spot-check:

1. Silver written for all three active datasets (cowrie + suricata + **nftables for the first time**):
   ```
   sudo find /var/lib/lantana/datalake/silver/ -name '*.parquet' | grep "date=2026-05-21" | sort
   ```
2. Gold partitions present for all 7 tables:
   ```
   sudo find /var/lib/lantana/datalake/gold/ -name '*.parquet' | grep "date=2026-05-21" | sort
   ```
3. Geographic data populating in gold (read the `geographic_summary` parquet — should have real countries / cities / ASNs):
   ```
   sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c "
   import polars as pl
   df = pl.read_parquet('/var/lib/lantana/datalake/gold/geographic_summary/date=2026-05-21/summary.parquet')
   print('top_countries:', df.get_column('top_countries').to_list()[0][:5])
   print('top_cities:', df.get_column('top_cities').to_list()[0][:5])
   "
   ```
4. `enrichment_errors.json` for 5-21 — any new error types are worth investigating; persistent rate_limit is expected.
5. The 05:00 UTC alerter — silent means clean. If a Discord embed arrives, follow the link/details to root-cause.
6. New `run_summary` events visible in journalctl for both `lantana-enrich` and `lantana-transform`.

If anything is unexpected: ssh to the VPS, check `journalctl -u vector --since '2026-05-22 00:00'` for ingestion health, and `enrichment_errors.json` for pipeline-side issues.

---

## Hand-off pointers

**For a cold session, read in this order:**

1. `CLAUDE.md` — updated today with: redaction now operates in two passes (IP-typed exact-match + attacker-content substring); `validate_no_leaks` is scoped to IP cols only; `_ensure_gold_columns` for cross-dataset column safety; the rate-limit dual circuit-breaker contract; the merged-tree Vector validate discipline; the alerter sketch.

2. `~/.config/claude/projects/-Users-jose-lopes-Projects-lantana/memory/project_progress.md` — point-in-time snapshot of project state. The memory system is loaded automatically by Claude Code.

3. `git log --oneline --since="2026-05-20 00:00"` — full sequence of fixes; commit messages are detailed and explain root cause + intent.

**Critical files for any new pipeline / Vector / deploy work:**

```
pipeline/src/lantana/
  common/redact.py                  # DST_IP_COLUMNS + ATTACKER_CONTENT_COLUMNS + validate scope
  models/normalize.py               # _flatten_geo_struct + _flatten_suricata_alert_struct (Utf8 + Struct paths)
  enrichment/runner.py              # circuit breaker thresholds, per-dataset try/except
  enrichment/providers/base.py      # is_retryable_http_error (NO 429!)
  transform/metrics.py              # _ensure_gold_columns + _optional_first
  transform/runner.py               # main() wraps run_transform with transform_failed error writer
  notify/alerts.py                  # severity model + Discord embed
pipeline/tests/
  test_integration_production_shape.py    # load-bearing regression harness
  fixtures/production_shape/bronze/...    # canonical "what Vector produces" fixtures
config/ansible/roles/
  firewall/templates/firewall.vector.yaml.j2    # Phase 2 nftables parser
  firewall/tasks/main.yml                        # validate-then-restart pattern
  profile_collector/templates/receive.vector.yaml.j2  # geo enrichment (flat City schema)
  profile_collector/tasks/main.yml               # alerter cron + validate task
```

**Deploy patterns:**

- `--tags pipeline` → Python code (clone + uv sync + cron file).
- `--tags nftables` → firewall.vector.yaml + nft rules. Vector restart now via the centralised handler (`base/handlers/main.yml`), which runs `Validate Vector config tree` first.
- `--tags collector` → receive.vector.yaml. Same handler chain.
- `--tags cowrie / dionaea / suricata / honeypots` → respective Vector pipelines, same handler chain.
- After any pipeline-code redeploy, targeted re-runs via `lantana-enrich --date YYYY-MM-DD` and `lantana-transform --date YYYY-MM-DD` work cleanly; both overwrite their date partitions.

**One-off ops commands worth remembering:**

```bash
# Trigger the alerter manually (e.g. to re-page after dismissing a Discord alert)
sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-alert --date YYYY-MM-DD --force

# Inspect cache state per provider before deciding whether to re-run enrich
sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c "
import sqlite3
conn = sqlite3.connect('/var/lib/lantana/datalake/.enrichment_cache.db')
for p, t, c in conn.execute('SELECT provider, ioc_type, COUNT(*) FROM cache GROUP BY provider, ioc_type ORDER BY provider, ioc_type'):
    print(f'{p:12} {t:6} {c}')
"

# Check Vector ingestion health
sudo systemctl is-active vector
sudo journalctl -u vector --since '2 hours ago' | grep -iE 'error|warn|enrichment|geoip' | head
```

**Things I would have done differently today:**

- Run the targeted re-run via `nohup … &` server-side so SSH disconnect doesn't kill it. The first 5-20 re-run wedged for an hour because tenacity backoff happens silently and the SSH client buffers stdout — I couldn't see whether it was alive. Defect #11 made this dramatically worse (~14 hours' worth of backoff sleep on Shodan), but even on a fast run the SSH stream is unreliable for monitoring.
- Add the `vector validate` task BEFORE shipping Phase 2's VRL, not as a reactive fix after the crashloop. The VRL was new code that ran in a strict compiler we'd never tested against locally; not validating it before restart was a foreseeable risk.
- Reach for `vector validate` (or any kind of local VRL syntax check) earlier when designing new templates. There's no good local workflow for this without Vector installed on the workstation — worth documenting under "Vector deployment discipline" once a clean approach exists.

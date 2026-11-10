---
name: verify-pipeline
description: >-
  Operational verification, free-tier API quota protection, SQLite enrichment
  cache inspection, targeted date re-runs, and post-cycle validation for the
  Lantana Python bronze-silver-gold pipeline. Load before running or debugging
  live enrichment, transform, or reporting cycles.
---

# Lantana Pipeline Verification & Quota Discipline (`verify-pipeline`)

End-to-end pipeline runs on a live operation consume real provider budget and wall-clock time. They are a **final verification step, never a dev feedback loop**.

---

## 1. Free-Tier Cost Model (~1,100 Unique Attacker IPs/Day)

| Provider | Free-Tier Quota | Exhaustion Behavior | Reset Window |
| :--- | :--- | :--- | :--- |
| **AbuseIPDB** | 1,000 / day | Exhausts before all daily IPs are covered | 24h rolling |
| **Shodan** | 100 / month | Exhausts in minutes | Monthly reset |
| **VirusTotal** | 4 / min + 500 / day | Dominates wall-clock time (hours) | UTC midnight |
| **GreyNoise Community** | 50 / week | Exhausts fast on busy days | 7 days |

---

## 2. Pre-Flight & Re-Run Protocol

1. **Mock First:** Validate all status codes, sparse payloads, retries, `RetryError` unwrapping, and parse errors against mocked unit tests (`tests/test_enrichment/` using `AsyncMock` + `patch.object(provider._client, "get", ...)`) before any live run.
2. **Offline Quality Gate:** Must return `0` errors before touching the VPS:
   ```bash
   cd pipeline && uv run pytest && uv run ruff check && uv run mypy --strict
   ```
3. **Inspect SQLite Enrichment Cache Before Re-Running:** Check how much fresh quota a re-run will burn:
   ```bash
   sqlite3 /var/lib/lantana/datalake/.enrichment_cache.db \
     "SELECT provider, ioc_type, COUNT(*) FROM cache WHERE expires_at > datetime('now') GROUP BY provider, ioc_type;"
   ```
4. **Targeted Date Re-Runs (`--date YYYY-MM-DD`):** Never wait for the 01:00 UTC `lantana-enrich.timer` when verifying a fix. `write_silver_partition` overwrites the target date partition cleanly.
5. **Mid-Run Hotfix Protocol (Never Kill an Active Run):**
   - If a defect surfaces during an active live run, **do not kill the run and do not redeploy mid-flight**.
   - Silver write is the final phase — killing a run means zero silver written while burning the provider quota already spent. Let the run finish, deploy the fix, and run a targeted `--date` re-run after rate-limit windows reset.

---

## 3. Post-Cycle Mechanical Validation

After the 06:00 UTC cycle (or an on-demand run), verify mechanically from `config/ansible/`:

```bash
ansible-playbook -i inventories/op_single/inventory.yml tests/validate-pipeline-cycle.yml -e target_date=YYYY-MM-DD
```

This asserts:
- Every pipeline systemd unit's last `Result=success` and `run_summary` in journald.
- Silver and Gold Parquet presence (all 6 gold tables) and `.provider_state.json`.
- Zero API-key residue in `/var/lib/lantana/datalake/enrichment_errors.json`.
- Per-provider `<provider>_risk_score` columns in silver, gold composite + sub-scores, and the GreyNoise RIOT short-circuit invariant (`greynoise_risk_score == 0`).

For off-cycle Discord brief replay/debug (`lantana-report` absorbed `lantana-alert`):
```bash
lantana-alert --force --date YYYY-MM-DD
```

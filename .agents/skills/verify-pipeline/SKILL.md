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

## 1. Provider Quota & Optional-Key Model (v1.5)

All provider API keys are optional (`str | None = None`); unconfigured providers skip cleanly without firing `401` errors. Enrichments are sorted by behavioral priority (`is_c2_ip`, `downloads`, `commands`, `auth_attempts`, `findings`, `event_count`) and paced by `_AsyncRateLimiter`.

| Provider | Free-Tier Quota | Queue / Pacing Behavior | Reset Window |
| :--- | :--- | :--- | :--- |
| **AbuseIPDB** | 1,000 / day | 1 req/s, behavioral priority order | 24h rolling |
| **Shodan** | 100 / month | 1 req/s, 28d skip window after 429 | Monthly reset |
| **VirusTotal / GTI** | 4 / min + 500 / day (free) | Unified queue (`hashes -> C2 IPs -> URLs -> domains -> inbound IPs`), `480`/day free cap, `x-tool: Lantana`, free `vhash`, opt-in `gti_enabled` | UTC midnight |
| **GreyNoise Community** | 50 / week | 1 req/s, top-40 behavioral subsample, 6d skip window | 7 days |

- HTTP `404` emits `None` for `<provider>_risk_score` (never dilutes `enrichment_risk_score`) and logs at `info` severity.
- HTTP `429` is never retried; dual circuit-breaker trips at `5` consecutive or `30` cumulative 429s.

---

## 2. Pre-Flight & Re-Run Protocol

1. **Mock First:** Validate all status codes, sparse payloads, rate-limiter pacing, and parse errors against mocked unit tests (`tests/test_enrichment/`) before any live run.
2. **Offline Quality Gate:** Must return `0` errors before touching the VPS:
   ```bash
   cd pipeline && uv sync --frozen --extra dev
   uv run ruff format --check . ../scripts/*.py
   uv run ruff check . ../scripts/*.py
   uv run mypy --strict src tests ../scripts/*.py
   uv run pytest
   ```
3. **Inspect SQLite Enrichment Cache Before Re-Running:** Check active cached entries (`ip`, `hash`, `url`, `domain`):
   ```bash
   sqlite3 /var/lib/lantana/datalake/.enrichment_cache.db \
     "SELECT provider, ioc_type, COUNT(*) FROM cache WHERE expires_at > datetime('now') GROUP BY provider, ioc_type;"
   ```
4. **Targeted Date Re-Runs (`--date YYYY-MM-DD`) & Dry-Run Brief:**
   ```bash
   sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-enrich --date YYYY-MM-DD
   sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-transform --date YYYY-MM-DD
   sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-report --date YYYY-MM-DD --dry-run --output /tmp/brief.md
   ```
5. **Mid-Run Hotfix Protocol (Never Kill an Active Run):**
   - Silver writes run in Phase C after enrichment. Killing a live run mid-flight wastes spent quota with zero Silver output. Let it finish, deploy the fix, then run a targeted `--date` re-run.

---

## 3. Post-Cycle Mechanical Validation

Run from `config/ansible/`:

```bash
ansible-playbook -i inventories/<op>/inventory.yml tests/validate-pipeline-cycle.yml -e target_date=YYYY-MM-DD
```

Asserts:
- All pipeline systemd units (`lantana-{prune,enrich,transform,report}`) ended with `Result=success` and emitted `run_summary`.
- Silver Parquet exists for all active datasets (`cowrie`, `dionaea`, `suricata`, `nftables`).
- All **7 Gold tables** exist (`daily_summary`, `ip_reputation`, `behavioral_progression`, `campaign_clusters`, `geographic_summary`, `detection_findings`, `extracted_iocs`).
- `.provider_state.json` exists and `enrichment_errors.json` contains zero API-key or infra IP residue.
- Silver carries all four `<provider>_risk_score` columns; Gold `ip_reputation` has zero null `src_endpoint_ip`, pure-scanner `risk_score <= 35.0`, and GreyNoise RIOT `greynoise_risk_score == 0.0`.

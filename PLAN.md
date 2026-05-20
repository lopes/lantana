# Bronze/Silver hardening: fail-safe by construction

**Status:** designed, not implemented. Pick this up cold. The current state of the codebase is fully committed.

**Created:** 2026-05-20 evening, at the end of op_alpha's first end-to-end production run. Captures the lessons from a full day of debugging the pipeline against real bronze data.

**Supersedes:** the previous `PLAN.md` (enrichment refactor — IOC-first, cache, error classification). Every goal from that plan is now committed and live; see `git log --oneline --since="2026-05-20 00:00:00"`. This new plan picks up what's still fragile or broken after that work.

---

## Context (read first)

Op_alpha is Lantana's first end-to-end production deploy on an OVH VPS. The pipeline went live 2026-05-19; on 2026-05-20 we attempted the first complete daily run end-to-end. The run surfaced **eight defects in sequence**, each blocking the next:

| # | Symptom | Root cause | Fix commit |
|---|---|---|---|
| 1 | Cowrie batch `enriched=0` despite working providers | Cache hits returned bool not data → silently dropped | `142c0f6` |
| 2 | Every error logged as `error_type=unknown` | Tenacity wrapped exceptions in `RetryError`; classifier never saw the real status | `9409006` |
| 3 | Same IP queried multiple times across datasets | Per-dataset enrichment, no global IOC dedup | `a2abc73` |
| 4 | Shodan / VT 200 responses crashed with `KeyError('asn')` / `KeyError('as_owner')` | Provider parse code assumed every documented field present | `f116454` |
| 5 | `fe80::*` and `10.x.x.x` IPs sent to providers, wasting budget | OPSEC filter only matched the operation's own infra, not all non-routable ranges | `03cd39b` |
| 6 | Honeypot's own WAN IP appeared in `src_endpoint_ip` and tripped the leak validator | Vector L1 filter only excluded internal CIDRs, not the WAN; redact layer only operated on dst columns | `57a426a` + `2385185` |
| 7 | One dataset's normalize crash blocked silver for all subsequent datasets | Phase C loop unwrapped | `fc768cb` |
| 8 | `lantana-transform` crashed three times in a row: extra `sensor` column, missing `geo.country_code`, missing `abuseipdb_confidence_score` | Production silver shape didn't match what transform assumed; test fixtures pre-flattened the same fields | `5583a57` + `ecc679b` + `b7e5bc9` |

Plus: PhishStats started returning HTTP 401/403 on every request, intel value was marginal anyway → dropped (`0965742`). Nftables bronze turned out to be raw `message` strings (Vector isn't parsing the log format) → defensive normalize skips it (`fc768cb` again).

**The pattern across all eight defects** is the same: production bronze (or production runtime conditions) differs from what the test fixtures and code assumed. Fixtures pre-flatten nested structs, never miss optional fields, and assume every provider succeeds. Production does none of those things. Each defect required a separate live debug cycle — and one of those cycles cost 6 hours of API budget plus a half-empty silver partition before the next defect emerged.

The runner is now robust to most known failure modes. **What's still fragile** is the principle: when a bronze defect or a provider outage surfaces in the future, we want it to fail-safe — log clearly, skip the affected dataset/IOC, never crash the whole run, never block subsequent layers.

---

## Goal: fail-safe bronze → silver → gold

A "fail-safe" pipeline has three properties:

1. **No single defect cancels more than its own scope.** A bug in nftables normalization affects nftables silver, nothing else. A provider outage affects only that provider's enrichment columns. A row with malformed data drops just that row.
2. **Failures are loud and structured.** Every skip/drop emits a log event with `dataset`, `reason`, and `repr(exc)` where applicable, accumulated into `enrichment_errors.json` for daily review. Silence is not success.
3. **Schema variation is tolerated by construction.** Code never assumes optional enrichment columns exist; nested structs are flattened at dispatcher boundaries; missing-but-typed null columns substitute for absent ones.

A lot of this is already in place — see the eight commits above. What remains:

---

## Known remaining issues

### Issue A: nftables bronze isn't parsed

**Severity:** silver for nftables is empty every day. Gold's network-activity volume is undercounted by however much firewall data would have contributed.

**What we see:** bronze events for `dataset=nftables` ship as the raw kernel log line in `.message`, with only Vector metadata columns alongside it (`dataset`, `host`, `operation`, `server`, `source_type`, `timestamp`, `file`). No `action`, `chain`, `src_ip`, `dst_ip`, `protocol`, `length`, `interface_in/out`. The `normalize_nftables` function expects all of those.

**Why:** the Suricata, Cowrie, and Dionaea Vector pipelines all start with `parsed, err = parse_json(.message); if err == null { . = parsed }`. The firewall (nftables) pipeline does NOT — nftables logs aren't JSON, they're the iptables-style kernel format:

```
[chain_name] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=10.50.99.100 LEN=60 PROTO=TCP SPT=54321 DPT=23
```

`config/ansible/roles/firewall/templates/firewall.vector.yaml.j2` ships unparsed.

**Fix sketch:**

1. Add a VRL parse step in the firewall pipeline's `tag_nftables` transform. Vector has `parse_klog` (RFC 3164 kernel log) and `parse_regex`. The nftables format isn't strict RFC 3164; a regex like `r'IN=(?P<interface_in>\S*) OUT=(?P<interface_out>\S*) .*?SRC=(?P<src_ip>\S+) DST=(?P<dst_ip>\S+) LEN=(?P<length>\d+) .*?PROTO=(?P<protocol>\S+) SPT=(?P<src_port>\d+) DPT=(?P<dst_port>\d+)'` extracts the eight fields normalize expects. The chain name is in `[bracketed]` form before `IN=` — separate regex.
2. The "action" field (`accept`/`drop`/`reject`) isn't in the raw message — it comes from the nftables rule's `log prefix` directive. The honeywall nftables rules need to encode it: `log prefix "drop "` etc. Check `config/ansible/roles/firewall/templates/network-single.nft.j2`; the log prefixes likely already encode the action and just need to be extracted from the `[prefix]` portion.
3. Emit a `nftables_parse_failed` event in the VRL when the regex doesn't match, with the raw `message` preserved. Don't silently drop.
4. The defensive `normalize_nftables` we already added stays as the safety net.

**Verification:** after Vector reload, `tail /var/log/lantana/collector/nftables.ndjson | jq '.action, .src_ip, .protocol'` should show structured fields. Then `lantana-enrich --date <yesterday>` should produce silver for `dataset=nftables`.

---

### Issue B: bronze geo enrichment partial (City MMDB)

**Severity:** every bronze event has `geo.asn` and `geo.isp` populated but `geo.country_code`, `geo.city`, `geo.latitude`, `geo.longitude`, `geo.region_code`, `geo.timezone` all null. Gold's geographic_summary and the dashboard's world map are blank.

**State:** repo configuration is correct (verified during the earlier session — see the appendix of `~/.config/claude/plans/i-switched-to-plan-linked-eagle.md` for full diagnostic detail). The failure is *runtime*: most likely the GeoLite2-City `.mmdb` file is missing or truncated on disk, OR Vector started before the MMDB existed and never reloaded. The ASN MMDB is loaded and works fine.

**Diagnostic commands to run on the VPS first** (do not fix until diagnosis confirms):

```bash
ls -lh /var/lib/lantana/collector/geoip/
# Expect both files; City ≈ 70 MB, ASN ≈ 9 MB. If City is 0 / missing / much smaller, the file is broken.

sudo -u vector python3 -c "
import maxminddb
db = maxminddb.open_database('/var/lib/lantana/collector/geoip/GeoLite2-City.mmdb')
print(db.get('8.8.8.8'))
"
# Expect a populated dict. None or {} → file is broken.

journalctl -u vector --since '1 hour ago' | grep -iE 'enrichment|geoip|mmdb'
# Look for load errors.
```

**Likely fixes** (one or more, depending on what diagnosis turns up):

1. **Harden `lantana-geoip-update.sh.j2`** — add `set -euo pipefail` at the top so a partial download fails loudly. Already noted as a TODO in the appendix.
2. **`notify: Restart Vector`** on the MMDB-refresh task in `roles/profile_collector/tasks/main.yml`. Currently absent — Vector keeps stale enrichment tables even after the script succeeds.
3. **`validate:` on the receive.yaml template task** — also already noted in the appendix.
4. **VRL `?? ""` cosmetic mismatch** in `receive.vector.yaml.j2:25-31` — the `??` operator catches errors, not nulls, so `get(city_data, [...])` returning null doesn't trigger the fallback. Lower priority; the primary issue is the lookup itself returning empty.

Full diagnostic and fix detail lives at `~/.config/claude/plans/i-switched-to-plan-linked-eagle.md` (the workstation plan file from the earlier session). The next session should read that first.

---

### Issue C: no integration test against production-shape bronze

**Severity:** every one of today's eight defects could have been caught in CI if the test suite ran end-to-end against bronze that mirrored Vector's real output. Instead, fixtures pre-flatten structs, never miss optional fields, and assume every provider succeeds. Three of the eight defects (suricata alert struct, geo struct, partial provider columns) are direct consequences of this gap.

**Fix sketch:**

1. **Add a `tests/fixtures/production_shape/` directory** with bronze samples that mirror Vector's actual output: nested `geo` struct, nested Suricata `alert` struct, no `shasum` on non-file_download events, optional enrichment columns missing for some rows, raw `message` only for nftables (until Issue A is fixed).
2. **Add a new integration test** at `tests/test_integration_production_shape.py` that pipes those fixtures through `run_enrichment` (with all providers mocked to either succeed, return empty, or rate-limit) and asserts:
   - All four datasets either produce silver or log a clean skip.
   - No `pl.exceptions.ColumnNotFoundError` or `pl.exceptions.SchemaError` is raised.
   - Each dataset's silver has the expected canonical column set (flat `geo.*`, flat enrichment columns where the provider succeeded, nulls where it didn't).
3. **Run `lantana-transform` against the resulting silver** in the same test, assert all seven gold tables produce a result (or `gold_skip_empty` for the conditional ones), and no metric function crashes.

This is the load-bearing test for "is the pipeline rock solid." Once it passes, the eight-bug iteration cycle from today shouldn't be possible.

**Existing test patterns to reuse:**

- `tests/test_enrichment/test_runner.py` — mocking providers via `AsyncMock` + `patch.object(provider._client, "get", ...)`.
- `tests/conftest.py:18-145` — bronze fixtures (which today's defect work showed need expanding for production shape).
- `tests/test_common/test_datalake.py::test_read_silver_partition_handles_heterogeneous_schemas` — pattern for cross-dataset silver assertions.

---

### Issue D (nice to have): tag the run output

**Severity:** low. Operational nice-to-have.

When `lantana-enrich` finishes, it would be valuable to emit a final summary line: `run_summary date=2026-05-19 cowrie_rows=7470 suricata_rows=11276 nftables_rows=0 dionaea_rows=0 ip_enrichments={...} hash_enrichments={...}`. Today operators have to grep multiple log events to assemble that picture.

Trivially small implementation — just a `logger.info("run_summary", ...)` at the end of `run_enrichment` aggregating the per-dataset and per-provider counters.

---

## Phasing

Three commits, in this order:

### Phase 1 — Integration test against production-shape bronze (Issue C)

Highest leverage. Write the test first. With the current code, run it and see which datasets surface what defects (geo will be fine since we just fixed it; nftables will surface as `silver_skipped_empty_after_normalize`; everything else should pass).

The test is also the regression harness for phases 2 and 3 — they're verified by re-running it.

### Phase 2 — Nftables Vector parsing (Issue A)

Update `roles/firewall/templates/firewall.vector.yaml.j2` to parse the kernel-log format into structured fields, emit `nftables_parse_failed` for non-matching lines. After deploy + Vector restart, bronze should have `action`, `src_ip`, `dst_ip`, etc. Re-run the integration test from phase 1; nftables should now produce silver.

This also requires the operator to deploy + verify on the VPS, then a `lantana-enrich --date <yesterday>` to produce real nftables silver.

### Phase 3 — Geo MMDB on the VPS (Issue B)

Diagnose first via the commands above. Apply one or more of the four fixes. Verify next-day bronze has full `geo.*` populated. This is mostly Ansible/Vector work on the VPS, not Python code.

### Phase 4 (optional) — Run summary log line (Issue D)

5-line change. Could be folded into phase 1 if convenient.

---

## What's intentionally out of scope

- Per-provider per-day query cap (predictive circuit breaker before 429s start). Today's reactive circuit breaker (5 consecutive 429s → bail) is sufficient given the daily rate windows.
- Concurrent per-IP enrichment. The 250-test suite and sequential model are working; concurrency is an optimization, not a fail-safe concern.
- URL/domain IOC extraction. Cache schema leaves the slot open; Suricata HTTP fields need Vector pipeline work first.
- `cache.py` extraction. The cache code in `runner.py` is fine in place.
- Hash extraction performance (re-hashing every file every run). Cache absorbs after first hit.
- Per-IOC-type cache TTL. Punt to a follow-up.

---

## Critical files for the next session

```
config/ansible/roles/firewall/templates/firewall.vector.yaml.j2     # Issue A
config/ansible/roles/profile_collector/templates/                   # Issue B
  lantana-geoip-update.sh.j2
  receive.vector.yaml.j2
config/ansible/roles/profile_collector/tasks/main.yml               # Issue B
pipeline/src/lantana/models/normalize.py                            # Issue C: normalize_nftables expectations
pipeline/src/lantana/enrichment/runner.py                           # Issue C/D: run_enrichment summary
pipeline/tests/conftest.py                                          # Issue C: expand bronze fixtures
pipeline/tests/test_integration_production_shape.py                 # Issue C: NEW
docs/pipeline.md                                                    # update after issues land
```

---

## Today's commits — fully shipped and in production

```
b7e5bc9 fix(transform): treat all provider columns as optional in ip_reputation
ecc679b fix(normalize): flatten Vector's nested geo struct into geo.<field> columns
5583a57 fix(datalake): diagonal-concat silver across datasets
2385185 fix(opsec): vector L1 filter drops honeypot-WAN-source events
0965742 refactor(enrichment): drop PhishStats provider
fc768cb fix(pipeline): isolate per-dataset failures + skip unparsed nftables bronze
57a426a fix(opsec): drop outbound-response rows where honeypot is the source
de8c83c feat(deploy): grant nectar read access to cowrie downloads via daily cron
9e54fb2 fix(normalize): flatten nested Suricata alert struct before column refs
5d7ae86 feat(enrichment): per-provider circuit breaker on consecutive failures
402d757 docs: codify pipeline verification discipline
03cd39b fix(enrichment): drop non-routable IPs before provider calls
f116454 fix(enrichment): tolerate sparse provider 200 responses
a2abc73 refactor(enrichment): IOC-first runner with global dedup and hash merge
9409006 fix(enrichment): preserve original exceptions through retry, classify errors
142c0f6 fix(enrichment): return cached data on hit, OPSEC IP filter, --date flag
```

Total: 252 tests passing, ruff at baseline (11 pre-existing errors, all in test files unrelated to this work), mypy clean on changed code.

---

## Hand-off notes

- **The pipeline ran end-to-end successfully against op_alpha's first day** (2026-05-19) before this strategic break. Cowrie + suricata silver both written, gold tables produced (after the final transform fixes). The user just needs to push `b7e5bc9` and run the final `lantana-transform` to close that loop.
- **Tomorrow's 01:00 UTC cron** will run automatically against day-2 bronze. The cache from today absorbs most queries; daily provider budgets refresh at UTC midnight (AbuseIPDB) / VT's rolling reset. Expect a fast run unless day-2 brings a substantial new IP pool.
- **PhishStats vault entries** in `vault.yml` are still present but harmless — `_DROPPED_KEYS` in `config.py` strips them at load. Remove at leisure.
- **The Vector L1 filter** for Suricata WAN-source events is deployed; today's re-run showed `infrastructure_source_rows_dropped count=1597`. After Vector reload picks up the new filter, that count should drop sharply for tomorrow.

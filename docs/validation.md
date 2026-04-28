# Lantana: Deployment Validation Guide

A day-by-day checklist for validating a fresh Lantana deployment. Covers infrastructure, honeypots, telemetry pipeline, enrichment, reports, and dashboard. Every file, directory, and service is listed explicitly.

---

## Day 0: Deploy and Verify Infrastructure

### 0.1 Provision the host

Either use Terraform (VMware Fusion / vSphere):
```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars  # fill in your values
terraform apply
```

Or provision a Debian 13 host manually and ensure SSH access.

### 0.2 Create your operation

```bash
cd config/ansible
cp -r inventories/op_single inventories/op_myop
```

Edit these files under `inventories/op_myop/group_vars/all/`:

| File | What to customize |
|---|---|
| `inventory.yml` | `ansible_host` (your host IP), `sensor_honeypots` list (cowrie, dionaea) |
| `main.yml` | SSH connection settings (port, user, key path) |
| `network.yml` | WAN interface, IP addresses, prefixes |
| `narrative.yml` | Deception story: hostname, OS, SSH banner, service versions |
| `reporting.yml` | Operator identity, TLP, pseudonym map |

Create the vault:
```bash
ansible-vault create inventories/op_myop/group_vars/all/vault.yml
```

### 0.3 Deploy

```bash
ansible-playbook -i inventories/op_myop/inventory.yml playbooks/deploy_single.yml --ask-vault-pass
ansible-playbook -i inventories/op_myop/inventory.yml playbooks/deploy_honeypots.yml --ask-vault-pass
```

### 0.4 Validate infrastructure

Run the validation playbook:
```bash
ansible-playbook -i inventories/op_myop/inventory.yml tests/validate-single-node.yml -vvv
```

Then SSH to the host and check manually:

**System users:**
```bash
id stigma    # UID 2001, sensor user
id nectar    # UID 2002, collector user
```

**Directories exist:**
```bash
ls -la /etc/lantana/sensor/cowrie/          # Cowrie config
ls -la /etc/lantana/sensor/dionaea/         # Dionaea config (if deployed)
ls -la /etc/lantana/collector/              # secrets.json, reporting.json
ls -la /var/log/lantana/sensor/cowrie/      # Cowrie log dir
ls -la /var/log/lantana/sensor/dionaea/     # Dionaea log dir
ls -la /var/log/lantana/honeywall/suricata/ # Suricata log dir
ls -la /var/lib/lantana/datalake/           # bronze/, silver/, gold/
ls -la /var/lib/lantana/sensor/cowrie/      # keys/, tty/, downloads/
ls -la /var/lib/lantana/sensor/dionaea/     # binaries/, wwwroot/
ls -la /var/lib/lantana/collector/geoip/    # GeoLite2-City.mmdb, GeoLite2-ASN.mmdb
```

**Config files deployed:**
```bash
cat /etc/lantana/sensor/cowrie/cowrie.cfg | head -5     # Should show narrative hostname
cat /etc/lantana/sensor/dionaea/dionaea.yaml | head -5  # Should show service config
cat /etc/lantana/collector/reporting.json | python3 -m json.tool | head -10
# secrets.json: DO NOT cat -- contains API keys. Just verify it exists:
test -f /etc/lantana/collector/secrets.json && echo "OK"
```

**Containers running:**
```bash
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 systemctl --user status cowrie
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 systemctl --user status dionaea  # if deployed
# Both should show "active (running)"
```

**Firewall rules loaded:**
```bash
sudo nft list ruleset | grep -A2 "lantana_nat"
# Should show DNAT rules:
#   port 22 -> sensor:2222 (Cowrie SSH)
#   port 23 -> sensor:2223 (Cowrie Telnet)
#   port 445 -> sensor:8445 (Dionaea SMB) -- if deployed
#   etc.
ls /etc/lantana/honeywall/nftables/sensors/
# cowrie.nft, dionaea.nft
```

**Suricata running:**
```bash
sudo systemctl status suricata
ls /var/lib/lantana/honeywall/suricata/rules/
# suricata.rules (ET), lantana.rules (custom SID 9000001-9000999)
```

**Vector running:**
```bash
sudo systemctl status vector
ls /etc/vector/conf.d/
# cowrie.yaml, dionaea.yaml, suricata.yaml, forward.yaml, receive.yaml
```

**Pipeline installed:**
```bash
ls /opt/lantana/pipeline/venv/bin/lantana-*
# lantana-enrich, lantana-transform, lantana-prune, lantana-notify, lantana-report, lantana-dashboard
cat /etc/cron.d/lantana-pipeline
# 00:15 lantana-prune
# 01:00 lantana-enrich
# 02:00 lantana-transform
```

---

## Day 0 + 1 hour: Verify Logs Are Being Generated

After deployment, real attackers will start hitting exposed ports. Within minutes to hours you should see data.

**Cowrie logs:**
```bash
tail -5 /var/log/lantana/sensor/cowrie/cowrie.json
# Should show JSON lines with eventid, src_ip, dst_ip, timestamp
# Event types: cowrie.login.failed, cowrie.login.success, cowrie.command.input, cowrie.session.file_download
```

**Dionaea logs (if deployed):**
```bash
tail -5 /var/log/lantana/sensor/dionaea/dionaea.json
# Should show JSON with connection.protocol, connection.type, src_ip, dst_ip
```

**Suricata alerts:**
```bash
tail -5 /var/log/lantana/honeywall/suricata/eve.json
# Should show JSON with event_type (alert, flow, stats), src_ip, dest_ip
# Look for event_type=alert to confirm IDS is detecting
```

**Bronze datalake (Vector writes):**
```bash
ls /var/lib/lantana/datalake/bronze/
# dataset=cowrie/, dataset=suricata/, dataset=nftables/
ls /var/lib/lantana/datalake/bronze/dataset=cowrie/
# date=YYYY-MM-DD/ directories should appear
wc -l /var/lib/lantana/datalake/bronze/dataset=cowrie/date=$(date +%Y-%m-%d)/server=*/events.json
# Should show event count > 0
```

If bronze is empty but raw logs exist, check Vector:
```bash
sudo journalctl -u vector --since "1 hour ago" | tail -20
```

---

## Day 1: First Pipeline Run

The pipeline runs via cron at 01:00 UTC (enrichment) and 02:00 UTC (gold aggregation). After the first night:

### 1.1 Verify enrichment ran (bronze -> silver)

```bash
# Check cron ran
grep lantana-enrich /var/log/syslog | tail -5

# Silver layer should exist
ls /var/lib/lantana/datalake/silver/
# dataset=cowrie/, dataset=suricata/, dataset=nftables/
ls /var/lib/lantana/datalake/silver/dataset=cowrie/date=$(date -d yesterday +%Y-%m-%d)/server=*/
# events.parquet should exist
```

**Verify OCSF normalization:**
```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
from datetime import date, timedelta
from lantana.common.datalake import read_silver_partition
yesterday = date.today() - timedelta(days=1)
df = read_silver_partition(yesterday).collect()
print(f'Rows: {df.shape[0]}, Columns: {df.shape[1]}')
print('Columns:', sorted(df.columns))
# Must have: class_uid, src_endpoint_ip, dst_endpoint_ip, time, metadata_version
# Must NOT have: src_ip, eventid, timestamp (raw columns consumed)
"
```

**Verify OPSEC redaction:**
```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
from datetime import date, timedelta
from lantana.common.datalake import read_silver_partition
yesterday = date.today() - timedelta(days=1)
df = read_silver_partition(yesterday).collect()
# Check that no infrastructure IPs leaked into silver
for col in df.columns:
    if df.schema[col] == pl.Utf8:
        vals = df.get_column(col).drop_nulls().to_list()
        # Replace with your actual WAN IP:
        assert not any('YOUR_WAN_IP' in str(v) for v in vals), f'LEAK in {col}!'
print('OPSEC OK: no infrastructure IPs in silver')
" 2>&1
```

**Verify enrichment cache:**
```bash
ls -la /var/lib/lantana/datalake/.enrichment_cache.db
# SQLite file should exist and be non-empty
sqlite3 /var/lib/lantana/datalake/.enrichment_cache.db "SELECT COUNT(*) FROM cache;"
# Should show cached entries (depends on API key availability)
```

### 1.2 Verify gold aggregation ran (silver -> gold)

```bash
# Check cron ran
grep lantana-transform /var/log/syslog | tail -5

# Gold tables should exist
ls /var/lib/lantana/datalake/gold/
# daily_summary/, ip_reputation/, behavioral_progression/, campaign_clusters/,
# behavioral_progression_multiday/
```

**Inspect gold tables:**
```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
from datetime import date, timedelta
from lantana.common.datalake import read_gold_table
yesterday = date.today() - timedelta(days=1)
for table in ['daily_summary', 'ip_reputation', 'behavioral_progression', 'campaign_clusters', 'behavioral_progression_multiday']:
    df = read_gold_table(table, yesterday)
    print(f'{table}: {df.shape}')
"
```

**Verify daily_summary has plausible numbers:**
```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
from datetime import date, timedelta
from lantana.common.datalake import read_gold_table
yesterday = date.today() - timedelta(days=1)
df = read_gold_table('daily_summary', yesterday)
if not df.is_empty():
    row = df.row(0, named=True)
    print(f'Total events:    {row[\"total_events\"]:,}')
    print(f'Unique IPs:      {row[\"unique_source_ips\"]:,}')
    print(f'Auth attempts:   {row[\"auth_attempts\"]:,}')
    print(f'Auth successes:  {row[\"auth_successes\"]:,}')
    print(f'Commands:        {row[\"commands_executed\"]:,}')
    print(f'Findings:        {row[\"findings_detected\"]:,}')
    print(f'Downloads:       {row[\"downloads_captured\"]:,}')
    print(f'Top usernames:   {row[\"top_usernames\"]}')
    print(f'Top passwords:   {row[\"top_passwords\"]}')
    print(f'Top downloads:   {row[\"top_download_urls\"]}')
"
```

### 1.3 Verify retention/prune ran

```bash
grep lantana-prune /var/log/syslog | tail -5
# Should show "prune complete" or similar
```

---

## Day 3: Enrichment Validation

By day 3, the enrichment cache should have meaningful entries from the API providers.

**Check provider results:**
```bash
sqlite3 /var/lib/lantana/datalake/.enrichment_cache.db "
SELECT provider, COUNT(*) as entries FROM cache GROUP BY provider;
"
# Expected: abuseipdb, greynoise, shodan, virustotal, phishstats
# Counts depend on API key availability and rate limits
```

**Check enrichment columns in silver:**
```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
from datetime import date, timedelta
from lantana.common.datalake import read_silver_partition
d = date.today() - timedelta(days=1)
df = read_silver_partition(d).collect()
enrichment_cols = [c for c in df.columns if any(c.startswith(p) for p in ['abuseipdb_', 'greynoise_', 'shodan_', 'virustotal_', 'phishstats_', 'geo.'])]
print('Enrichment columns present:', enrichment_cols)
for col in enrichment_cols:
    non_null = df.get_column(col).drop_nulls().len()
    print(f'  {col}: {non_null} non-null values')
"
```

If enrichment columns are all null, check:
- API keys in `/etc/lantana/collector/secrets.json` (non-empty for each provider)
- GeoIP MMDB files in `/var/lib/lantana/collector/geoip/`
- Enrichment runner logs: `grep lantana-enrich /var/log/syslog`

---

## Day 7: Reports, STIX, and Dashboard

After a full week, there's enough data for meaningful intelligence output.

### 7.1 Discord reports

If `discord_webhook` is configured in `secrets.json`:

```bash
# Manual trigger:
/opt/lantana/pipeline/venv/bin/lantana-report
```

Check your Discord channel for:
- **Embed**: short summary with event count, unique IPs, stage breakdown
- **Attached .md file**: full daily brief with:
  - Key Metrics table
  - Mermaid escalation funnel
  - Top Attackers table
  - Notable Escalations (stage 3+)
  - Campaign Clusters
  - Malware Captured (download count, top URLs, top hashes)
  - Top Credentials and Commands

### 7.2 STIX bundles

Generate a bundle manually:
```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
import json
from datetime import date, timedelta
from lantana.common.config import load_reporting
from lantana.common.datalake import read_gold_table
from lantana.intel.stix import generate_bundle
yesterday = date.today() - timedelta(days=1)
reporting = load_reporting()
reputation = read_gold_table('ip_reputation', yesterday)
progression = read_gold_table('behavioral_progression', yesterday)
clusters = read_gold_table('campaign_clusters', yesterday)
summary = read_gold_table('daily_summary', yesterday)
multiday = read_gold_table('behavioral_progression_multiday', yesterday)
bundle = generate_bundle(yesterday, reporting, reputation, progression, clusters, summary=summary, multiday_progression=multiday)
print(json.dumps(json.loads(bundle.serialize()), indent=2)[:2000])
print(f'...')
print(f'Total STIX objects: {len(bundle.objects)}')
"
```

**Verify the bundle contains:**
- `identity` object (your operator)
- `indicator` objects for high-risk IPs (risk >= 40) with `[ipv4-addr:value = '...']` patterns
- `indicator` objects for file hashes with `[file:hashes.'SHA-256' = '...']` patterns (if downloads captured)
- `malware` objects for captured samples
- `campaign` objects for shared credential clusters
- `relationship` objects linking indicators to campaigns
- `report` wrapping all objects with TLP marking
- Slow-burn IPs with `slow-burn-escalation` label (if multi-day data available)
- No infrastructure IPs in any object

### 7.3 Streamlit dashboard

Launch the dashboard:
```bash
/opt/lantana/pipeline/venv/bin/lantana-dashboard
# Or from local dev:
cd pipeline && uv run python ../scripts/run-dashboard-local.py
```

Open http://localhost:8501 and verify each page:

**Overview page:**
- Metric cards (events, IPs, auth, commands, findings)
- Event type distribution
- Top-N tables (IPs, usernames, passwords, commands)

**IP Reputation page:**
- Risk score distribution
- Filterable IP table with enrichment details
- Risk slider filter

**Behavioral Progression page:**
- Escalation funnel (scan -> credential -> authenticated -> interactive)
- Stage scatter plot (stage vs time, colored by automated/manual)
- Automated vs manual breakdown
- **Multi-day progression section**: slow-burn IPs count, velocity distribution, slow-burn details table

**Credentials page:**
- Campaign cluster table (shared username:password pairs, IP count)
- Top username/password pairs

**STIX Export page:**
- Bundle preview
- Generate button
- JSON download

### 7.4 Multi-day progression

After 7 days, the `behavioral_progression_multiday` gold table should show slow-burn patterns:

```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
from datetime import date, timedelta
from lantana.common.datalake import read_gold_table
yesterday = date.today() - timedelta(days=1)
df = read_gold_table('behavioral_progression_multiday', yesterday)
if not df.is_empty():
    import polars as pl
    slow = df.filter(pl.col('is_slow_burn'))
    print(f'Total IPs (7-day): {len(df)}')
    print(f'Slow-burn IPs: {len(slow)}')
    if not slow.is_empty():
        print(slow.select('src_endpoint_ip', 'max_stage', 'stage_label', 'first_seen_date', 'last_seen_date', 'progression_velocity_days').head(10))
"
```

---

## Ongoing: What to Watch

| Interval | Check | Command |
|---|---|---|
| Daily | Bronze growing | `ls /var/lib/lantana/datalake/bronze/dataset=cowrie/` |
| Daily | Silver/gold populated | `ls /var/lib/lantana/datalake/gold/daily_summary/` |
| Daily | Cron ran | `grep lantana /var/log/syslog \| tail -20` |
| Weekly | Disk usage | `df -h /var/lib/lantana/` |
| Weekly | Enrichment cache size | `sqlite3 .enrichment_cache.db "SELECT COUNT(*) FROM cache;"` |
| Monthly | GeoIP MMDB updated | `ls -la /var/lib/lantana/collector/geoip/` |
| Monthly | Suricata rules updated | `suricata-update --data-dir /var/lib/lantana/honeywall/suricata` |

---

## Future: Report Improvements

After initial validation, the Markdown daily brief and Streamlit dashboard will likely need tuning based on real operational use. Expected areas for iteration:

- **Markdown report**: section ordering, metric selection, Mermaid chart readability, STIX bundle summary inclusion
- **Streamlit dashboard**: chart types, filter UX, new pages (malware analysis, geographic view), STIX data integration into the dashboard
- **STIX bundles**: indicator confidence tuning, relationship depth, TLP per-object granularity

These improvements are best driven by reviewing actual reports from 1-2 weeks of production data.

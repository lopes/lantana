# Lantana: Deployment Validation Guide

A post-deploy verification walkthrough — from "the playbook said `failed=0`" to "honeypots are actually capturing attacker traffic and the pipeline is producing usable intel." Covers static infrastructure checks, active protocol smoke tests, telemetry, enrichment, reports, and dashboard. Every file, directory, and service is listed explicitly.

> This guide assumes the operation has already been deployed via [`setup.md`](/docs/setup.md) (`deploy_single.yml` + `deploy_honeypots.yml`). For the first-deploy walkthrough — provisioning the server, configuring the inventory, vault, narrative — start there.

## Executable validation (the fast path)

Most of the checks below are encoded in four Ansible playbooks. Run those first; drop into the manual day-by-day walkthrough only when you need to debug a failure or want to learn the architecture.

| When | Playbook | What it checks |
|---|---|---|
| Immediately after `deploy_single.yml` | `tests/validate-single-node.yml` | Users, SSH port, `ltn0` interface, nftables meters + ruleset, NIC offloads (`ethtool`), non-root Suricata, log directories + rotation, systemd timers for the four pipeline jobs (enabled and present), GeoIP cron entry |
| Immediately after `deploy_honeypots.yml` (or `deploy_single.yml`), with a ~30 s settle | `tests/validate-sensor-runtime.yml` | Cowrie + Dionaea Quadlet ownership invariants (`UserNS=keep-id` for Cowrie, no `,U` for either), app-layer health (`healthy`), zero log-plugin failure tracebacks since each container's `StartedAt`, worker write FDs on `cowrie.json` / `dionaea.json`, fresh bronze NDJSON, zero orphan-UID files under sensor state trees |
| Immediately after `validate-sensor-runtime.yml` | `tests/validate-canaries.yml` | Active synthetic probes proving Vector 1-in-1-out delivery, Layer-1 OPSEC edge filtering (`::1`, RFC 1918, host WAN dropped), and Suricata `sid:9000004` detection with zero TCPv4 invalid-checksum alerts |
| After the first 06:00 UTC cycle (day 2+) | `tests/validate-pipeline-cycle.yml` | Each pipeline unit's last `Result=success`, `run_summary` events in journal, silver written for `cowrie`/`dionaea`/`suricata`/`nftables`, all 7 gold tables present (including `extracted_iocs`), `.provider_state.json` exists, no API-key leak in `enrichment_errors.json`, per-provider `<provider>_risk_score` columns in silver, monotonic composite + scanner cap (`<= 35`) + GreyNoise RIOT invariant |

Run them via:

```bash
cd config/ansible
ansible-playbook -i inventories/op_<name>/inventory.yml tests/validate-single-node.yml --ask-vault-pass
sleep 30  # let sensors bind and Vector discover their JSON logs
ansible-playbook -i inventories/op_<name>/inventory.yml tests/validate-sensor-runtime.yml --ask-vault-pass
ansible-playbook -i inventories/op_<name>/inventory.yml tests/validate-canaries.yml --ask-vault-pass
# Tune the bronze freshness window when running long after a deploy:
#   -e sensor_freshness_window_seconds=900
ansible-playbook -i inventories/op_<name>/inventory.yml tests/validate-pipeline-cycle.yml --ask-vault-pass
# Override target_date if not yesterday-UTC:
#   -e target_date=2026-05-23
```

If all four pass, the deployment is healthy. The remaining manual checks are full per-protocol banner probes (§0.2 below) and visual verification of Discord report rendering, Vigil dashboard views, and STIX bundle downloads (§7.2 / §7.3).

---

## Day 0: Verify Infrastructure

### 0.1 Static infrastructure checks

Run the two automated playbooks:

```bash
ansible-playbook -i inventories/op_<name>/inventory.yml \
  tests/validate-single-node.yml -vvv --ask-vault-pass

sleep 30  # let sensors settle

ansible-playbook -i inventories/op_<name>/inventory.yml \
  tests/validate-sensor-runtime.yml -vvv --ask-vault-pass
```

The first covers the **static** surface — users, SSH port, ltn0 interface, nftables ruleset, log directories + rotation, the four pipeline timers, and the GeoIP cron entry. The second covers the **runtime** surface — Quadlet ownership invariants, container Health, no log-plugin failure tracebacks since the last `StartedAt`, the worker holds the JSON-log FD, today's bronze NDJSON is fresh, and zero orphan-UID files under sensor state trees. Together they are the executable counterpart to the manual recipe an operator would otherwise run by hand after a sensor restart. If anything below the playbooks' scope is in doubt, SSH to the host and check manually:

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
cat /etc/lantana/sensor/cowrie/cowrie.cfg | head -5
# Should show narrative hostname in [honeypot] section

ls /etc/lantana/sensor/dionaea/services-enabled/
# One *.yaml per entry in dionaea_service_catalog (currently 6: ftp,
# http, epmap, smb, mssql, mysql — see roles/dionaea/defaults/main.yml).

cat /etc/lantana/collector/reporting.json | python3 -m json.tool | head -10
# secrets.json: DO NOT cat — contains API keys. Just verify it exists:
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
#   port 445 -> sensor:8445 (Dionaea SMB) — if deployed
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
# Single-node: cowrie.yaml, dionaea.yaml, suricata.yaml, firewall.yaml, receive.yaml
# (Multi-node additionally adds forward-honeywall.yaml / forward-sensor.yaml.)
```

**Pipeline installed and scheduled:**

```bash
ls /opt/lantana/pipeline/venv/bin/lantana-*
# lantana-enrich, lantana-transform, lantana-prune, lantana-alert, lantana-notify, lantana-report, lantana-dashboard
# (5 .service units and 4 .timer units: lantana-alert.service stays installed for
# off-cycle replay, while its timer was retired when lantana-report absorbed the daily flow.)
sudo systemctl list-timers --all | grep lantana
# lantana-prune.timer      next fire 00:15 UTC
# lantana-enrich.timer     next fire 01:00 UTC
# lantana-transform.timer  next fire 05:30 UTC
# lantana-report.timer     next fire 06:00 UTC
```

---

### 0.2 Active protocol smoke tests

Section 0.1 confirms the platform is *installed and writing*. What it
can't do from inside the operation is **drive an attacker-side
connection through the full DNAT → sensor → JSON log → bronze chain**
— that requires a runner outside the operation's prefix, otherwise
the Vector `filter_<honeypot>` transform drops the traffic. The probes
below close that loop manually. For each protocol:

1. The port answers and the banner matches the narrative persona.
2. Cowrie or Dionaea writes a structured event to its JSON log.
3. Vector picks the event up and writes it to bronze NDJSON.

Replace `<host>` with `network.honeywall.wan.ipv4` from your
inventory. Run probes from a workstation outside the operation's
internal prefixes (see [AGENTS.md §3 — OPSEC](/AGENTS.md#1-opsec-is-non-negotiable-layers-03)). Note your
workstation's egress IP first — you'll match against it in the logs:

```bash
curl -s ifconfig.me
```

#### One-shot banner sweep

```bash
nmap -sV -Pn -p 21,22,23,80,135,445,1433,3306 <host>
```

Cross-check each banner against `narrative.services.<svc>` in your
operation's `narrative.yml`. Mismatches mean a stale render, a template
not consuming the narrative, or — for MSSQL — the upstream module
hard-coding the version (documented in [docs/honeypots.md](/docs/honeypots.md#known-limitations)).

#### SSH 22 — Cowrie

**Workstation:**

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PubkeyAuthentication=no -o IdentityAgent=none \
    root@<host>
# Any password works. Land in Cowrie's fake shell.
# Run: whoami; uname -a; ls; exit
```

The shell's prompt hostname must match `narrative.host.hostname`.
Without `PubkeyAuthentication=no -o IdentityAgent=none`, your SSH
agent may silently hand a key to Cowrie which accepts it — no
password prompt and you'll mis-diagnose the auth path.

**Sensor verification:**

```bash
sudo tail -5 /var/log/lantana/sensor/cowrie/cowrie.json | jq -c .
# Expect: cowrie.session.connect → cowrie.login.failed/success →
#         cowrie.command.input(*) → cowrie.session.closed
# src_ip matches your egress IP from `curl ifconfig.me` above.

sudo tail -1 /var/lib/lantana/datalake/bronze/dataset=cowrie/date=$(date -u +%Y-%m-%d)/server=*/events.json | jq .
# Vector has written this event to bronze. Empty or stale means
# the cowrie → vector → bronze chain is broken; check `journalctl -u vector`.
```

#### Telnet 23 — Cowrie

**Workstation:**

```bash
nc -v <host> 23
# Login: root <enter>
# Password: <anything> <enter>
# Lands in the same Cowrie fake shell. Type `exit` or Ctrl-]; quit.
```

**Sensor verification:** identical to SSH; the matching cowrie.json
event has `"protocol": "telnet"` instead of `"ssh"`.

#### FTP 21 — Dionaea

**Workstation:**

```bash
nc -v <host> 21
# Expect line: 220 <narrative.services.ftp.banner>
# Optionally drive an anonymous login:
#   USER anonymous <enter>
#   PASS test@example.com <enter>
#   QUIT <enter>
```

Or one-shot with curl:

```bash
curl -v ftp://anonymous:test@<host>/
# Dionaea logs every command regardless of whether anonymous succeeds.
```

**Sensor verification:**

```bash
sudo tail -3 /var/log/lantana/sensor/dionaea/dionaea.json | jq -c .
# Expect: { "connection": { "protocol": "ftpd", "type": "accept",
#                            "remote": { "host": "<your-egress-ip>" } } }

sudo tail -1 /var/lib/lantana/datalake/bronze/dataset=dionaea/date=$(date -u +%Y-%m-%d)/server=*/events.json | jq .
```

#### HTTP 80 — Dionaea

**Workstation:**

```bash
curl -I http://<host>/
# Expect: Server: <narrative.services.http.server_header>

curl -sv http://<host>/ -o /dev/null
# Body is the persona-consistent index.html rendered by
# roles/dionaea/templates/wwwroot/index.html.j2.
```

**Sensor verification:** dionaea.json shows `"protocol": "httpd"`
with the GET line. Note Dionaea logs the connection on accept; the
request body shows up as a separate event.

#### EPMAP 135 — Dionaea

DCERPC endpoint mapper. Most workstations don't ship `rpcclient`; the
banner sweep above already touched port 135, so just confirm Dionaea
saw the connect:

```bash
sudo grep -i 'epmapper\|protocol=epmapper' /var/log/lantana/sensor/dionaea/dionaea.json | tail -3
```

If you want a deeper probe, `impacket-rpcdump <host>` (from the
impacket toolkit) enumerates RPC interfaces — Dionaea responds with
the bundled fake set.

#### SMB 445 — Dionaea

**Workstation:**

```bash
nmap --script=smb-os-discovery -p 445 <host>
# Expect OS string ~ narrative.host.os_release; workgroup ~
# narrative.services.smb.workgroup; server name ~ uppercase(hostname).
```

Or, if you have smbclient:

```bash
smbclient -L //<host> -N
# Anonymous shares listing; Dionaea logs the SMB negotiation.
```

**Sensor verification:** dionaea.json shows `"protocol": "smbd"`.

#### MSSQL 1433 — Dionaea

```bash
nmap -p 1433 --script=ms-sql-info <host>
# Returns the version banner. Known upstream constraint: the MSSQL
# module hardcodes its version string, so this won't reflect
# narrative.services.mssql.version. Connections and SQL queries still log.
```

**Sensor verification:** dionaea.json shows `"protocol": "mssqld"`.

#### MySQL 3306 — Dionaea

**Workstation (no mysql client required):**

```bash
nc -v <host> 3306 < /dev/null | head -c 64 | xxd
# Expect the version handshake packet:
# byte 0-2: packet length, byte 3: sequence
# byte 4:   protocol version (0x0a)
# byte 5+:  null-terminated version string = narrative.services.mysql.version
```

Or with a mysql client:

```bash
mysql -h <host> -u root -p<anything>
# Authentication fails (expected); Dionaea logs the connection.
```

**Sensor verification:** dionaea.json shows `"protocol": "mysqld"`.

#### End-to-end smoke matrix

After all probes, confirm the protocols you exercised aggregated
correctly:

```bash
# Per-protocol event counts in the raw honeypot logs (today UTC):
sudo jq -r '.connection.protocol // .eventid' \
  /var/log/lantana/sensor/cowrie/cowrie.json \
  /var/log/lantana/sensor/dionaea/dionaea.json \
  2>/dev/null | sort | uniq -c | sort -rn
# Expect at least one entry per protocol you tested. Look for
# ssh/telnet (cowrie eventids) and ftpd/httpd/epmapper/smbd/mssqld/mysqld.

# Per-dataset bronze line counts (today UTC):
for d in cowrie dionaea suricata nftables; do
  total=$(sudo find /var/lib/lantana/datalake/bronze/dataset=$d \
            -name 'events.json' -exec wc -l {} + 2>/dev/null \
            | awk 'END{print $1+0}')
  printf '%-10s bronze lines: %d\n' "$d" "$total"
done
```

**Suricata corroboration:** every external probe should also surface
in Suricata's flow log even if no IDS rule matched. Quick spot-check:

```bash
sudo jq -c 'select(.src_ip == "<your-egress-ip>" and .event_type == "flow")' \
  /var/log/lantana/honeywall/suricata/eve.json | tail -10
```

**Triage matrix when something is missing:**

| Symptom | Most likely cause | Where to look |
|---|---|---|
| Workstation probe times out | nftables DNAT missing or sensor container down | `sudo nft list ruleset \| grep -A2 lantana_nat`; `systemctl --user status cowrie\|dionaea` |
| Probe succeeds but no log on sensor | Container bound but didn't write log (config or service-yaml issue) | `podman exec` into the container; check stdout/stderr of the supervised process |
| Log exists locally but not in bronze | Vector pipeline broken | `sudo journalctl -u vector --since '5 min ago'`; look for VRL errors |
| Local + bronze fine but Suricata flow missing | Suricata not seeing traffic on the listening interface | `sudo systemctl status suricata`; `sudo nft list ruleset \| grep lantana_forward` |
| All present but you can't find them | Egress IP mismatch (CGNAT, VPN) | re-run `curl ifconfig.me` from the same workstation |

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
# Should show JSON with event_type (alert, flow), src_ip, dest_ip
# Look for event_type=alert to confirm IDS is detecting
```

**Bronze datalake (Vector writes):**

```bash
ls /var/lib/lantana/datalake/bronze/
# dataset=cowrie/, dataset=dionaea/, dataset=suricata/, dataset=nftables/
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

The pipeline runs via systemd timers: 00:15 UTC prune, 01:00 UTC enrich, 05:30 UTC transform, 06:00 UTC report (plus `00:10 UTC` `lantana-grant-read` POSIX ACL cron jobs for Cowrie `downloads/`/`tty/` and Dionaea `binaries/`/`bistreams/`/`tmp/`). After the first night:

### 1.1 Verify enrichment ran (bronze -> silver)

```bash
# Check the unit ran (and succeeded)
sudo systemctl status lantana-enrich.service --no-pager | head
sudo journalctl -u lantana-enrich.service --since '01:00 UTC' | grep run_summary

# Silver layer should exist
ls /var/lib/lantana/datalake/silver/
# dataset=cowrie/, dataset=dionaea/, dataset=suricata/, dataset=nftables/
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

This is a one-off spot check; the production redaction validator (`common/redact.py::validate_no_leaks`) runs every enrichment cycle and asserts against the full infrastructure IP set plus CIDR containment. Replace `YOUR_WAN_IP` with the public IPv4 your operation actually binds:

```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
import polars as pl
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
# Check the unit ran (and succeeded)
sudo systemctl status lantana-transform.service --no-pager | head
sudo journalctl -u lantana-transform.service --since '05:30 UTC' | grep run_summary

# Gold tables should exist — seven directories, one per table
ls /var/lib/lantana/datalake/gold/
# daily_summary/, ip_reputation/, behavioral_progression/,
# campaign_clusters/, geographic_summary/, detection_findings/, extracted_iocs/
```

**Inspect gold tables:**

```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
from datetime import date, timedelta
from lantana.common.datalake import read_gold_table
yesterday = date.today() - timedelta(days=1)
tables = [
    'daily_summary',
    'ip_reputation',
    'behavioral_progression',
    'campaign_clusters',
    'geographic_summary',
    'detection_findings',
    'extracted_iocs',
]
for table in tables:
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
sudo systemctl status lantana-prune.timer --no-pager | head
sudo journalctl -u lantana-prune.service --since '00:15 UTC' --no-pager | tail -10
# Should show Result=success and the prune run summary in journald
```

---

## Day 3: Enrichment Validation

By day 3, the enrichment cache should have meaningful entries from the API providers.

**Check provider results:**

```bash
sqlite3 /var/lib/lantana/datalake/.enrichment_cache.db "
SELECT provider, COUNT(*) as entries FROM cache GROUP BY provider;
"
# Expected: abuseipdb, greynoise, shodan, virustotal
# Counts depend on API key availability and rate limits
```

**Check enrichment columns in silver:**

```bash
/opt/lantana/pipeline/venv/bin/python3 -c "
from datetime import date, timedelta
from lantana.common.datalake import read_silver_partition
d = date.today() - timedelta(days=1)
df = read_silver_partition(d).collect()
enrichment_cols = [c for c in df.columns if any(c.startswith(p) for p in ['abuseipdb_', 'greynoise_', 'shodan_', 'virustotal_', 'vt_', 'geo.'])]
print('Enrichment columns present:', enrichment_cols)
for col in enrichment_cols:
    non_null = df.get_column(col).drop_nulls().len()
    print(f'  {col}: {non_null} non-null values')
"
```

If enrichment columns are all null, check:

- API keys in `/etc/lantana/collector/secrets.json` (non-empty for each provider)
- GeoIP MMDB files in `/var/lib/lantana/collector/geoip/`
- Enrichment runner logs: `sudo journalctl -u lantana-enrich.service --since today`

---

## Day 7: Reports, STIX, and Dashboard

After a full week, there's enough data for meaningful intelligence output.

### 7.1 Discord reports

If `vault_webhook_discord` is configured in `secrets.json` (with `discord_webhook` accepted as alias):

```bash
# Manual trigger:
/opt/lantana/pipeline/venv/bin/lantana-report
```

Check your Discord channel for:

- **Embed**: short summary with event count, unique IPs, stage breakdown, plus a one-line pipeline-health summary (✅ clean / 🔴 N critical / 🟡 N warning / 🔵 N info) and per-step timing.
- **Attached .md file**: full daily brief with:
  - **Pipeline Health** section (severity-tiered table of yesterday's enrichment errors)
  - **Pipeline Timing** section (systemd duration per step)
  - Key Metrics table
  - Geographic Origin (top countries + ASNs)
  - Mermaid Escalation Funnel + stage-definition legend
  - Top Attackers table with monotonic behavioral-anchored `E`/`B` decomposition and `A/V/S/G` per-provider quadruplet
  - Attacker Persistence (`## Attacker Persistence`)
  - Threat Actor Attribution (GreyNoise-named)
  - Notable Escalations (stage 3+)
  - Campaign Clusters table + rank-numbered IP list
  - Detection Highlights (top Suricata rules)
  - Malware Captured (top hashes with VT family / type / detections, top URLs)
  - Top Credentials and Commands
  - Footer pointer to the dashboard's **STIX Export** page for the curated bundle and the raw IOC CSV — the long-tail IOC inventory lives there, not inline.

### 7.2 STIX bundles

**Primary path — via the dashboard.** STIX bundles aren't stored server-side. They're generated on-demand from gold tables and streamed to the operator's browser. Open the Vigil dashboard (§7.3), navigate to **Intel & Export** (`/intel`), pick the target date or window, and click **Download STIX 2.1 Bundle (.json)** (`/download/stix`) — the file saves to your workstation as `lantana-stix-<YYYY-MM-DD>.json`.

Inspect the downloaded bundle on your workstation:

```bash
jq '.objects[] | {type, id, labels}' lantana-stix-2026-05-23.json | head -40
# OPSEC sanity check — no internal IPs in any indicator pattern
jq '.objects[] | select(.type=="indicator") | .pattern' lantana-stix-2026-05-23.json \
  | grep -E '10\.|192\.168\.|fd99:' || echo "OK: no internal IPs"
```

**CLI path (for automation / debugging).** Generate a bundle from a sensor-side Python shell:

```bash
sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c "
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
extracted_iocs = read_gold_table('extracted_iocs', yesterday)
bundle = generate_bundle(
    yesterday, reporting, reputation, progression, clusters,
    summary=summary, extracted_iocs=extracted_iocs,
)
print(json.dumps(json.loads(bundle.serialize()), indent=2)[:2000])
print('...')
print(f'Total STIX objects: {len(bundle.objects)}')
"
```

**Verify the bundle contains:**

- `identity` object (your operator)
- Durable `indicator` objects from `extracted_iocs`: outbound C2 IPs (30d), post-auth stager URLs & domains (30d), malware SHA-256 hashes (with `vhash` cluster tags & `malware` SDOs), and persistent OpenSSH public-key fingerprints (90d)
- Transient inbound IP `indicator` objects strictly gated on `behavioral_risk_score > 0` AND `risk_score >= 40` (non-RIOT, non-`benign`) with explicit 7-day `valid_until`
- `campaign` objects for shared credential clusters and `relationship` objects linking indicators to campaigns/malware
- `report` wrapping all objects with TLP marking
- Zero bogus HTTP-pattern rules, zero benign-scanner Threat Actors, and zero infrastructure IPs or hostnames

### 7.3 Vigil dashboard

The Vigil dashboard is the operator's personal console — **air-gapped and never exposed externally** (OPSEC Layer 3; strict `connect-src 'none'` CSP, zero external CDNs or fonts). It binds strictly to `127.0.0.1:8501` on the collector. Reach it from your workstation via SSH local-port-forwarding.

**Workstation terminal:** open an SSH tunnel and leave it running.

```bash
# Replace <PORT> + <SN01> with the values from inventories/op_<name>/group_vars/all/main.yml.
# You can map any free local port (e.g. -L 1313:127.0.0.1:8501 -> http://127.0.0.1:1313).
ssh -p <PORT> -L 8501:127.0.0.1:8501 lantana@<SN01>
```

**Collector (inside that SSH session, or a separate one):** launch the Vigil console.

```bash
sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-dashboard
# Or for local dev against synthetic/copied Gold data:
cd pipeline && uv run python ../scripts/run-dashboard-local.py
```

Then on your workstation, open <http://localhost:8501> and verify the window picker (`Day` / `7d` / `30d` / `Custom` / `All`), the dark/light theme toggle, and all 5 views (legacy paths like `/stix` and `/geography` cleanly `302` redirect to the corresponding anchored section):

- **Overview (`/overview`):** Telemetry pulse KPIs (events, IPs, auth, commands, malware, C2s, findings) with `<details>` help drawers from `notify/explanations.py`, multi-day trend, auth outcome donut, events-by-class bar, and top commands / top IDS rules highlights.
- **Attackers (`/attackers`):** Risk buckets (`RISK_HIGH_THRESHOLD = 70`, `RISK_THRESHOLD = 40`) + monotonic formula drawer linking [`docs/risk-scoring.md`](/docs/risk-scoring.md), composite/behavioral/enrichment histograms, offline MaxMind GeoLite2 world map + Top Countries/Cities/ASNs (`#geo-origins`, collapsing to a compact warning callout when GeoLite2 is unset), and searchable Scored IP table.
- **Behavior (`/behavior`):** Escalation funnel (Scan / Credential / Authenticated / Interactive), Stage-vs-Time scatter, multi-day persistence, Top Credentials + Post-Auth Commands + shared-credential `campaign_clusters` (`#cred-lists`), and Suricata Detection Findings (`#find-summary`, decoder SIDs `2200000-2260999` excluded, top rules + Pareto).
- **Intel & Export (`/intel`):** Durable IOCs (`#ioc-summary`: outbound C2 IPs, post-auth stager URLs & domains, malware SHA-256 hashes with `vhash` clusters, SSH keys), live STIX 2.1 bundle composition (`#stix-export`, fail-closed when `reporting.json` is unavailable), one-click `/download/stix` (`.json`), and `/download/iocs.csv.gz` raw IOC export.
- **System Health (`/health`):** 3rd-party API integration config and last-run status, scheduled pipeline unit timings, Bronze/Silver dataset liveness, live non-root `statvfs` disk headroom, per-tier datalake storage footprint, and recent sanitized error messages (zero secret values exposed).
  - **Overall Status meanings:** **`Healthy`** = zero criticals, warnings, rate-limits, and usable disk `<= 70%`; **`Degraded`** = pipeline still wrote data, but at least one non-critical issue is listed below (e.g., provider `auth_failed`, `Warning (Rate Limit)` / cooldown, `Silent (1d)`, or disk `70–80%`); **`Critical`** = data capture or retention is endangered (`pipeline_starved`, `Silent (2+d)`, `transform_failed`, failed systemd unit, or disk `> 80%`).
  - **Integration & alert labels:** **`Not Configured`** means an optional key is intentionally omitted and never degrades Overall Status; **`C · W · I`** on the alerts card counts **Critical**, **Warning**, and routine **Info** (e.g. free-tier `rate_limit`) events for the latest partition.

### 7.4 Multi-day progression

With `read_gold_range()`, the Vigil dashboard aggregates `behavioral_progression` across any selected window (`7d`, `30d`, `custom`, or `all`) and flags IPs active across 2+ days. There is no `behavioral_progression_multiday` gold table — per-stage lossless slow-burn detection remains tracked on the [README Roadmap](/README.md#roadmap).

---

## Ongoing: What to Watch

| Interval | Check | Command |
|---|---|---|
| Daily | Bronze growing | `ls /var/lib/lantana/datalake/bronze/dataset=cowrie/` |
| Daily | Silver/gold populated | `ls /var/lib/lantana/datalake/gold/daily_summary/` |
| Daily | Pipeline timers ran cleanly | `systemctl list-timers 'lantana-*' && sudo journalctl -u 'lantana-*.service' --since today \| tail -20` |
| Weekly | Disk usage | `df -h /var/lib/lantana/` |
| Weekly | Enrichment cache size | `sqlite3 /var/lib/lantana/datalake/.enrichment_cache.db "SELECT COUNT(*) FROM cache;"` |
| Monthly | GeoIP MMDB updated | `ls -la /var/lib/lantana/collector/geoip/` |
| Monthly | Suricata rules updated | `suricata-update --data-dir /var/lib/lantana/honeywall/suricata` |

---

## Post-v1.5 Analytical Follow-Ups

The v1.5 release ships self-owned pinned GHCR honeypot images, Dionaea `lantana_json` (attributed binaries, download URLs, MSSQL/MySQL `sql_command`, structured HTTP POST bodies), monotonic behavioral-anchored risk scoring, durable STIX 2.1 IOCs (`extracted_iocs`), stateless D-1/D-2 dead-man's-switch alerting, decoupled 14d/180d retention, and the 5-view air-gapped Vigil dashboard (`Overview`, `Attackers`, `Behavior`, `Intel & Export`, `Health`) with 5 date windows. Remaining roadmap items tracked on the [README Roadmap](/README.md#roadmap):

- **Lossless multi-day slow-burn detection**: streaming or per-day stage-timestamp persistence to replace the window-rollup proxy without risking collector OOMs.

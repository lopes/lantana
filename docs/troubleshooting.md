# Lantana Operations: Troubleshooting Guide

This document outlines standard operating procedures for debugging and troubleshooting the Lantana honeypot infrastructure.

---

## Podman Quadlets & Sensor Management

Lantana utilizes Podman Quadlets to manage honeypot sensors. Quadlets allow us to write declarative `.container` files that systemd automatically translates into native `.service` files.

Because sensors run under a dedicated, non-interactive service account, standard `systemctl` commands from an admin account will fail without proper environment context.

### The Management Wrapper Context

To interact with the container user's systemd session, we must explicitly pass the runtime directory and D-Bus session. Furthermore, running `sudo` from a directory this user cannot read (like `/home/lantana`) will result in an immediate `Permission denied` error due to how the kernel handles the Current Working Directory.

#### Always change to a neutral directory before debugging

```sh
cd /tmp
```

#### Export the necessary variables (or use the wrapper if deployed)

```sh
CONTAINER_USER="stigma" # Default service account for sensors
CONTAINER_UID=$(id -u $CONTAINER_USER)
CONTAINER_ENV="env XDG_RUNTIME_DIR=/run/user/$CONTAINER_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$CONTAINER_UID/bus"
```

### Common Operations

#### Reloading Quadlets (Required after modifying a `.container` file)

```sh
sudo -u $CONTAINER_USER $CONTAINER_ENV systemctl --user daemon-reload
```

#### Checking Sensor Status & Restarting

```sh
sudo -u $CONTAINER_USER $CONTAINER_ENV systemctl --user status cowrie.service
sudo -u $CONTAINER_USER $CONTAINER_ENV systemctl --user restart cowrie.service
```

#### Tailing Sensor Logs

Because the container is managed by the user's systemd daemon, logs are routed to the systemd journal for that specific user.

```sh
sudo -u $CONTAINER_USER $CONTAINER_ENV journalctl --user -u cowrie.service -f
```

### Storage and Permission Flags

When debugging volume mounts in the `.container` files, verify the correct flags are applied based on the use case:

- `UserNS=keep-id`: Maps the user running the container to the exact same UID inside the container. Essential for honeypots that write logs directly to host-mounted directories.
- `:Z`: SELinux/AppArmor private container security label. Prevents cross-container data leakage.
- `:U`: Podman automatically `chown`s the source directory on the host to match the container's internal UID/GID.

---

## Dionaea Sensor

The dinotools/dionaea image has several startup quirks that produce
silent or near-silent failures. The container will be `healthy` per
Podman's healthcheck (which only checks process liveness via `pgrep`)
even when dionaea has bound zero ports. See [`honeypots.md`](/docs/honeypots.md#container-model-and-constraints)
for the deployment invariants this section troubleshoots.

### Symptom: Exit status 133 immediately, no log content

dionaea launched and died within ~100ms. The container shows
`status=exited (133)` in `systemctl --user status dionaea.service`,
the container itself is already gone (auto-rm) so `podman logs` says
"no such container", and neither `dionaea.log` nor `dionaea-errors.log`
exist on disk.

Most likely cause: a missing capability. The bundled entrypoint runs
`dionaea -u dionaea -g dionaea` which calls `setuid()`/`setgid()` to
drop privileges; without `CAP_SETUID` / `CAP_SETGID` the call fails
and dionaea exits silently with 133. Confirm by checking the Quadlet:

```bash
grep -A2 AddCapability /etc/containers/systemd/users/2001/dionaea.container
```

Should show `NET_BIND_SERVICE SETUID SETGID CHOWN FOWNER`. If
anything is missing — re-deploy the dionaea role.

### Symptom: dionaea runs but binds zero ports

`podman exec sensor-dionaea python3 -c "import socket; ..." ` returns
`ConnectionRefusedError` for every catalog port even though the
process is alive. The killer is the YAML parser:

```bash
sudo grep -i UnicodeDecodeError /var/log/lantana/sensor/dionaea/dionaea-errors.log
```

If you see a `UnicodeDecodeError('ascii', ...)` referencing one of our
service yamls, the file has a non-ASCII byte (em-dash, arrow, smart
quote) in a comment or value. Python 3.6's PyYAML falls back to the
ASCII codec without a BOM and aborts the *entire* service registration
loop, not just the bad file — so one stray `—` in
`services-enabled/mssql.yaml` knocks out FTP, HTTP, SMB, and everyone
else too.

Fix:

```bash
# Find any non-ASCII bytes in the rendered yamls on the VPS:
sudo python3 -c "import pathlib; [print(p, sum(1 for b in p.read_bytes() if b>127)) for p in pathlib.Path('/etc/lantana/sensor/dionaea/services-enabled').glob('*.yaml')]"
```

Any nonzero count means that template has a non-ASCII char. Open the
matching `roles/dionaea/templates/services-enabled/<svc>.yaml.j2`,
replace `—` with `--`, `→` with `->`, smart quotes with straight
quotes, then re-deploy.

### Symptom: SIP only — "attempt to write a readonly database"

The bundled image's SIP module opens `accounts.sqlite` from the
supervisor process (running as container root) before the worker
process drops privileges to the `dionaea` user. The worker then can't
write to the root-owned file and dionaea logs:

```
sqlite3.OperationalError: attempt to write a readonly database
```

`:memory:` doesn't fix it (other on-disk state in the SIP module hits
the same race). SIP is intentionally not in the v1.0.0 catalog for
this reason — see [`honeypots.md`](/docs/honeypots.md#dionaea). If you see
this error for any *other* service, the same root cause applies and
the same `:memory:` / drop-from-catalog escape hatches are your
options.

### Symptom: Half-deployed state from earlier failed run

The state directory `/var/lib/lantana/sensor/dionaea/` keeps seed
files (sqlite DBs, FTP root, http template) between runs. After a
failed deploy these can have wrong ownership and produce cryptic
permission errors. To fully reset:

```bash
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 systemctl --user stop dionaea.service
sudo rm -rf /var/lib/lantana/sensor/dionaea/*
sudo rm -f /var/log/lantana/sensor/dionaea/{dionaea.log,dionaea-errors.log,dionaea.json}
ansible-playbook -i inventories/op_<name>/inventory.yml playbooks/deploy_honeypots.yml --ask-vault-pass
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 systemctl --user start dionaea.service
```

The re-deploy re-renders the `wwwroot/index.html` page (otherwise the
HTTP service has no root to serve) and the entrypoint's `init_lib`
re-seeds state dirs from the image's `template/lib/`.

### Diagnostic recipe: which ports are actually bound

```bash
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 podman exec sensor-dionaea python3 -c "import socket
for p in (21,80,135,445,1433,3306):
    try: socket.create_connection(('127.0.0.1',p),1).close(); print(p,'BOUND')
    except Exception as e: print(p,'NOT_BOUND',type(e).__name__)"
```

Runs inside the container's netns; reports each catalog port from
dionaea's own loopback. `BOUND` means dionaea has bound that port;
`ConnectionRefusedError` means nothing's listening; other exceptions
are unusual and worth pasting into a bug report.

---

## Cowrie Sensor

The `cowrie/cowrie:latest` image is a rolling tag and has historically bumped the in-container `cowrie` user UID across rebuilds (998 → 999 around 2026-06-08). Lantana handles UID drift declaratively via `UserNS=keep-id:uid=999,gid=999` in the Quadlet (see CLAUDE.md "Honeypot deployment discipline"), but the mapping only works if the host-side bind-mount contents are already owned by `stigma`. Two failure modes flow from this — the second is the silent one and the more painful.

### Symptom: cowrie accepts logins but logs zero `cowrie.command.*` events

Bronze contains `cowrie.session.connect`, `cowrie.login.success`, and `cowrie.session.closed` but no `cowrie.command.input` rows for the whole day. Attackers are landing — they just can't run a command that ever reaches the JSON log. Downstream this surfaces as the cowrie normaliser crashing on `ColumnNotFoundError: unable to find column "input"` (defect of the 2026-06-08 → 2026-06-10 incident, fixed structurally by the conditional-column guard in `pipeline/src/lantana/models/normalize.py`, but the bronze-side absence is the upstream symptom worth recognising).

Two distinct root causes share this symptom:

1. **TTY transcript write fails.** Every command-exec session opens `/cowrie/cowrie-git/var/lib/cowrie/tty/<sid>-Ne.log` for writing. If the `tty/` directory or its files are owned by a host UID that doesn't match the container `cowrie` user's mapping, Twisted aborts the exec path **before** emitting `cowrie.command.input`. Auth events still log because they fire earlier in the session lifecycle. Diagnose:
   ```bash
   sudo journalctl _SYSTEMD_USER_UNIT=cowrie.service --since=-1h | grep PermissionError
   # Expect: lines like  [twisted.conch.ssh.session#critical] Error executing command "..."
   #                     builtins.PermissionError: [Errno 13] Permission denied: '/.../tty/...-e.log'
   ```
   Fix is the chown recipe below.

2. **`jsonlog` output plugin failed at startup.** Twisted loads output plugins exactly once when cowrie's `twistd` process initialises. `cowrie/output/jsonlog.py` opens the JSON log with `mode="w"` — needs write permission on an existing file. If the file is owned by a stale UID at process-start time, the plugin raises `PermissionError`, Twisted disables it for the rest of the process lifetime, and cowrie keeps running with only the systemd-journal sink. The container appears healthy. SSH/Telnet auth works. The journal shows traffic. But `cowrie.json` mtime stops dead and Vector ships nothing to bronze, because Vector tails the file, not the journal. Diagnose:
   ```bash
   sudo journalctl _SYSTEMD_USER_UNIT=cowrie.service --since='<container-restart-time>' | grep -E 'Failed to load|jsonlog'
   # Expect: "Failed to load output engine: jsonlog"  immediately followed by a PermissionError traceback.
   sudo stat /var/log/lantana/sensor/cowrie/cowrie.json
   # Compare mtime to container .StartedAt — if they match the container restart and nothing later, jsonlog is dead.
   ```
   Crucially, chowning the file **after** cowrie has already started does NOT bring jsonlog back — the plugin is gone until the container is restarted. The chown still has to happen first; the restart cements it.

### Recovery recipe — image rebase or first `UserNS=keep-id` deploy

Run **before** the Quadlet restart fires, not after. Ad-hoc only, not in Ansible (per repo policy):

```bash
# 1. Survey orphan ownership (anything not stigma in the cowrie state tree).
sudo find /var/lib/lantana/sensor/cowrie /var/log/lantana/sensor/cowrie \
     ! -user stigma -printf '%u:%g %p\n'

# 2. Chown the orphans to stigma (they appear as cowrie inside the container under keep-id).
sudo find /var/lib/lantana/sensor/cowrie /var/log/lantana/sensor/cowrie \
     ! -user stigma -exec chown stigma:stigma {} +

# 3. THEN deploy / restart cowrie.
ansible-playbook -i inventories/<op>/inventory.yml playbooks/deploy_honeypots.yml
# OR if the container is already running with jsonlog disabled:
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 systemctl --user restart cowrie.service

# 4. Verify jsonlog loaded cleanly (no PermissionError traceback).
sudo journalctl _SYSTEMD_USER_UNIT=cowrie.service --since=-1min \
    | grep -E 'Loaded output engine: jsonlog|Failed to load'
```

If step 4 shows "Loaded output engine: jsonlog" with no preceding traceback, the plugin is healthy. Validate end-to-end with the active SSH probe in `docs/validation.md` §0.2 — the `cowrie.command.input` event must appear in `cowrie.json` within 1–2 seconds of the command landing.

---

## Nftables Filtering & Routing

Lantana uses `nftables` for strict blast-radius containment and routing traffic to the rootless decoys.

### Viewing the Active Ruleset

To see exactly what is loaded into the kernel right now (including dynamic sets):

```sh
sudo nft list ruleset
```

### Live Packet Tracing

If a decoy is not receiving traffic, utilize nftables native tracing. First, add a trace rule to your prerouting chain:

```sh
sudo nft add rule inet filter prerouting ip saddr <YOUR_TEST_IP> meta nftrace set 1
```

Then, monitor the flow in real-time to see exactly which chain is dropping or accepting the packet:

```sh
sudo nft monitor trace
```

### Debugging Dual-Stack

Ensure your rules use the `inet` family to cover both IPv4 and IPv6. If IPv6 is failing, verify your rules aren't explicitly matching `ip daddr` (IPv4 only) instead of `ip6 daddr` or generic port matches. The same applies to `saddr` matches — `ip saddr` won't trigger on IPv6 source addresses.

---

## Suricata Intrusion Detection

Suricata monitors the honeypot interfaces to provide out-of-band detection and telemetry enrichment.

### Validating Configuration Syntax

Before restarting Suricata, always test the YAML configuration and rule syntax:

```sh
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### Live Reloading Rules

Do not restart the Suricata service just to update rules, as this drops packets. Use the built-in command tool:

```sh
sudo suricatasc -c ruleset-reload
```

### Testing Signatures against PCAPs

If you need to verify if a Suricata rule correctly fires against a specific attack payload, test it offline against a packet capture using `jq` to parse the structured output:

```sh
sudo suricata -c /etc/suricata/suricata.yaml -r /tmp/test-attack.pcap -l /tmp/suricata-test-logs/
cat /tmp/suricata-test-logs/eve.json | jq 'select(.event_type=="alert")'
```

### eve.json Event Type Policy

The `outputs[].eve-log.types` block in `roles/suricata/templates/suricata.yaml.j2` emits **only `alert` and `flow`** events. All other types — `stats`, `netflow`, `anomaly`, `fileinfo`, `http`, `dns`, `tls`, `ssh`, `smb`, `ftp`, `rdp`, `smtp`, `tftp`, `ike`, `krb5`, `snmp`, `rfb`, `sip`, `dhcp`, `mqtt`, `http2`, `quic` — are disabled.

**What's kept and why:**

- **`alert`** — the only event type the pipeline consumes today. `models/normalize.py` dispatches `event_type == "alert"` to OCSF Detection Finding (2004) with `alert_signature`, `alert_signature_id`, `alert_severity`, `alert_category`, `alert_action` flattened into silver. `transform/metrics.py` filters silver to `class_uid == CLASS_DETECTION_FINDING` to compute the detection findings gold table.
- **`flow`** — retained for a planned behavioural-engagement metric. Carries fields nftables logs cannot provide: `app_proto` (Suricata's application-protocol classification — useful for understanding what attackers tried on non-honeypotted ports), `bytes_toserver` / `bytes_toclient` (volume discriminator between casual scanners and active engagement), `state` (clean-close vs. RST vs. timeout), and `community_id` (deterministic 5-tuple hash for cross-tool correlation). No gold consumer wired today; intended for v1.1+.

**Why everything else is dropped:**

The pipeline's silver normaliser does not extract a single field from `http`, `dns`, `tls`, `ssh`, `smb`, or any other protocol decoder. Greps for `tls.ja3`, `http_user_agent`, `dns_rrname`, `smb_command`, etc., return empty across `pipeline/src/`. The Network Activity (4001) silver rows produced from non-alert events carry only src/dst/timestamp/proto and have no gold consumer. Carrying these event types in bronze is paying real cost — disk, Vector parsing, Polars memory — for capability that is not wired and that overlaps with honeypot logs anyway (Cowrie covers SSH semantics, Dionaea covers HTTP/SMB/FTP/MySQL/MSSQL/EPMAP). The decision was made to drop them and re-enable individual types when a real consumer ships, rather than carrying them indefinitely as option-value.

`stats` and `netflow` are the specific exception worth flagging: they were the *first* cut, made after the 2026-05-30 OOM incident. `stats` events are ~68 KB each of Suricata's internal process counters (app-layer totals, decoder stats, detect engine state) — zero detection or intel value. `netflow` are flow *summaries* that mostly duplicate `flow` events. The Vector OPSEC filter (`filter_suricata`, `roles/suricata/templates/suricata.vector.yaml.j2`) cannot drop `stats` because they have no `src_ip` field — the filter's CIDR/WAN checks never engage.

**The 2026-05-30 incident (why the policy exists):** `lantana-enrich.service` was OOM-killed at 01:01:38 UTC processing the previous day's bronze. The trigger was a suricata bronze file ~3.25× its typical size (864 MB vs. ~266 MB on a normal day), with `stats` accounting for ~31% of bytes and `netflow` another ~30%. Polars materialises the day's NDJSON in memory during bronze→silver normalize; the enricher peaked at 6.2 GB anon-rss on a 7.6 GB single-node deployment with no swap, and the global OOM killer fired before any silver was written. Downstream `lantana-transform` and `lantana-report` ran on empty silver, the brief posted "No data available for this date" to Discord with a green embed, and the day's intel was lost. The deeper cut to alert + flow followed once code analysis confirmed nothing in `pipeline/src/` consumed the other event types.

**Re-enabling a type:** verify there's an actual silver/gold consumer for the fields you want. Don't enable a decoder "for future use" — option-value paid as bronze cost adds up. Profile bronze row sizes first (`p99 ≫ p50` means a small population of giant events dominates — that's the cut target). Suricata's top-level `stats: enabled: true` block (separate from the eve.json output) may stay enabled — it controls counter *collection* for Suricata's own observability and does not contribute to bronze.

---

## Systemd & Debian Core

### Verifying Lingering

If containers fail to start on boot, verify that lingering is actually enabled for the service account. A directory matching the user's name should exist in `/var/lib/systemd/linger/`:

```sh
ls -l /var/lib/systemd/linger/$CONTAINER_USER
```

### Checking Global System State

If the Debian host is acting erratically, check for degraded units. This is often the fastest way to find a failing mount or crashed agent.

```sh
systemctl --failed
```

### Ansible Fact Caching Issues

If Ansible is acting on outdated host data during playbook runs, clear the fact cache manually on the control node or force fact gathering:

```sh
ansible-playbook site.yml -e "ansible_facts_parallel=false" --flush-cache
```

### Ansible "Permission denied (publickey)" mid-session

Symptom: an `ansible-playbook` run that worked earlier in the same workstation session suddenly fails with `Permission denied (publickey)` from `Gathering Facts`, even though no SSH-side change happened on the VPS.

Most common cause on workstations that maintain **per-operation SSH keys** (e.g. `id_ed25519` for git/local, `ovh_id_ed25519` for the OVH VPS, `aws_id_ed25519` for an AWS host): the ssh-agent has the wrong key loaded. Earlier the operation's key was cached; then something — running `ssh-add` for a different purpose, a Keychain timeout, agent restart, OS sleep — evicted it. The default key remains loaded and gets offered first, but it's not authorised on the target host, and Ansible doesn't fall back to trying other keys before the server refuses.

Diagnose and fix:

```sh
# What's currently in the agent?
ssh-add -l

# Load the operation-specific key.
ssh-add ~/.ssh/<operation>_id_ed25519
```

To pin the key for a given operation so the agent state stops mattering, set `ansible_ssh_private_key_file` on the host (or in `group_vars/all/main.yml`) so Ansible always uses the right key regardless of which keys happen to be in the agent:

```yaml
ansible_ssh_private_key_file: ~/.ssh/<operation>_id_ed25519
```

Pinning is the durable fix; `ssh-add` is the immediate one.

### Ansible Debug Task

Whenever a task is failing due to variable errors, you can add the following task before the one that's failing to check out the values:

```yaml
- name: "Debug variable"
  debug:
    var: network # replace by the variable you're debugging
```

---

## Manual Testing on Sensors

In an "as-code" project, the usual workflow is:

1. Update the code with the changes you want to see.
2. Run deployment playbooks to apply changes in the environment.
3. Check the new behavior.

No more script-oriented manual patching. It is all defined in the code.

> [!WARNING]
> The only exception to this workflow is when you must rapidly test or debug specific behaviors directly on the sensor. If you manually alter configurations outside of Ansible to test a hypothesis, that node is now **tainted**. Once testing is complete, the node must be reprovisioned to eliminate state drift.

### Testing SSH Honeypots

SSH honeypots will usually accept almost any public key offered to them, allowing automatic login.

Use the command below to test SSH connections to decoys. It explicitly disables key exchange mechanisms and known-hosts checks, ensuring you do not mix real workstation configurations with the test environment, nor accidentally leak your real SSH identities to the honeypot:

```sh
ssh -o PubkeyAuthentication=no -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -v -6 root@fd99:10:50:99::100 -p 60090
```

---

## Third-Party Integrations

Lantana's enrichment depends on four HTTP APIs (AbuseIPDB, Shodan, VirusTotal, GreyNoise) and one local MMDB dataset (MaxMind GeoLite2). When silver Parquet shows missing enrichment columns or the dashboard's geographic map is empty, this section is where you start. For the full integration catalog (endpoints, auth, free-tier limits, field extraction), see [`integrations.md`](/docs/integrations.md); for the role enrichment plays in the bronze → silver pipeline, see [`pipeline.md`](/docs/pipeline.md#31-bronze-to-silver-daily-enrichment).

### Probe scripts

Two diagnostic scripts mirror the two enrichment paths. Both run from `pipeline/` via `uv run`:

| Script | What it exercises | Default flags |
|---|---|---|
| [`scripts/probe-enrichment.py`](/scripts/probe-enrichment.py) | Live HTTP API call per provider, prints raw upstream response + normalized `EnrichmentResult.data` | `--ip <addr>` repeatable; `--hash <sha256>` for VT only; `--provider <name|all>`; `--secrets <path>`; `--no-raw`; `--insecure` |
| [`scripts/probe-mmdb.py`](/scripts/probe-mmdb.py) | Downloads City + ASN MMDBs if missing (using `vault_apikey_maxmind` from `--secrets`), then queries them | `--ip <addr>` repeatable; `--mmdb-dir <path>` (auto-falls back to `/tmp/lantana/mmdb` off-collector); `--secrets <path>`; `--force-download`; `--no-raw`; `--insecure` |

Both scripts auto-translate legacy vault key names (`vault_<service>_api_key`, `vault_maxmind_license_key`) to the current `vault_<type>_<service>` form, so a hand-written secrets file from before 2026-05 still parses — they print a stderr `[note: ...]` when translation kicks in.

### "Provider returned no data" — what's normal vs broken

The enrichment runner treats a few HTTP responses as **not errors** because they're routine for honeypot attacker IPs:

| Response | Provider | Pipeline behaviour |
|---|---|---|
| `404` | GreyNoise | IP isn't in the dataset → row gets `greynoise_classification: "unknown"` and false booleans. Common for residential botnets. |
| `404` | Shodan    | IP was never scanned → row gets empty `shodan_*` fields. Common for the same reason. |
| `404` | VirusTotal (IP) | Never indexed → row gets zero counts. Less common but possible. |
| `404` | VirusTotal (hash) | Fresh malware not yet seen by any AV → zero counts. Common for first-day captures. |
| `200` with `abuseConfidenceScore: 0` | AbuseIPDB | No abuse reports → row populated with clean fields. The default state. |

So "missing fields" in silver Parquet is the **normal** state for the vast majority of attacker IPs. It only indicates a problem when columns are missing for ALL rows — that suggests provider misconfiguration.

### "Provider returned an error" — diagnosing

The runner records every failure to `/var/lib/lantana/datalake/enrichment_errors.json` (NDJSON, one line per `(provider, error_type)` pair per day). Inspect:

```bash
sudo -u nectar jq . /var/lib/lantana/datalake/enrichment_errors.json | tail -50
```

Common `error_type` values and what they mean:

| `error_type` | Cause | Action |
|---|---|---|
| `auth`         | 401/403 — bad API key                                  | Re-check `vault_apikey_<service>` and re-run `deploy_single.yml` with the `collector` tag. The runner now fails fast on auth errors (no retries), so the count equals the number of IPs that were attempted. |
| `rate_limit`   | 429                                                    | Provider quota exhausted. Retry tomorrow (cache covers ≥7 days, longer for malicious IOCs — see CLAUDE.md → Enrichment cache lifecycle). Consider trimming the IP set or upgrading the free tier. |
| `timeout`      | TCP timeout                                            | Transient. The runner retries 3× with exponential backoff before recording. If sustained, check the collector's egress firewall. |
| `http_4xx`     | Other 4xx — most commonly bad request / missing param  | Provider API contract changed. Check the upstream docs (linked from `integrations.md`) and the recent provider changelog. |
| `http_5xx`     | Provider-side outage                                   | Wait it out. The runner retries 3× before giving up. Confirm with the probe script — if `probe-enrichment.py --provider <name>` also fails, it's not us. |
| `unknown`      | Catch-all                                              | Read the `message` field in the error file — usually a JSON parse error or a transport-level issue. |

The runner is designed so that **one provider failing never blocks the others**: each provider's enrichment is independent, and a `RetryError` after exhausted retries on provider A still leaves providers B–E with full data for the same IP. Per-IP errors don't block other IPs either.

### MaxMind silent failure (`.geo.*` fields empty)

If the dashboard's geographic page is empty or all attackers show "unknown country":

1. **Check the vault has the key.** `ansible-vault view inventories/op_<name>/group_vars/all/vault.yml | grep maxmind`. If `vault_apikey_maxmind` is missing or empty, Ansible silently skipped the MMDB download — that's by design but it's the most common cause.
2. **Check the MMDBs exist on the collector.** `ls -la /var/lib/lantana/collector/geoip/` should show two ~70 MB and ~10 MB files dated within the last month.
3. **Verify Vector can read them.** `sudo -u vector cat /var/lib/lantana/collector/geoip/GeoLite2-City.mmdb | head -c 16 | xxd` — first bytes should not be all zeros.
4. **Run the probe.** `cd pipeline && uv run python ../scripts/probe-mmdb.py --ip 8.8.8.8` should print the City + ASN records and the `.geo.*` block.

If step 4 succeeds but bronze NDJSON still has empty `.geo.*` fields, Vector's enrichment-tables block didn't reload after the MMDB refresh. `sudo systemctl restart vector` and check the next day's bronze.

### Workstation TLS verification failures

Homebrew Python 3.14 on macOS sometimes can't chain-validate TLS certs even with `certifi.where()` configured (symptom: `httpx.ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED]` while `curl` to the same URL works). Both probe scripts ship a `--insecure` flag for this case — it bypasses TLS verification and prints a loud warning. **Never use `--insecure` in production**; the collector on Debian 13 has a working trust store and doesn't need it.

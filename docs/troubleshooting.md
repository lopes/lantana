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

Ensure your rules use the `inet` family to cover both IPv4 and IPv6. If IPv6 is failing, verify your rules aren't explicitly matching `ip daddr` (IPv4 only) instead of `ip6 daddr` or generic port matches.

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

### Ansible Debug Task

Whenever a task is failing due to variable errors, you can add the following task before the one that's failing to check out the values:

```yaml
- name: "Debug variable"
  debug:
    var: network # replace by the variable you're debugging
```

---

## Tests

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

Lantana's enrichment depends on five HTTP APIs (AbuseIPDB, Shodan, VirusTotal, GreyNoise, PhishStats) and one local MMDB dataset (MaxMind GeoLite2). When silver Parquet shows missing enrichment columns or the dashboard's geographic map is empty, this section is where you start. For the full integration catalog, see [`integrations.md`](integrations.md).

### Probe scripts

Two diagnostic scripts mirror the two enrichment paths. Both run from `pipeline/` via `uv run`:

| Script | What it exercises | Default flags |
|---|---|---|
| [`scripts/probe-enrichment.py`](../scripts/probe-enrichment.py) | Live HTTP API call per provider, prints raw upstream response + normalized `EnrichmentResult.data` | `--ip <addr>` repeatable; `--hash <sha256>` for VT only; `--provider <name|all>`; `--secrets <path>`; `--no-raw`; `--insecure` |
| [`scripts/probe-mmdb.py`](../scripts/probe-mmdb.py) | Downloads City + ASN MMDBs if missing (using `vault_apikey_maxmind` from `--secrets`), then queries them | `--ip <addr>` repeatable; `--mmdb-dir <path>` (auto-falls back to `/tmp/lantana/mmdb` off-collector); `--secrets <path>`; `--force-download`; `--no-raw`; `--insecure` |

Both scripts auto-translate legacy vault key names (`vault_<service>_api_key`, `vault_maxmind_license_key`) to the current `vault_<type>_<service>` form, so a hand-written secrets file from before 2026-05 still parses — they print a stderr `[note: ...]` when translation kicks in.

### "Provider returned no data" — what's normal vs broken

The enrichment runner treats a few HTTP responses as **not errors** because they're routine for honeypot attacker IPs:

| Response | Provider | Pipeline behaviour |
|---|---|---|
| `404` | GreyNoise | IP isn't in the dataset → row gets `greynoise_classification: "unknown"` and false booleans. Common for residential botnets. |
| `404` | Shodan    | IP was never scanned → row gets empty `shodan_*` fields. Common for the same reason. |
| `404` | VirusTotal (IP) | Never indexed → row gets zero counts. Less common but possible. |
| `404` | VirusTotal (hash) | Fresh malware not yet seen by any AV → zero counts. Common for first-day captures. |
| Empty `[]` | PhishStats | No phishing URLs known for this IP → `phishstats_url_count: 0`. The default state. |
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
| `rate_limit`   | 429                                                    | Provider quota exhausted. Retry tomorrow (cache covers 7-day TTL). Consider trimming the IP set or upgrading the free tier. |
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

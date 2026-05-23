# Lantana: New Operation Runbook

This runbook walks through standing up a brand-new Lantana operation end to end — from a freshly provisioned server to a running honeypot capturing real attacker traffic.

The flow is the same for every operation:

1. Prepare the server (SSH hardening, admin user).
2. Gather server facts (interface, IPs).
3. Clone an existing operation as the starting point.
4. Configure the inventory (host) and network (WAN).
5. Create the vault (enrichment API keys).
6. **Craft the narrative.** This is the cornerstone of the operation. A weak narrative produces a weak honeypot regardless of how well everything else is configured.
7. Deploy the base platform and honeypots.
8. Validate and capture a backup baseline.

> [!IMPORTANT]
> Steps 1–5 are mechanical. Step 6 is creative and load-bearing. Budget more time for the narrative than for everything else combined.

> [!NOTE]
> All IPs, ports, hostnames, and domains in this runbook are placeholders — IPs come from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 3849 (`2001:db8::/32`); domains from RFC 2606. Substitute your own values throughout. For the SSH admin port, **pick a random ephemeral port (49152–65535)** rather than reusing the runbook's `60090` — a known default makes a host fingerprintable as a Lantana deployment.

---

## 0. Prerequisites

### On your workstation

- A local checkout of this repo.
- An SSH key pair (`~/.ssh/id_ed25519` and `.pub` by default).
- `ansible-core` and `ansible-vault` installed locally.
- One of:
  - **For the bootstrap path** (step 1, Option A): SSH access to a freshly provisioned Debian-family VPS as an existing sudo-capable user. Cloud images typically ship one (`debian`, `ubuntu`, `admin`, …).
  - **For the Terraform path** (step 1, Option B): `terraform >= 1.5`, credentials for your Proxmox cluster, and a Debian 13 cloud-init template VM available on it.

### On the server (Deployment Contract)

The Ansible playbooks assume the target host is already in this state when a deploy starts. Both provisioning paths in step 1 — `bootstrap-ssh.sh` and the Terraform Proxmox module — deliver it.

- **OS**: Debian 13.
- **Admin user** (conventionally `lantana`):
  - Member of `sudo` with `NOPASSWD:ALL` via `/etc/sudoers.d/lantana`.
  - Your SSH public key in `~/.ssh/authorized_keys`.
  - Name matches `ansible_user` in the operation's `main.yml`.
- **SSH service** — `/etc/ssh/sshd_config.d/00-lantana.conf` contains:
  - `PasswordAuthentication no`, `PubkeyAuthentication yes`, `AuthenticationMethods publickey`, `PermitRootLogin no`.
  - `Port <random ephemeral port 49152–65535 chosen by the operator>` — never `22`, never the runbook's example `60090`.
  - That port matches `ansible_port` in the operation's `main.yml`.
- **`ssh.socket` disabled** — Debian 13 ships socket activation enabled, which silently keeps `sshd` listening on `22` regardless of the drop-in config.
- **Python 3** installed (required for Ansible module execution).

If you provision by hand (no Terraform, no script), satisfy the contract manually before step 2.

---

## 1. Prepare the Server

Two paths to satisfy the [deployment contract](#on-the-server-deployment-contract). Pick whichever fits your infrastructure.

### Option A — Bootstrap an existing VPS

For a Debian-family VPS or pre-existing host you already have SSH access to. `bootstrap-ssh.sh` creates the `lantana` admin user, installs your pubkey, and hardens `sshd` onto your chosen port.

```bash
scripts/bootstrap-ssh.sh <host> <initial_ssh_user> <ssh_key> <ssh_port>

# Example: fresh cloud-image VPS where the default user is `debian`
scripts/bootstrap-ssh.sh 203.0.113.42 debian ~/.ssh/id_ed25519 60090
```

The script will:

- Create the `lantana` admin user with passwordless sudo.
- Inject your public key into `lantana@host:~/.ssh/authorized_keys`.
- Write `/etc/ssh/sshd_config.d/00-lantana.conf` (key-only auth, your chosen port).
- Comment out any explicit `Port 22` in the main config and disable `ssh.socket`.
- Restart `ssh.service`.

### Option B — Provision with Terraform (Proxmox)

For Proxmox-hosted operations, `infra/terraform/environments/proxmox/` clones a Debian 13 template and applies a cloud-init that delivers the same end-state as `bootstrap-ssh.sh`.

1. Pick a random ephemeral SSH admin port (49152–65535) — same rule as Option A.
2. Provide your variables (Proxmox endpoint and credentials, `template_vm_id`, `operation_name`, `ssh_public_key`, and the `ssh_port` you just picked). See `infra/terraform/environments/proxmox/variables.tf` for the full input list — `ssh_port` has no default and is validated against the ephemeral range.
3. `terraform init && terraform apply` from `infra/terraform/environments/proxmox/`.
4. Use that same `ssh_port` value as `ansible_port` in step 4's `main.yml`.

The rendered cloud-init writes the same `/etc/ssh/sshd_config.d/00-lantana.conf` drop-in `bootstrap-ssh.sh` does, disables `ssh.socket`, and restarts `ssh.service` — so the host arrives at a contract-identical state.

### Verify (both paths)

```bash
ssh -p <ssh_port> -i ~/.ssh/id_ed25519 lantana@<host> 'sudo -n true && echo ok'
```

Expected output: `ok`. Anything else means the contract isn't fully satisfied — re-check sshd, sudo, key, and port before moving to step 2.

---

## 2. Gather Server Facts

On the prepared server, collect the values you'll plug into the inventory.

```bash
ssh -p 60090 -i ~/.ssh/id_ed25519 lantana@<host>

# WAN interface and addressing
ip -br link                       # interface name (eno1, ens3, enp2s0, ...)
ip -br addr show dev <iface>      # IPv4 + IPv6, with netmask
ip -4 route show default          # confirm IPv4 default route
ip -6 route show default          # confirm IPv6 default route if dual-stack
```

Record the following — you'll paste them into the inventory in step 4:

- WAN interface name (e.g. `eno1`)
- IPv4 address with prefix (e.g. `203.0.113.42/24`)
- IPv6 address with prefix (e.g. `2001:db8:1::1/64`) — or note that IPv6 is unavailable on this host.

---

## 3. Clone an Existing Operation

Each operation is a self-contained Ansible inventory under `config/ansible/inventories/op_*`. `op_single` is the canonical starting point for single-node deployments.

Pick a short, lowercase name for the operation. It surfaces in MOTDs, log paths, Parquet partitions, and STIX bundle IDs, so avoid operator initials, real customer names, or anything tied back to you — opaque codenames (`op_dovetail`, `op_canary`, `op_marlin`) work well.

```bash
cd config/ansible
cp -r inventories/op_single inventories/op_<name>
```

You now have:

```
inventories/op_<name>/
├── inventory.yml
└── group_vars/all/
    ├── main.yml         # SSH/connection + platform mode
    ├── network.yml      # WAN interface + IP addressing
    ├── narrative.yml    # The persona (cornerstone — see step 6)
    └── reporting.yml    # Operator identity + pseudonyms
```

`vault.yml` does not exist yet; you'll create it in step 5.

---

## 4. Configure Inventory, Network, and Reporting

Walk through each file below and fill in the values from steps 1–2. The vault (`vault.yml`) is handled separately in step 5.

### `inventory.yml`

Set `ansible_host` to the server's public IP. Pick which honeypots to ship via `sensor_honeypots` — `cowrie` alone is a sensible first deploy; uncomment additional roles later.

```yaml
all:
  children:
    single_nodes:
      hosts:
        sn-01:
          ansible_host: 203.0.113.42
          lantana_profile: "single_node_sensor"
          sensor_honeypots:
            - cowrie
            # - dionaea     # uncomment to deploy
```

### `group_vars/all/main.yml`

Confirm the SSH user, port, and key path match what `bootstrap-ssh.sh` configured, and set `lantana.mode` to `single` or `multi` (single is the default this runbook assumes):

```yaml
ansible_user: "lantana"
ansible_port: "60090"                          # the ephemeral port you chose in step 1
ansible_private_key_file: "~/.ssh/id_ed25519"

lantana:
  mode: "single"                               # or "multi"
```

### `group_vars/all/network.yml`

Set the WAN block to the values from step 2.

```yaml
network:
  honeywall:
    wan:
      interface: "eno1"                       # from `ip -br link` on the server
      ipv4: "203.0.113.42/24"                 # public IPv4 with prefix length
      ipv6: "2001:db8:1::1/64"                # public IPv6 with prefix, or remove the key entirely
```

> [!WARNING]
> A wrong WAN interface name is the most common first-run failure: the firewall role binds rules to it, and a typo silently produces a working playbook run with a non-functional firewall. Copy it verbatim from `ip -br link` on the server.

Leave the internal `lan`, `collectors`, and `sensors` blocks alone — they reference the dummy interface and never touch the public network.

### `group_vars/all/reporting.yml`

This file controls how the operation identifies itself in shared intelligence (Discord posts, STIX bundles). Set the operator identity — **you, the CTI publisher**, not the persona — and the sharing policy:

```yaml
reporting:
  operator:
    name: "Your Name or Handle"
    handle: "your_handle"
    contact: "https://yoursite.example/contact"
    pgp_fingerprint: ""                       # optional

  sharing:
    tlp: "GREEN"                              # CLEAR / GREEN / AMBER / RED
    community: "Lantana Threat Intel"
    discord_channel: "lantana-intel"          # channel name shown in reports
```

The Discord webhook URL itself lives in the vault (step 5), not here. Leave the `pseudonym_map` block alone — those labels are what your real WAN and internal IPs get rewritten to in shared output.

---

## 5. Create the Vault

Enrichment API keys, Discord webhook, and (optionally) the sudo password live in an Ansible Vault file. A tracked template exists at:

```
config/ansible/inventories/op_single/group_vars/all/vault.yml.example
```

### Workflow

```bash
cd config/ansible

# 1. Copy the template into your operation
cp inventories/op_single/group_vars/all/vault.yml.example \
   inventories/op_<name>/group_vars/all/vault.yml

# 2. Edit it in plaintext — fill in real keys
$EDITOR inventories/op_<name>/group_vars/all/vault.yml

# 3. Encrypt before deploying (or committing, if your op directory is tracked)
ansible-vault encrypt inventories/op_<name>/group_vars/all/vault.yml
```

After this, modifications use `ansible-vault edit` (auto-decrypt + re-encrypt) and inspection uses `ansible-vault view`:

```bash
ansible-vault edit inventories/op_<name>/group_vars/all/vault.yml
ansible-vault view inventories/op_<name>/group_vars/all/vault.yml | grep -E '^vault_'
```

If you re-deploy often, point `ANSIBLE_VAULT_PASSWORD_FILE` at a 0600-mode file containing just the password, or pass `--vault-password-file <path>` to `ansible-playbook`. Both replace `--ask-vault-pass` without prompting.

### Naming convention

`vault_<type>_<service>`:

- `type` is `apikey` or `webhook`
- `service` is the lowercase provider name (`virustotal`, `shodan`, `discord`, ...)

The same keys appear unchanged in the rendered `/etc/lantana/collector/secrets.json` on the collector — that file is just the decrypted view of the vault, not a separate schema. See [Vault ↔ secrets.json nomenclature](pipeline.md#vault--secretsjson-nomenclature) for the reasoning.

### What goes in the template

```yaml
# Required — no free public endpoint
vault_apikey_virustotal: "..."
vault_apikey_shodan:     "..."
vault_apikey_abuseipdb:  "..."

# Optional — public Community endpoint exists (see auth modes below)
vault_apikey_greynoise:  ""

# GeoIP enrichment (MaxMind GeoLite2 City + ASN)
# Free signup: https://www.maxmind.com/en/geolite2/signup
vault_apikey_maxmind:    "..."

# Reporting
vault_webhook_discord:   "https://discord.com/api/webhooks/..."

# Optional sudo password (skip if you use --ask-become-pass)
# vault_become_password: "..."
```

### Provider enablement rules

| Provider | Vault line missing | Vault line `""` | Vault line `"<key>"` |
|---|---|---|---|
| `virustotal` / `shodan` / `abuseipdb` | misconfiguration — provider runs with empty key, gets 401 | same | authenticated |
| `greynoise` | provider skipped (`provider_disabled` log) | community endpoint, anonymous (50/week) | community endpoint, key in header (higher rate limit) |
| `maxmind` | MMDB download skipped at deploy — Vector emits no `.geo.*` fields | same as missing | MMDBs downloaded + refreshed monthly |
| `discord` | reports generated locally only | same | webhook delivers daily brief |

So the only way to disable GreyNoise is to **omit the line entirely** — empty string keeps it enabled in unauthenticated community mode.

### References

- GreyNoise Community API: https://docs.greynoise.io/docs/using-the-greynoise-community-api (50 searches per 7 days)
- Endpoints, free-tier limits, extracted fields, and the live-probe workflow: [`integrations.md`](integrations.md)
- Auth-mode matrix (per-provider behaviour by vault state): [Provider auth modes](pipeline.md#72-provider-auth-modes)

---

## 6. Craft the Narrative

This is where most operations succeed or fail. The narrative is the deception story attackers see in every banner, certificate, MOTD, and service version. It drives whether the box reads as a credible target or as a honeypot pretending to be one.

### What makes a narrative work

- **Internal consistency.** Every detail must coexist plausibly. Don't pair a 2024 kernel with a 2014 OpenSSH unless the admin archetype explicitly explains it (e.g. "legacy box, kernel hand-bumped for a CVE patch"). Pick an OS first; let everything else flow from its stock repos.
- **Plausibility.** The company should look like a real-world organisation in the chosen sector. Localised legal suffixes (`Ltda`, `S.A.`, `GmbH`, `K.K.`), realistic domain conventions, sector-appropriate service mix.
- **Admin archetype.** A skilled SRE produces minimal banners, role-prefixed hostnames, and a tidy service mix. A junior contractor produces full-disclosure banners, default workgroups, generic hostnames, and a "vibe-coded" zoo of unrelated services on the same box. The archetype dictates banner verbosity more than anything else.
- **Era alignment.** Service versions, kernel, and OS release should belong to the same time window. Mixed eras get fingerprinted instantly.
- **Target audience.** Be intentional about who you want to attract. Old SSH on a Brazilian fintech invites different adversaries than a fresh Apache on a US e-commerce site.

### Schema

`narrative.yml` has four blocks. All fields are required — Jinja templates index into them directly:

| Block | Drives |
|---|---|
| `operation_name`, `sector`, `start_date` | Reporting metadata, MOTD, STIX bundles |
| `identity.*` | TLS certs (`C=`, `ST=`, `L=`, `CN=`), HTTP cert chains |
| `host.*` | Cowrie `uname -a`, MOTD, banner output |
| `services.*` | Cowrie SSH version, Dionaea FTP/HTTP/SMB/MSSQL/MySQL banners |

### Workflow

1. **Decide the archetype** (one sentence): sector + geography + hosting story + admin skill level. Example: *"German light-manufacturing SMB, on-prem migration to a budget EU VPS, mid-skill DevOps generalist."*
2. **Invoke the `scaffold-narrative` skill** in Claude Code (opened in this repo) with that sentence as input. Trigger it explicitly with `/scaffold-narrative …` or just describe the persona in plain English — the skill auto-triggers on phrases like "scaffold a narrative," "generate narrative.yml," or "create a persona for op_<name>." It produces a complete `narrative.yml` consistent with the archetype plus a list of fields worth reviewing.
3. **Review the output** against the schema below. Check the era / OS / service alignment by hand even when the skill gets it right — this is the file most worth understanding.
4. **Paste into** `inventories/op_<name>/group_vars/all/narrative.yml`.

#### Example invocations

> `/scaffold-narrative` German light-manufacturing SMB, on-prem migration to a budget EU VPS, mid-skill DevOps generalist who left default SMB workgroups and an unpatched kernel in place.

> Scaffold a narrative for `op_marlin`: small Brazilian fintech that outsourced infrastructure to a cheap Canadian VPS provider. Junior contractor stood up the host — defaults everywhere, EOL Ubuntu LTS, mismatched zoo of services.

> Generate `narrative.yml` for a Japanese e-commerce mid-market shop, hosted on a domestic provider, run by a skilled SRE who keeps banners minimal and the service surface tight.

The skill infers the company identity, host profile (OS release, kernel build, hostname), and internally consistent banners (SSH, FTP, HTTP, SMB, MySQL, MSSQL) for the era and admin archetype, then flags fields worth a manual sanity-check.

### Manual checklist (if not using the skill)

- `identity.country` is where the **company is registered**, not where the server is hosted. The TLS `C=` field reflects the company.
- `identity.company` uses a localised legal suffix.
- `identity.common_name` is a FQDN that fits the archetype (skilled → `api.<co>.<tld>`; unskilled → `<hostname>.<co>.<tld>`).
- `host.os_release`, `kernel_version`, and `kernel_build` are real stock repo strings for the chosen distro.
- `services.ssh.version` follows RFC 4253 (`SSH-2.0-OpenSSH_X.Yp Z [distro suffix]`).
- Banner verbosity matches the admin archetype (full disclosure for unskilled, minimal for skilled).
- MSSQL on Linux only exists from SQL Server 2017 onward — don't pair it with a pre-2017 OS without a story.

### What the narrative must NOT contain

- The real operator's identity, handle, or email (those go in `reporting.yml`).
- Real company names, customer names, or partner brands.
- References to the operator's own infrastructure outside this operation.

The persona is fiction. Everything in `narrative.yml` ships in artifacts attackers will see.

---

## 7. Deploy Base Platform

From `config/ansible/`:

```bash
ansible-playbook -i inventories/op_<name>/inventory.yml \
  playbooks/deploy_single.yml --ask-vault-pass
```

`bootstrap-ssh.sh` configures the `lantana` user with passwordless `sudo`, so privilege escalation needs no extra flag. If you've tightened `sudo` on the host to require a password, append `--ask-become-pass` (prompt at runtime) or set `vault_become_password` in `vault.yml` (no prompt).

For multi-node, swap `deploy_single.yml` for `deploy_multi.yml` and use the corresponding inventory.

---

## 8. Validate Base Platform

Run the automated validation playbook:

```bash
ansible-playbook -i inventories/op_<name>/inventory.yml \
  tests/validate-single-node.yml -vvv
```

Then verify on the host:

- `id stigma` (UID 2001) and `id nectar` (UID 2002) exist.
- The MOTD on login shows the operation name and persona hostname.
- `sudo systemctl status vector` is active.
- `sudo nft list ruleset` loads without error.

Move to step 9 only after the validation playbook passes cleanly.

---

## 9. Deploy and Validate Honeypots

Deploy the honeypot roles listed in `sensor_honeypots` in the operation's inventory. The same command applies for both single-node and multi-node — the playbook targets `single_nodes` and `sensor_low_nodes` automatically:

```bash
ansible-playbook -i inventories/op_<name>/inventory.yml \
  playbooks/deploy_honeypots.yml --ask-vault-pass
```

### Validate on the sensor

For single-node, connect to the host. For multi-node, connect to the sensor node. For each deployed honeypot, verify the service is running and the nftables DNAT rules are present. For `cowrie`:

```bash
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 systemctl --user status cowrie
sudo nft list ruleset | grep lantana_nat
cat /etc/lantana/sensor/cowrie/cowrie.cfg | head -5
```

### External smoke test (from your workstation)

Target the WAN IP. For multi-node, all external traffic enters via the honeywall, so the WAN IP is the honeywall's.

**Banner scan** — fingerprints must match the narrative era and OS:

```bash
nmap -sV -Pn -p 22,23,80,445,3306,1433 <host>
```

The SSH banner must match `services.ssh.version` in `narrative.yml`. If it does, the deception layer is live.

**SSH — simulate an attacker with no prior key** (forces password prompt, no local config pollution):

```bash
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PubkeyAuthentication=no \
    -o IdentityAgent=none \
    root@<host>
```

Type any password. You should land in Cowrie's fake shell. Confirm the prompt hostname matches `host.hostname` in `narrative.yml`, then disconnect. Without `PubkeyAuthentication=no` and `IdentityAgent=none`, your SSH agent may hand a key to Cowrie which accepts it silently — no password prompt and a false sense that auth was skipped.

**Telnet** (macOS ships without `telnet`; use `nc`):

```bash
nc <host> 23
```

### Validate telemetry and pipeline

Do this after at least one external connection (SSH or nc) so there are events to trace.

**Raw Cowrie events captured:**

```bash
sudo tail -3 /var/log/lantana/sensor/cowrie/cowrie.json
```

Should show JSON lines with `src_ip` matching your workstation's IP.

**Bronze datalake populated (Vector forwarded and enriched):**

```bash
sudo find /var/lib/lantana/datalake/bronze/ -type f
```

Expected on day one: `dataset=cowrie/date=YYYY-MM-DD/server=<hostname>/events.json` and equivalent paths for each active sensor. Vector writes `.json` (NDJSON codec), not `.ndjson`.

**Vector healthy (no pipeline errors):**

```bash
sudo journalctl -u vector --since "1 hour ago" | grep -i error | tail -10
```

**Pipeline dry-run (confirm enrichment runs without error):**

```bash
sudo -u nectar /opt/lantana/pipeline/venv/bin/lantana-enrich
```

On day zero there may be no "yesterday" bronze data yet — a clean exit with nothing to process is correct. The full enrichment run happens at 01:00 UTC via cron.

See `docs/validation.md` for the full day-by-day checklist.

---

## 10. Go Live

The operation is running. This step covers a recommended baseline snapshot and what to expect from the automated routines in the days ahead.

### Recommended: snapshot a baseline

Before significant attacker traffic accumulates, pull a clean baseline you can diff against later or restore from after an incident:

```bash
scripts/backup-vps.sh <host> <user> <key> <port> ./backups/<op_name>/baseline
```

This pulls `/etc/lantana`, `/var/log/lantana`, and `/var/lib/lantana` over SSH via streaming tar. Not strictly required, but strongly recommended before walking away.

### What happens next (automated routines)

The platform runs itself from here. Pipeline jobs are systemd `oneshot` services triggered by matching `.timer` units (not cron). Query via `journalctl -u <unit>.service` and inspect schedule via `systemctl list-timers`.

| Time (UTC) | Job | What it does |
|---|---|---|
| Continuous | Vector | Reads honeypot logs, enriches with GeoIP, writes bronze NDJSON |
| 00:15 daily | `lantana-prune` | Enforces 180-day retention; emergency prune at >80% disk |
| 01:00 daily | `lantana-enrich` | Bronze → silver: OCSF normalisation, redaction, Parquet |
| 04:00 daily | `lantana-transform` | Silver → gold: aggregated intelligence, STIX bundles |
| 05:00 daily | `lantana-alert` | Posts Discord alert on non-clean days (silent on clean) |
| 06:00 daily | `lantana-report` | Posts Discord daily intel brief regardless of clean state |
| 02:30 (1st of month) | `lantana-geoip-update` | Refreshes MaxMind City + ASN databases |

**Day one** — bronze accumulates from live traffic. Enrichment has nothing to process yet (it runs against yesterday's data).

**Day two morning** — first full pipeline cycle. By ~06:00 UTC the entire chain (prune → enrich → transform → alert → report) has run. Walk through [§11 Post-deploy first-cycle verification](#11-post-deploy-first-cycle-verification) below to confirm everything fired cleanly.

**Ongoing** — run the validation playbook periodically to confirm all services are healthy and the datalake is growing as expected:

```bash
ansible-playbook -i inventories/op_<name>/inventory.yml \
  tests/validate-single-node.yml -vvv
```

See `docs/validation.md` for the full day-by-day checklist.

---

## 11. Post-deploy first-cycle verification

Run after the first full pipeline cycle (i.e. after 06:00 UTC on the day following the deploy). All commands are read-only.

### Fast path — run the playbook

The 10 mechanically-verifiable checks below are encoded in `tests/validate-pipeline-cycle.yml`. From your workstation:

```bash
cd config/ansible
ansible-playbook -i inventories/op_<name>/inventory.yml tests/validate-pipeline-cycle.yml --ask-vault-pass
# Optional: override target_date (defaults to yesterday UTC)
#   -e target_date=2026-05-23
```

If every task is green, the pipeline cycled cleanly. If any assertion fails, the `fail_msg` names the failing invariant and points at the next diagnostic command — drop into the **Manual interpretation** section below to localise.

The Discord daily report content (check 13) is the one thing the playbook can't verify — it's a manual visual check (sections present, A/V/S/G column populated, composite-risk decomposition rendered).

Replace `<SN01>` with the sensor IP and `<PORT>` with the SSH admin port from `inventories/op_<name>/group_vars/all/main.yml`.

### What you're actually verifying

This is a 13-step walkthrough divided into two phases:

* **Immediate (checks 1–4)** — confirm the deploy *itself* completed correctly. Timers are scheduled, the legacy cron file is gone, Vector is ingesting, the datalake directory tree exists. You run these within minutes of `ansible-playbook` finishing; results are deterministic. A failure here means rerun the deploy.

* **Post first cycle (checks 5–13)** — confirm the pipeline *actually ran* and produced clean output. You can only run these after 06:00 UTC on day-2 because that's when the last scheduled job (`lantana-report`) fires. A failure here usually points at runtime state (provider quota exhausted, secrets misconfigured, etc.) — diagnose in place, don't redeploy.

The 13 checks map to the architectural pieces:

| Check | What it proves |
|---|---|
| 1 | Schedule itself is alive — five timers, next-fire times within 24h |
| 2 | The cron→systemd migration completed cleanly (no double-fire risk) |
| 3 | Vector source layer is ingesting; no startup errors |
| 4 | Filesystem layout matches what `lantana-prune` will operate on |
| 5 | Each pipeline job ran and exited 0 (the systemd contract; replaces the old `\| logger` pipe that masked exit codes) |
| 6 | `run_summary` structlog line appears for enrich + transform — the single-line per-run health signal added today (operators get the day's outcome in one event instead of grepping ~15) |
| 7 | Silver was written for all active datasets (cowrie + suricata + nftables) — confirms the bronze→silver path is functioning |
| 8 | All seven gold tables produced — confirms the silver→gold transform completed |
| 9 | `.provider_state.json` was created — confirms the new cross-run rate-limit memory is wired in. Empty `{}` on day-1 is fine; entries appear only after a provider trips its breaker |
| 10 | The Shodan API-key sanitiser is working — `enrichment_errors.json` must not contain `key=<actual-value>` substrings |
| 11 | Per-provider `<provider>_risk_score` columns landed in silver — verifies Phase D.1 (the new score helpers) are flowing through `_build_lookup` + `_merge_lookup` correctly |
| 12 | Gold `ip_reputation` has the composite + decomposition + RIOT invariant. The load-bearing operational check: if any IP shows `greynoise_riot=True`, its `greynoise_risk_score` must be `0.0` |
| 13 | The Discord report was actually sent (operator visual check). New format includes the `composite (enrichment+behavioral)/2` cell and the `A/V/S/G` per-provider column |

### How to read the outputs

**A clean day-2 morning looks like:**
- `systemctl list-timers` shows five `lantana-*.timer` entries
- `journalctl ... | grep run_summary` returns one JSON line per service with non-zero `silver_rows` and per-provider counters
- `find ... gold/ -name '*.parquet' | awk -F/ '{print $7}' | sort -u` returns exactly the seven expected table names
- The Discord report arrives at 06:00 UTC with all sections populated

**Common non-issues** (don't panic, don't roll back):
- GreyNoise columns missing or all-null in silver — the 50/week quota is tight; days where GN never returned a 200 are normal
- `enrichment_errors.json` has rate-limit entries for VT or Shodan — expected on busy days; the dual circuit-breaker design means these are *handled*, not failures
- `lantana-alert.service` shows `Result: success` but no Discord post — alerter is silent on clean days by design (it only posts on non-clean days)
- Day-1 silver/gold partitions don't exist yet — the pipeline runs against *yesterday's* bronze, so on day-1 morning there's no upstream data to process

**Real failures** (these need attention):
- Any timer missing from `list-timers` → Ansible deploy didn't complete; rerun
- `Result: failed` in `systemctl status` → check that service's journal for the exception
- Missing `run_summary` despite `Result: success` → unit ran but exited before completing (check for `dataset_processing_failed` in journal)
- `key=<long string>` in `enrichment_errors.json` → sanitiser regression; the test in `tests/test_enrichment/test_runner.py::TestSanitizeErrorMessage` should catch this locally first
- RIOT IP with non-zero `greynoise_risk_score` in gold → integration regression (`test_riot_signal_survives_bronze_to_gold` should fail locally; if not, the bug is downstream of provider)

### Immediate post-deploy (within minutes of `ansible-playbook` finishing)

```bash
# (1) Pipeline systemd timers active — five entries with next-fire timestamps.
ssh -p <PORT> lantana@<SN01> "sudo systemctl list-timers --all | grep lantana"
# Expect: lantana-prune.timer / -enrich / -transform / -alert / -report

# (2) No legacy cron file (the systemd-timer migration removed it).
ssh -p <PORT> lantana@<SN01> "sudo cat /etc/cron.d/lantana-pipeline 2>&1 | head"
# Expect: cat: ... : No such file or directory

# (3) Vector active and ingesting.
ssh -p <PORT> lantana@<SN01> "sudo systemctl is-active vector"
ssh -p <PORT> lantana@<SN01> "sudo journalctl -u vector --since '5 min ago' | grep -iE 'error|warn' | head"

# (4) Datalake skeleton present.
ssh -p <PORT> lantana@<SN01> "sudo find /var/lib/lantana/datalake -maxdepth 2 -type d | sort"
# Expect: bronze/, silver/, gold/ — empty until the first events arrive.
```

### After the first full cycle (≥ 06:00 UTC on day two)

```bash
# (5) Each systemd unit shows last-run success.
ssh -p <PORT> lantana@<SN01> "for u in lantana-prune lantana-enrich lantana-transform lantana-alert lantana-report; do
  echo == \$u ==; sudo systemctl status \$u.service --no-pager | head -10
done"
# Expect each: Loaded: loaded, ActiveState: inactive (dead), Result: success.

# (6) journalctl captures structlog run_summary for enrich + transform.
ssh -p <PORT> lantana@<SN01> "sudo journalctl -u lantana-enrich.service --since '01:00 UTC' | grep run_summary"
ssh -p <PORT> lantana@<SN01> "sudo journalctl -u lantana-transform.service --since '04:00 UTC' | grep run_summary"
# Expect: one structured line per service with silver_rows + provider stats.

# (7) Silver written for all active datasets.
ssh -p <PORT> lantana@<SN01> "sudo find /var/lib/lantana/datalake/silver -name '*.parquet'"

# (8) Gold present — all 7 tables.
ssh -p <PORT> lantana@<SN01> "sudo find /var/lib/lantana/datalake/gold -name '*.parquet' | awk -F/ '{print \$7}' | sort -u"
# Expect: behavioral_progression / behavioral_progression_multiday / campaign_clusters /
#         daily_summary / detection_findings / geographic_summary / ip_reputation

# (9) Provider state file created (shape: `{provider: {last_rate_limited: 'YYYY-MM-DD'}}`).
ssh -p <PORT> lantana@<SN01> "sudo cat /var/lib/lantana/datalake/.provider_state.json"
# Empty `{}` on day-1 is fine — no provider tripped its rate-limit breaker yet.

# (10) enrichment_errors.json contains no API-key residue (the URL sanitiser is working).
ssh -p <PORT> lantana@<SN01> "sudo grep -E 'key=[A-Za-z0-9]{20,}' /var/lib/lantana/datalake/enrichment_errors.json | head"
# Expect: NO output. Any match here is a sanitiser regression.

# (11) Silver carries the expected enrichment + per-provider risk_score columns.
ssh -p <PORT> lantana@<SN01> "sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c '
import polars as pl, glob
parquets = glob.glob(\"/var/lib/lantana/datalake/silver/dataset=cowrie/date=*/server=*/events.parquet\")
df = pl.read_parquet(sorted(parquets)[-1])
print({k: any(c.startswith(k) for c in df.columns) for k in [
    \"abuseipdb_\", \"shodan_\", \"vt_\", \"greynoise_\", \"geo.\",
    \"abuseipdb_risk_score\", \"virustotal_risk_score\",
    \"shodan_risk_score\", \"greynoise_risk_score\",
]})
'"
# On a fresh server, greynoise_ may be False (50/week quota is tight).
# The other raw fields and the four <provider>_risk_score columns should be True.

# (12) Gold ip_reputation: composite + per-provider sub-scores + RIOT short-circuit.
ssh -p <PORT> lantana@<SN01> "sudo -u nectar /opt/lantana/pipeline/venv/bin/python3 -c '
import polars as pl, glob
parquets = glob.glob(\"/var/lib/lantana/datalake/gold/ip_reputation/date=*/summary.parquet\")
df = pl.read_parquet(sorted(parquets)[-1])
top = df.sort(\"risk_score\", descending=True).head(5)
print(top.select([
    \"src_endpoint_ip\", \"risk_score\", \"enrichment_risk_score\", \"behavioral_risk_score\",
    \"abuseipdb_risk_score\", \"virustotal_risk_score\",
    \"shodan_risk_score\", \"greynoise_risk_score\",
    \"greynoise_riot\",
]))
'"
# Expect: risk_score ≈ (enrichment + behavioral) / 2 for each row.
# RIOT invariant: if any IP shows greynoise_riot=True, its greynoise_risk_score MUST be 0.0.
# See docs/risk-scoring.md for the full formula reference.

# (13) Discord report received at 06:00 UTC with:
#   - Geographic Origin section (top countries + ASNs from MaxMind)
#   - Top Attackers table — "Risk" cell shows `composite (enrichment+behavioral)/2`,
#     "A/V/S/G" column shows per-provider scores (`-` for offline providers)
#   - Threat Actor Attribution section (if any GN data this day)
#   - Detection Highlights section (if Suricata fired)
# Visual check; nothing to ssh.
```

### Acceptance gate

If checks 1–13 all return the expected output, the pipeline is healthy.

If any check fails, **don't roll back** — diagnose in place. Most likely failure modes:

- **(1) failed** — Ansible deploy didn't complete; rerun `--tags collector,pipeline`.
- **(5) `Result: failed`** — `journalctl -u <unit>` will name the failure.
- **(8) missing tables** — Transform died after silver. Look for `dataset_processing_failed` in `journalctl -u lantana-transform.service`.
- **(12) RIOT invariant violated** — A failure here means a refactor broke the GreyNoise short-circuit. Run `uv run pytest tests/test_integration_production_shape.py::test_riot_signal_survives_bronze_to_gold` locally to bisect.
- **(13) no report** — Either `secrets.discord_webhook` is unset (logs `no_discord_webhook`), or the webhook itself is rate-limited / mis-configured. `systemctl status lantana-report.service` and its journal will say.

### Inspect the dashboard + export STIX

The Streamlit dashboard is the operator's personal console — **never exposed externally** (OPSEC Layer 3). It binds to `localhost:8501` on the sensor. Reach it from your workstation via SSH local-port-forwarding:

```bash
# From your workstation: open an SSH tunnel and leave it running in a terminal.
ssh -p <PORT> -L 8501:localhost:8501 lantana@<SN01>

# On the sensor (inside the SSH session above OR in a separate one):
sudo -u nectar XDG_CACHE_HOME=/tmp /opt/lantana/pipeline/venv/bin/lantana-dashboard
```

Then on your workstation, open <http://localhost:8501>. Pages to walk:

| Page | What to verify |
|---|---|
| **Overview** | Metric cards populated (events, IPs, auth attempts, commands, findings); top-N tables for IPs/usernames/passwords |
| **Geography** | World map with attacker origins; top countries + ASNs match what's in the Discord report |
| **IP Reputation** | High/Medium/Low risk metric cards; three side-by-side distribution charts (composite, enrichment, behavioral); per-provider risk_score columns (`abuseipdb_risk_score` etc.) in the IP table |
| **Behavioral Progression** | Escalation funnel; stage scatter; automated-vs-manual breakdown; multi-day slow-burn section |
| **Detection Findings** | Top Suricata rules; IPs per rule |
| **Credentials** | Campaign cluster table (shared user:password pairs ≥ 2 IPs) |
| **STIX Export** | Bundle preview metrics → **Generate STIX 2.1 Bundle** button → **Download** button |

**Exporting a STIX bundle** (for sharing with peers):

1. STIX Export page → pick the target date from the sidebar
2. Click **Generate STIX 2.1 Bundle** → page shows `Bundle generated: N objects`
3. Click **Download STIX Bundle (.json)** — file saves to your workstation as `lantana-stix-<YYYY-MM-DD>.json`
4. Inspect locally before sharing:
   ```bash
   jq '.objects[] | {type, id, labels}' lantana-stix-2026-05-23.json | head -40
   # Sanity-check: no internal IPs in any indicator pattern
   jq '.objects[] | select(.type=="indicator") | .pattern' lantana-stix-2026-05-23.json | grep -E '10\.|192\.168\.|fd99:' || echo "OK: no internal IPs"
   ```

Bundles are **not stored server-side** — they're generated on-demand from gold tables and streamed to your browser. Re-generate any historic date by changing the sidebar date picker.

---

## Tearing Down or Rotating

Two common follow-ups:

- **Rotate the narrative on the same host.** Edit `narrative.yml`, then re-run `deploy_single.yml` (add `--diff --check` first for a dry-run preview of the rendered banners, MOTD, and certs). The infrastructure is untouched; only the deception layer changes.
- **Destroy and rebuild.** If using Terraform: `terraform destroy` in `infra/terraform/environments/proxmox/`. If manually provisioned: just wipe the VM. Ansible state is captured entirely by the inventory, so a fresh provision + re-deploy reproduces the operation bit-for-bit.

---

## Quick Reference

| Step | Command |
|---|---|
| Bootstrap SSH | `scripts/bootstrap-ssh.sh <host> <user> <key> <port>` |
| Clone op | `cp -r inventories/op_single inventories/op_<name>` |
| Create vault | `cp inventories/op_single/group_vars/all/vault.yml.example inventories/op_<name>/group_vars/all/vault.yml` then edit, then `ansible-vault encrypt` |
| Scaffold narrative | invoke the `scaffold-narrative` skill with a one-sentence archetype |
| Deploy base | `ansible-playbook -i inventories/op_<name>/inventory.yml playbooks/deploy_single.yml --ask-vault-pass` |
| Validate base | `ansible-playbook -i inventories/op_<name>/inventory.yml tests/validate-single-node.yml -vvv` |
| Deploy honeypots | `ansible-playbook -i inventories/op_<name>/inventory.yml playbooks/deploy_honeypots.yml --ask-vault-pass` |
| Validate pipeline cycle | `ansible-playbook -i inventories/op_<name>/inventory.yml tests/validate-pipeline-cycle.yml --ask-vault-pass` |
| Dashboard tunnel | `ssh -p <PORT> -L 8501:localhost:8501 lantana@<SN01>` → on sensor: `sudo -u nectar XDG_CACHE_HOME=/tmp /opt/lantana/pipeline/venv/bin/lantana-dashboard` → browse to <http://localhost:8501> |
| Export STIX bundle | Dashboard → STIX Export page → pick date → **Generate** → **Download** (`.json`) |
| Baseline snapshot | `scripts/backup-vps.sh <host> <user> <key> <port> ./backups/<op_name>/baseline` |

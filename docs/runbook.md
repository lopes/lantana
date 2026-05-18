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

---

## 0. Prerequisites

- A Debian-family VPS or VM with public IPv4 (IPv6 optional but recommended).
- SSH access as a sudo-capable user (cloud images typically ship one: `debian`, `ubuntu`, `admin`, ...).
- An SSH key pair on your workstation (`~/.ssh/id_ed25519` and `.pub`).
- Local checkout of this repo.
- `ansible-core` and `ansible-vault` installed locally.

---

## 1. Prepare the Server

Bootstrap the `lantana` admin user, install your pubkey, and harden `sshd` onto a custom port. This script handles all of it.

```bash
scripts/bootstrap-ssh.sh <host> <initial_ssh_user> <ssh_key> <ssh_port>

# Example: fresh OVH/SoYouStart box where the cloud image gives you `debian`
scripts/bootstrap-ssh.sh 149.56.130.97 debian ~/.ssh/id_ed25519 60090
```

The script will:

- Create the `lantana` admin user with passwordless sudo.
- Inject your public key into `lantana@host:~/.ssh/authorized_keys`.
- Write `/etc/ssh/sshd_config.d/00-lantana.conf` (key-only, custom port).
- Comment out any explicit `Port 22` in the main config and disable `ssh.socket` (Debian 13 trap).
- Restart `ssh.service`.

Verify before moving on:

```bash
ssh -p 60090 -i ~/.ssh/id_ed25519 lantana@<host> 'sudo -n true && echo ok'
```

---

## 2. Gather Server Facts

On the prepared server, collect the values you'll plug into the inventory.

```bash
ssh -p 60090 -i ~/.ssh/id_ed25519 lantana@<host>

# WAN interface and addressing
ip -br link                       # interface name (eno1, ens3, enp2s0, ...)
ip -br addr show dev <iface>      # IPv4 + IPv6, with netmask
ip -6 route show default          # confirm IPv6 default route if dual-stack
```

Write down:

- WAN interface name (e.g. `eno1`)
- IPv4 with prefix (e.g. `149.56.130.97/24`)
- IPv6 with prefix (e.g. `2607:5300:201:3100::1234/64`) — or note that IPv6 is unavailable.

---

## 3. Clone an Existing Operation

Each operation is a self-contained Ansible inventory under `config/ansible/inventories/op_*`. `op_single` is the canonical starting point for single-node deployments.

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

## 4. Configure Inventory and Network

### `inventory.yml`

Set `ansible_host` to the server's public IP.

```yaml
all:
  children:
    single_nodes:
      hosts:
        sn-01:
          ansible_host: 149.56.130.97
          lantana_profile: "single_node_sensor"
          sensor_honeypots:
            - cowrie
            # - dionaea     # uncomment to deploy
```

### `group_vars/all/main.yml`

Confirm SSH user, port, and key path match what `bootstrap-ssh.sh` configured. Defaults work for the standard flow:

```yaml
ansible_user: "lantana"
ansible_port: "60090"
ansible_private_key_file: "~/.ssh/id_ed25519"
```

### `group_vars/all/network.yml`

Set the WAN block to the values from step 2.

```yaml
network:
  honeywall:
    wan:
      interface: "eno1"                       # from `ip -br link`
      ipv4: "149.56.130.97/24"                # public IPv4 + netmask
      ipv6: "2607:5300:201:3100::1234/64"     # public IPv6 or remove the key
```

> [!WARNING]
> A wrong WAN interface name is the most common first-run failure. The firewall role binds rules to it. Double-check against `ip -br link` on the server.

Leave the internal `lan`, `collectors`, and `sensors` blocks alone — they reference the dummy interface and never touch the public network.

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

# Optional — public endpoints exist (see auth modes below)
vault_apikey_greynoise:  ""
vault_apikey_phishstats: ""

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
| `phishstats` | provider skipped (`provider_disabled` log) | public endpoint, no auth | public endpoint, key value silently ignored |
| `maxmind` | MMDB download skipped at deploy — Vector emits no `.geo.*` fields | same as missing | MMDBs downloaded + refreshed monthly |
| `discord_webhook` | reports generated locally only | same | webhook delivers daily brief |

So the only way to disable GreyNoise or PhishStats is to **omit the line entirely** — empty string keeps them enabled in unauthenticated mode.

### References

- GreyNoise Community API: https://docs.greynoise.io/docs/using-the-greynoise-community-api (50 searches per 7 days)
- PhishStats public API: https://phishstats.info/api-docs (20 requests per minute)
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

1. **Decide the archetype** (one sentence): sector + geography + hosting story + admin skill level. Example: *"Brazilian fintech, Canada VPS, old Ubuntu, vibe-coded by an unskilled IT contractor."*
2. **Run the `scaffold-narrative` skill** with that sentence as input. It produces a complete `narrative.yml` consistent with the archetype, plus notes on which fields to review.
3. **Review the output** against the schema below. Check the era / OS / service alignment by hand even when the skill gets it right — this is the file most worth understanding.
4. **Paste into** `inventories/op_<name>/group_vars/all/narrative.yml`.

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

## 7. Deploy

From `config/ansible/`:

```bash
# Base platform: users, firewall, Vector, Suricata, dummy interface
ansible-playbook -i inventories/op_<name>/inventory.yml \
  playbooks/deploy_single.yml --ask-vault-pass --ask-become-pass

# Honeypots: rolls out roles listed in sensor_honeypots
ansible-playbook -i inventories/op_<name>/inventory.yml \
  playbooks/deploy_honeypots.yml --ask-vault-pass --ask-become-pass
```

Drop `--ask-become-pass` if `vault_become_password` is set in the vault.

For multi-node, swap `deploy_single.yml` for `deploy_multi.yml` and use the corresponding inventory.

---

## 8. Validate

Run the validation playbook and the manual checks in `docs/validation.md`:

```bash
ansible-playbook -i inventories/op_<name>/inventory.yml \
  tests/validate-single-node.yml -vvv
```

Then verify on the host:

- `id stigma` (UID 2001) and `id nectar` (UID 2002) exist.
- `systemctl --user status cowrie` (as `stigma`) is active.
- `sudo nft list ruleset | grep lantana_nat` shows DNAT rules for the published ports.
- The MOTD on login shows the operation name and persona hostname.
- `cat /etc/lantana/sensor/cowrie/cowrie.cfg | head -5` reflects the narrative.

External smoke test from your workstation:

```bash
nmap -sV -Pn -p 22,23,80,445,3306,1433 <host>     # banners should match narrative
ssh root@<host>                                    # should land in cowrie's shell
```

See `docs/validation.md` for the full day-by-day checklist (honeypots, telemetry, enrichment, dashboard).

---

## 9. Backup Baseline

Before letting the box receive attacker traffic, snapshot a clean baseline so you can diff later or restore after an incident.

```bash
scripts/backup-vps.sh <host> lantana ~/.ssh/id_ed25519 60090 ./backups/<op_name>/baseline
```

This pulls `/etc/lantana`, `/var/log/lantana`, and `/var/lib/lantana` over SSH via streaming tar.

---

## Tearing Down or Rotating

Two common follow-ups:

- **Rotate the narrative on the same host.** Edit `narrative.yml`, re-run `deploy_single.yml`. The infrastructure is untouched; only the deception layer changes.
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
| Deploy honeypots | `ansible-playbook -i inventories/op_<name>/inventory.yml playbooks/deploy_honeypots.yml --ask-vault-pass` |
| Validate | `ansible-playbook -i inventories/op_<name>/inventory.yml tests/validate-single-node.yml -vvv` |
| Backup | `scripts/backup-vps.sh <host> lantana <key> <port> ./backups/<op_name>/baseline` |

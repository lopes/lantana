# Lantana

<p align="center">
  <img src="assets/lantana-logo.svg" alt="Lantana" width="160">
</p>

Lantana is a honeypot-as-code platform that deploys and operates IPv4/IPv6 dual-stack honeypots aligned with [MITRE Engage](https://engage.mitre.org/) principles. It treats honeypots as operational infrastructure — continuously rotated, reshaped, and adapted to evolving narratives and intelligence goals.

The platform covers the full lifecycle: from controlled exposure to structured data ingestion, enrichment, analysis, and intelligence output (STIX bundles, Discord reports, Streamlit dashboard). It emphasizes disposability, policy-driven deployment, and strict blast-radius containment.

> [!tip]
> [Lantana camara](https://en.wikipedia.org/wiki/Lantana_camara) is a plant that attracts insects with its colorful flowers — much like a honeypot attracts attackers with its deliberately vulnerable services. It's invasive, resilient, and thrives in hostile environments.

---

## Quick Start

### 1. Clone and provision

```bash
git clone https://github.com/lopes/lantana.git
cd lantana
```

Provision a [Debian 13](https://www.debian.org/) host (VM or bare metal). Terraform support for Proxmox is available under `infra/terraform/environments/proxmox/`.

### 2. Create an operation

```bash
cd config/ansible
cp -r inventories/op_single inventories/op_myop
```

Customize `inventory.yml`, `main.yml`, `network.yml`, `narrative.yml`, and `reporting.yml` under `inventories/op_myop/group_vars/all/`. See the [setup guide](docs/setup.md) for an annotated walkthrough of each file. Create the encrypted vault:

```bash
ansible-vault create inventories/op_myop/group_vars/all/vault.yml
```

### 3. Deploy

```bash
ansible-playbook -i inventories/op_myop/inventory.yml playbooks/deploy_single.yml --ask-vault-pass
ansible-playbook -i inventories/op_myop/inventory.yml playbooks/deploy_honeypots.yml --ask-vault-pass
```

### 4. Validate

```bash
ansible-playbook -i inventories/op_myop/inventory.yml tests/validate-single-node.yml -vvv --ask-vault-pass
```

---

## Rules of Engagement

Lantana is designed to operate safely in hostile environments and assumes that sensor hosts will eventually be compromised. To ensure ethical, legal, and operational safety, the platform enforces these rules at both architectural and operational levels:

1. **No offensive use.** Honeypots must never be used as offensive infrastructure. The honeywall zone enforces outbound restrictions by default — compromised hosts cannot scan, attack, or otherwise harm third parties. Egress allowances must be explicit and narrowly scoped.
2. **Assume disposability.** No secrets, credentials, production access, or sensitive systems on sensor hosts. Any compromise is total. Rebuilds are routine, not exceptional.
3. **No entrapment.** Honeypots must not target specific individuals or organizations without explicit legal authorization. Lantana is broad-spectrum research, not targeted intelligence collection.
4. **Respect privacy.** Captured data must be handled, stored, and processed according to applicable policies, regulations, and ethical standards.
5. **Align with operational goals.** Narratives, exposure profiles, and sensor configurations must answer specific questions. Sensor rotation and topology shifts are part of the lifecycle, not ad hoc events.
6. **No infrastructure disclosure.** Real operator-identifying values (WAN IPs, hostnames, domains, ASNs, SSH host fingerprints) must never appear in any artifact leaving the operator's control — that includes Discord reports, STIX bundles, this repository, commits, talks, screenshots. Real values live only inside each operation's untracked or vault-encrypted inventory. Examples in tracked files use RFC 5737 / 3849 / 2606 / 5398 documentation ranges.

---

## Project Structure

```
lantana/
  config/ansible/     # Ansible roles, playbooks, inventories, validation playbooks
  infra/terraform/    # Terraform host provisioning (Proxmox)
  pipeline/           # Python data pipeline (enrichment, OCSF, dashboard, reports, STIX)
  scripts/            # Operational scripts (bootstrap, backup, probes, dashboard)
  docs/               # Full documentation
```

---

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/architecture.md) | Zoned model, deployment modes, network topology, tech stack |
| [Setup Guide](docs/setup.md) | First-deploy walkthrough: prepare server, clone an operation, vault, narrative, deploy honeypots |
| [Pipeline](docs/pipeline.md) | Data pipeline: bronze/silver/gold datalake, OCSF normalization, enrichment, reports, STIX |
| [Integrations](docs/integrations.md) | Third-party threat-intel providers: endpoints, auth, rate limits, field extraction, live-probe workflow |
| [Validation](docs/validation.md) | Post-deploy verification: protocol smoke tests + day-by-day pipeline/report/dashboard checks |
| [Risk Scoring](docs/risk-scoring.md) | Composite + per-provider risk score formula, RIOT short-circuit, decomposition |
| [Honeypots](docs/honeypots.md) | Cowrie + Dionaea: per-honeypot config model, capability allowlist, persona drift notes |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and fixes (Dionaea startup, nftables, Vector pipeline) |
| [Glossary](docs/glossary.md) | Terminology and definitions |

---

## Design Decisions

Lantana intentionally avoids Kubernetes (honeypots are disposable, not HA), SIEM-first architectures (research honeypot data benefits from batch analytics over real-time alerting), and monolithic stacks like T-Pot (Lantana is composable — infrastructure, policy, sensors, and narratives evolve independently).

For the full rationale, see [docs/architecture.md](docs/architecture.md).

---

## Roadmap

Tracked work for post-v1.0.0 — a mix of known gaps deliberately deferred from the v1 cut and planned improvements that would expand Lantana's analytical reach. Boxes get checked as items land.

- [ ] **Dionaea download URL → pipeline.** The `store` ihandler captures attacker-delivered binaries to `/var/lib/lantana/sensor/dionaea/binaries/`, but URL + hash metadata stays inside dionaea's incident bus and never reaches `dionaea.json`. Surfacing the URL into bronze → silver → brief → STIX needs a small custom ihandler that subscribes to `dionaea.download.complete.unique` and writes the URL + MD5 + connection metadata to a JSON stream Vector can tail.
- [ ] **Dionaea MSSQL/MySQL command bodies → pipeline.** Same upstream constraint. The bundled `log_json` ihandler emits only connection lifecycle + credentials for these services; surfacing command bodies requires a custom ihandler or switching to `log_sqlite` + a tail job.
- [ ] **SHA-256 hash integration for dionaea binaries.** Dionaea names captured files by MD5 (and re-emits SHA-512 via the `store` ihandler), but the IOC pipeline (`file_hash_sha256` column, STIX file indicators, VirusTotal lookup) assumes SHA-256. Either add a `file_hash_sha512` column with downstream fallback handling, or hash files on disk after a `lantana-grant-read` cron grants `nectar` access to `/var/lib/lantana/sensor/dionaea/binaries/` (parallel to Cowrie's at `roles/cowrie/tasks/main.yml`).
- [ ] **Dionaea restart breaks log_json.** The Quadlet's `:U` flag re-chowns `/var/log/lantana/sensor/dionaea` to container-root on every container start, but the dionaea worker drops to UID 999 (host UID 100999) before writing logs. Initial start works because the file descriptor is acquired before the privilege drop; subsequent restarts cannot reopen the existing stigma-owned file. Fix is to drop `:U` from the log + data volume mounts in `dionaea.container.j2` and add an explicit `chown 100999:100999` step in `roles/dionaea/tasks/main.yml`. Operationally invisible on fresh deploys; surfaces only when an operator bounces the container.
- [ ] **Dashboard date-range selector.** The Streamlit dashboard currently renders a fixed window from the gold tables. Adding `start` + `end` date pickers (defaulting to the last 7 days) and threading them through the Polars filters on every page would let analysts scope visualizations to specific incidents, persona-rotation windows, or comparative periods without code edits. Major analytical power-up for a small UI change.

---

## License

This project is licensed under the [MIT License](LICENSE).

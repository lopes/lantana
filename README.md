# Lantana

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

Provision a [Debian 13](https://www.debian.org/) host (VM or bare metal). Terraform support for VMware/vSphere is available under `infra/terraform/`.

### 2. Create an operation

```bash
cd config/ansible
cp -r inventories/op_single inventories/op_myop
```

Customize `inventory.yml`, `main.yml`, `network.yml`, `narrative.yml`, and `reporting.yml` under `inventories/op_myop/group_vars/all/`. Create the encrypted vault:

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
ansible-playbook -i inventories/op_myop/inventory.yml tests/validate-single-node.yml -vvv
```

---

## Project Structure

```
lantana/
  config/ansible/     # Ansible roles, playbooks, inventories
  infra/terraform/    # Terraform host provisioning
  pipeline/           # Python data pipeline (enrichment, OCSF, dashboard, reports, STIX)
  scripts/            # Operational scripts (VPS data fetch, injection, dashboard)
  docs/               # Full documentation
```

---

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/architecture.md) | Zoned model, deployment modes, network topology, tech stack |
| [Pipeline](docs/pipeline.md) | Data pipeline: bronze/silver/gold datalake, OCSF normalization, enrichment, reports, STIX |
| [Rules of Engagement](docs/rules-of-engagement.md) | Ethical and operational boundaries for honeypot use |
| [Glossary](docs/glossary.md) | Terminology and definitions |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and fixes |

---

## Design Decisions

Lantana intentionally avoids Kubernetes (honeypots are disposable, not HA), SIEM-first architectures (research honeypot data benefits from batch analytics over real-time alerting), and monolithic stacks like T-Pot (Lantana is composable — infrastructure, policy, sensors, and narratives evolve independently).

For the full rationale, see [docs/architecture.md](docs/architecture.md).

---

## License

This project is licensed under the [MIT License](LICENSE).

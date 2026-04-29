# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Lantana is a honeypot-as-code platform built on Ansible that deploys and operates IPv4/IPv6 dual-stack honeypots aligned with MITRE Engage principles. It supports single-node (all-in-one) and multi-node (distributed) deployment models using a zoned architecture (Honeywall, Sensor, Collector).

## Deployment Commands

All commands run from `config/ansible/`.

**Single-node deployment:**

```bash
ansible-playbook -i inventories/op_single/inventory.yml playbooks/deploy_single.yml --ask-vault-pass
```

**Multi-node deployment:**

```bash
ansible-playbook -i inventories/op_multi/inventory.yml playbooks/deploy_multi.yml --ask-vault-pass
```

**Deploy honeypots (after base deployment):**

```bash
ansible-playbook -i inventories/<operation>/inventory.yml playbooks/deploy_honeypots.yml
```

**Validate single-node deployment:**

```bash
ansible-playbook -i inventories/op_single/inventory.yml tests/validate-single-node.yml -vvv
```

## Architecture

### Zoned Model

- **Honeywall Zone**: Network control, nftables firewalling, Suricata IDS, egress containment. Never hosts honeypots.
- **Sensor Zone**: Runs honeypots in rootless Podman containers (low-interaction) or as full VMs (high-interaction, multi-node only). Managed by `stigma` user (UID 2001).
- **Collector Zone**: Data ingestion, OCSF normalization, Parquet storage, enrichment via external APIs. Managed by `nectar` user (UID 2002).

In single-node mode, all zones coexist on one host with a dummy interface (`ltn0`) simulating the private network. In multi-node mode, zones run on separate hosts with the honeywall as SSH bastion.

### Operation-as-Inventory

Each deployment is an Ansible inventory under `config/ansible/inventories/op_*`. Clone `op_single` or `op_multi` to create new operations. Each operation has its own `group_vars/all/` with:

- `main.yml` - platform mode, system users, connection settings
- `network.yml` - IP addressing, interface assignments
- `narrative.yml` - deception story, fake host profiles, service versions
- `vault.yml` - encrypted API keys (VirusTotal, AbuseIPDB, GreyNoise, Shodan, PhishStats, Discord)

### Role Hierarchy

- **Atomic roles** do one thing: `base`, `cowrie`, `dionaea`, `suricata`, `firewall`, `network`
- **Composite roles** (`profile_*`) group atomic roles into zone archetypes via meta-dependencies: `profile_honeywall`, `profile_collector`, `profile_sensor_low`
- **Playbooks** select a "Plate" (e.g., `deploy_single.yml`) then add "Toppings" (honeypots via `deploy_honeypots.yml`)

### Honeypots as Plugins

Each honeypot role self-registers by dropping files into three locations:

- Config: `/etc/lantana/sensor/`
- Telemetry: `/etc/vector/conf.d/`
- Firewall rules: `/etc/lantana/honeywall/nftables/sensors/` (auto-included by nftables on reload)

### Network Addressing

- IPv4: `10.50.99.0/24` | IPv6 ULA: `fd99:10:50:99::/64`
- Collector: `.10` | Sensor: `.100` | Honeywall gateway (multi-node): `.1`
- Custom SSH admin port: 60090, certificate-based auth, user `lantana`

### Telemetry Pipeline

Datadog Vector runs across all zones. Logs centralize in `/var/log/lantana/{honeywall,sensor,collector}`. Log rotation is managed via `/etc/cron.d/lantana-logs` triggering configs in `/etc/lantana/logrotate.d/`.

## Project Structure

```
lantana/
  config/ansible/     # Host configuration (Ansible roles, playbooks, inventories)
  infra/terraform/    # Infrastructure provisioning (Proxmox VMs)
  pipeline/           # Data processing pipeline (Python: enrichment, analysis, dashboard)
  scripts/            # Operational scripts (VPS data fetch, injection, dashboard, malware quarantine)
  docs/               # Project documentation
```

## Key Conventions

- Target OS is Debian 13 exclusively
- Ansible config lives at `config/ansible/ansible.cfg` (roles_path, collections_path, pipelining enabled)
- Jinja2 templates (`.j2`) generate nftables rules, Vector pipelines, Cowrie configs, and SSH settings
- Sensors run as rootless Podman containers under `stigma` using Quadlet `.container` files managed by user-scoped systemd
- Firewall rules use `inet` family (dual-stack) in nftables; avoid `ip`-only matches when IPv6 is needed
- `sensor_honeypots` list variable in inventory controls which honeypot roles are dynamically included
- Single-node is the primary deployment model; multi-node exists as an architectural design principle for zone separation

## Python Code Standards (pipeline/)

- **Python 3.13+** (Debian 13 native)
- **Pylance strict mode**: all types declared, no `Any` escape hatches, full type annotations on all function signatures and return types
- **TDD**: write tests first, then implement. Every module has a corresponding test file mirroring the `src/` structure
- **Functional programming style**: pure functions for data transforms, Pydantic models for structured data, push IO to the edges. Prefer Polars expression chains over imperative loops. Minimize side effects.
- **Boring, reliable tooling only**: Polars, httpx, Pydantic, tenacity, structlog, stix2, Streamlit, Plotly. No exotic or trendy dependencies.
- **Linting/formatting**: `ruff` for linting + formatting, `mypy` strict for type checking, `pytest` for tests
- **Package manager**: `uv`

## Shell Script Standards

- Plain POSIX-compatible patterns, standard coreutils only
- No exotic tools or fancy constructs
- Readable and auditable

## OPSEC Requirements

Lantana produces shareable intelligence (Discord reports, STIX bundles). The primary OPSEC concern is **external/WAN IP leakage** — the public-facing addresses that identify the honeypot on the internet. If an attacker or peer discovers these, they can blacklist the honeypot, fingerprint the setup, or map the operator's infrastructure. Only the honeypot owner should know these addresses. OPSEC is enforced at every layer:

### Layer 1: Vector telemetry (noise suppression)

- Every honeypot Vector pipeline must include a `filter_<honeypot>` transform that drops events from non-attacker source IPs before forwarding to the collector
- Dropped sources: loopback (`127.0.0.0/8`, `::1`), internal network prefixes (`network.prefixes.ipv4`, `network.prefixes.ipv6`)
- This catches health check probes, inter-zone traffic, and operational noise at the earliest possible point
- Pattern: use VRL `ip_cidr_contains!()` against the operation's network prefixes from inventory
- **Every new honeypot role must replicate this filter** — see `cowrie.vector.yaml.j2` as the reference

### Layer 2: Silver datalake (pseudonymization)

- During bronze-to-silver enrichment, all operation-related IPs are replaced with pseudonyms (e.g., `honeypot-sensor-01`)
- **External/WAN IPs are the primary redaction target** — these are the public addresses in `network.honeywall.wan.ipv4/ipv6` that appear as destination IPs in attacker events
- Internal IPs (`network.prefixes.*`, sensor/collector addresses) are also redacted for defense in depth
- Controlled by `reporting.yml` → `redact.infrastructure_ips` and `redact.pseudonym_map`
- Validation assertion: zero operation-related IPs (external or internal) in output Parquet before writing

### Layer 3: Gold / Reports / STIX (complete absence)

- Gold aggregation reads only from silver (already redacted)
- STIX bundles assert no operation-related addresses in any indicator object
- Discord reports generated exclusively from gold data
- Reports never contain: honeypot WAN IPs, internal IPs, server hostnames, network topology, SSH admin port, interface names, CIDRs

## Datalake Architecture

- Per-instance singleton. Multiple operations coexist via `operation` column tag (not filesystem partition)
- Partition scheme (Hive-style): `dataset={name}/date={YYYY-MM-DD}/server={hostname}/`
- Bronze = raw NDJSON (Vector writes). Silver = enriched Parquet (OCSF, redacted). Gold = correlated intelligence (Parquet)
- Cross-honeypot correlation happens ONLY at the gold layer
- GeoIP enrichment happens in Vector (MMDB), API enrichment happens in Python (daily batch)

# Lantana
Lantana is a honeypot-as-code platform designed to deploy and operate IPv4/IPv6 dual-stack honeypots in a scalable, reproducible, and security-conscious way. It treats honeypots not as static traps but as **operational infrastructure**, aligned with [MITRE Engage](https://engage.mitre.org/) principles, where deception assets are continuously rotated, reshaped, and adapted to evolving narratives and intelligence goals.

Rather than focusing only on collecting raw telemetry, Lantana is built to support **end-to-end intelligence generation**: from controlled exposure, to structured data ingestion, to enrichment, storage, and downstream analysis. The platform emphasizes disposability, policy-driven deployment, and strict blast-radius containment, making it suitable for both research and production-facing environments.

Lantana supports both **single-host** deployments (for lightweight or edge use cases) and fully distributed **multi-host** topologies (for production, research, or high-interaction operations), while preserving the same logical architecture and operational model across both.

---

## Zones
Lantana is structured around a **zoned architecture**, where each zone represents a security and functional boundary rather than just a deployment role. Zones can coexist on the same host (single-host mode) or be deployed on separate hosts or VMs (multi-host mode), but their responsibilities and trust boundaries remain consistent across both models.

### Honeywall Zone
The honeywall zone is responsible for **network-level control, containment, and observability**. It enforces egress filtering, traffic logging, and segmentation policies to ensure compromised sensors cannot be weaponized or used as pivot points into other networks. This zone uses Linux networking primitives and nftables to implement filtering, routing, and logging in a transparent and auditable way. It also implements an Intrusion Detection System (**IDS**) to identify known attack signatures, providing another layer of detection.

In single-host deployments, the honeywall zone coexists with the sensor runtime and applies policy locally to container traffic through nftables and routing rules. In multi-host deployments, it becomes a dedicated gateway sitting between sensors and upstream networks, acting as both a choke point and an enforcement boundary. Logically, there is always exactly one honeywall zone per deployment, even if its physical realization varies.

The honeywall zone does not run honeypots and is not intended to be directly exposed to adversaries; its sole purpose is containment, visibility, and enforcement.

### Sensor Zone
The sensor zone is the core of the platform and hosts the actual honeypot workloads. It is intentionally designed to support two fundamentally different sensor classes under the same control plane.

#### Low-interaction sensors
Low-interaction sensors are implemented as hardened containerized services running known honeypot frameworks such as [Cowrie](https://www.cowrie.org/), [Dionaea](https://dionaea.readthedocs.io/en/latest/), [Honeyd](https://www.honeyd.org/), or [OpenCanary](https://opencanary.readthedocs.io/en/latest/). Docker provides process isolation, filesystem isolation, and network namespace separation, while Lantana applies additional hardening: no privileged mode, no host mounts, no Docker socket access, seccomp and capability drops, and restricted egress paths enforced by the honeywall zone.

Because these sensors are containerized, a single host can safely run multiple honeypots in parallel, each isolated into its own runtime environment. This model is supported both in single-host and multi-host deployments.

#### High-interaction sensors
High-interaction sensors are full operating systems or application stacks intentionally deployed in vulnerable configurations and directly exposed to adversaries. These hosts are expected to be compromised and must be treated as disposable. They do not run container runtimes or cohost other honeypots, and they are never colocated with low-interaction sensors or security services.

High-interaction sensors are only supported in multi-host deployments and are isolated through network topology and policy enforcement at the honeywall zone boundary rather than through local containment mechanisms.

In both models, sensors are ephemeral. They are rotated, rebuilt, and reprofiled regularly based on operational goals, compromise state, or narrative shifts.

### Collector Zone
Every zone generates telemetry. The honeywall zone emits network-level connection and IDS logs. The sensor zone emits honeypot application logs (for low-interaction systems) and OS/application telemetry (for high-interaction systems). While each zone performs lightweight normalization and enrichment locally, **all telemetry converges into the collector zone**, which acts as the central processing, enrichment, and archival pipeline.

Logs are normalized into [OCSF](https://github.com/ocsf) format and stored in [Parquet](https://parquet.apache.org/) to support large-scale analytical workflows. Data flows through a staging pipeline and is periodically enriched using both internal and external intelligence sources such as [VirusTotal](https://www.virustotal.com/), [AbuseIPDB](https://www.abuseipdb.com/), [GreyNoise](https://www.greynoise.io/), [Shodan](http://shodan.io/), and [PhishStats](https://phishstats.info/). Once enrichment completes, data is promoted into a production data lake and optionally synchronized to cloud storage for redundancy and long-term retention.

The collector zone also hosts notebooks, analysis pipelines, and downstream tooling used to transform raw telemetry into actionable intelligence. It is explicitly out of band from sensor execution paths and does not expose attack surface to adversaries.

---

## Deployment Models
Lantana supports multiple deployment models without changing its logical architecture. The same zone abstractions, policies, and workflows apply regardless of where components physically run.

### Single-node mode
In single-host mode, the honeywall, sensor, and collector zones coexist on the same machine. This mode is intended for lightweight deployments, edge sensors, labs, and environments where operational simplicity or cost constraints dominate.

Only **low-interaction sensors** are supported in this mode. Honeypots run inside hardened Docker containers, and containment is enforced through container isolation and nftables-based egress control applied by the honeywall zone. While this model does not provide hardware isolation between zones, it preserves policy boundaries and observability semantics and is considered acceptable for low-interaction deception workloads.

This mode optimizes for ease of deployment, minimal infrastructure footprint, and fast iteration.

### Multi-node mode
In multi-host mode, zones are deployed on separate hosts or VMs, creating strong isolation boundaries enforced at the network layer. The honeywall zone becomes a dedicated gateway between sensor networks and upstream connectivity. Sensor hosts contain either low-interaction honeypots (containerized) or high-interaction honeypots (entire systems intentionally exposed). The collector zone runs independently and never exposes services to adversaries.

This model supports:

- High-interaction honeypots
- Strong containment guarantees
- Lateral movement detection and research
- Forensic-grade telemetry capture

Multi-host mode is the default for production, research, and adversary emulation environments.

### Hybrid and edge deployments
Lantana also supports hybrid models, where:

- Edge locations run single-host low-interaction sensors
- Core infrastructure runs centralized honeywall and collector zones
- Telemetry is archived upstream for unified analysis

This model enables geographically distributed sensing with centralized analysis and governance.

---

## Operations
Lantana operationalizes the **MITRE Engage** framework by treating deception not as a static trap, but as a series of coordinated **Operations**. In this model, we move away from "set and forget" deployments. An operation represents a specific intelligence goal or a target adversary persona. Because deception is a cat-and-mouse game, Lantana enables the simultaneous management of multiple operations, each isolated within its own logical boundary.

To facilitate this, Lantana treats each operation as a unique **Ansible Inventory**. This "Operation-as-Inventory" approach allows the security team to define a bespoke **Narrative**—the specific story, vulnerability profile, and behavioral traits—for a specific set of hosts without affecting other ongoing activities. This ensures that while the underlying "Menu" of technical capabilities (roles) is shared, the "Order" (the specific deployment) remains strictly tailored to the adversary we intend to engage.

---

## Ansible and Terraform
The technical backbone of Lantana rests on the synergy between [Terraform](https://developer.hashicorp.com/terraform) and [Ansible](https://docs.ansible.com/), separating infrastructure provisioning from behavioral configuration. Terraform acts as the "scaffolding" layer, responsible for the lifecycle of generic compute assets. It creates and destroys the raw virtual machines or cloud instances, treating them as purely disposable resources.

Once the infrastructure is provisioned, Ansible takes over to apply identity and purpose through a tiered role system:

- **Atomic Roles:** These are the granular building blocks of the platform. An atomic role does exactly one thing—such as installing the Docker engine, configuring the Vector log-shipper, or deploying a specific honeypot application like Cowrie. They are highly reusable and agnostic of the larger deployment model.
- **Composite Roles:** These serve as functional archetypes or "Zones." A composite role uses Ansible's meta-dependency system to group atomic roles into a higher-level abstraction. For example, the `sensor_low` composite role automatically ensures that `common` utilities and `docker` runtimes are present before preparing the environment for honeypot containers.

This architecture enables a "Menu-based" deployment. The user selects a **Plate** (the base playbook, such as `single_node.yml` or `multi_node.yml`) to establish the infrastructure's backbone, and then adds **Toppings** (the narrative-driven sensors) via the `apply_narrative.yml` playbook. This separation ensures that security baselines and telemetry pipelines (the Plate) are consistently applied, while the deception logic (the Toppings) remains flexible and easily rotatable.

---

## Rules of Engagement
Lantana is designed to operate safely in hostile environments and assumes that sensor hosts—especially high-interaction ones—will eventually be compromised. To ensure ethical, legal, and operational safety, the platform enforces strict **rules of engagement** at both architectural and operational levels.

First, honeypots must never be used as offensive infrastructure. The honeywall zone enforces outbound traffic restrictions by default, ensuring compromised hosts cannot scan, attack, or otherwise harm third parties. Egress allowances, if any, must be explicit, narrowly scoped, and justified by a specific research goal.

Second, honeypots are assumed to be disposable. No secrets, credentials, production access, or sensitive internal systems may reside on sensor hosts. Any compromise must be considered total, and rebuilds must be routine rather than exceptional. Persistence by adversaries is treated as signal, not failure.

Third, honeypots must not intentionally target specific individuals or organizations without explicit legal and organizational authorization. Lantana is designed for broad-spectrum observation, adversary tradecraft research, and detection engineering, not entrapment or targeted intelligence collection.

Fourth, telemetry collection must respect privacy and data governance constraints. While honeypots observe hostile behavior by design, captured data must be handled, stored, and processed according to applicable policies, regulations, and ethical standards.

Finally, narratives, exposure profiles, and sensor configurations must align with a defined operational goal. Honeypots exist to answer questions, not merely to collect noise. Sensor rotation, profile changes, and topology shifts are part of the operational lifecycle, not ad hoc events.

---

## Why not Kubernetes, SIEM-first pipelines, or T-Pot
Lantana intentionally avoids Kubernetes, SIEM-centric architectures, and monolithic honeypot stacks such as T-Pot because they optimize for fundamentally different goals than deception operations.

**Kubernetes** is designed for service availability, self-healing, and workload abstraction. Honeypots, by contrast, are intentionally disposable, failure-tolerant, and identity-sensitive. Automatic restarts, rescheduling, and shared control planes obscure adversary behavior and introduce unnecessary attack surface and trust dependencies. For low-interaction honeypots, hardened standalone containers provide simpler, stronger, and more auditable isolation properties.

Traditional **SIEM**-first architectures optimize for real-time alerting and enterprise security operations. Honeypot telemetry instead benefits from long-term behavioral analysis, clustering, campaign reconstruction, and research-driven workflows. Lantana therefore prioritizes structured data lakes, columnar storage, and analytical pipelines over real-time alerting primitives, while still allowing downstream SIEM integration if desired.

Projects like **T-Pot** offer excellent turnkey honeypot environments but follow an appliance-style model: monolithic deployments, fixed topologies, and limited lifecycle control. Lantana is built as a composable platform where infrastructure, security policy, sensor identity, telemetry pipelines, and narratives are independently defined, versioned, and evolved.

---

## Getting Started
Lantana follows a modular operational workflow where you first prepare the "Plate" (infrastructure) and then "Skin" it with a specific "Narrative" (the honeypot persona). This workflow is powered by Ansible playbooks and Terraform manifests, allowing for rapid rotation and containment.

### Step 1: Clone the Repository
```bash
git clone https://github.com/lopes/lantana.git
cd lantana
```

> [!NOTE]
> In the future, we'll use **Terraform** to deploy VMs but it's not implemented yet, so we assume there's a VM with [Debian 13](https://www.debian.org/) available and the operator has the right credentials to reach and administrate it through SSH.

### Step 2: Define the Operation and Narrative
Each deployment is an "Operation" with its own inventory (Ansible). You define the behavior of your honeypots—such as exposed services, SSH banners, and vulnerable versions—within the `narrative.yml` file for that specific operation. Lantana comes with two operations as examples, one for single-node mode and the other fo for multi-node mode, and it's highly recommended to "clone" them to avoid starting operations from scratch. For the sake of this quick start guide, we'll show how to clone the `op_single` operation into `op_alpha`.

Clone the operation by copying the whole folder in the new one:
```bash
cp -r inventories/op_single inventories/op_alpha
```

Navigate to your operation folder and customize all files under `group_vars/all` with your host's data and the narrative you'll use. Create the `vault.yml` file using the next structure (even if you aren't planning to use a listed service, declare it with empty string).

> [!NOTE]
> Ansible will require a password to this file. It's crucial to a secure passphrase and keep it safe.
> It'll be required during all interactions with this operation, from deployment to day-to-day tasks.

```bash
ansible-vault create inventories/op_alpha/group_vars/all/vault.yml
```

`vault.yml` structure:

```text
vault_apikey_virustotal: ""
vault_apikey_abuseipdb: ""
vault_apikey_greynoise: ""
vault_apikey_shodan: ""
vault_apikey_phishstats: ""
vault_webhook_discord: ""
```

### Step 3: Prepare the Node
Use the `single_node` playbook to apply the required roles, turning the generic host into an all-in-one Lantana node.

```bash
ansible-playbook -i inventories/op_alpha/inventory.yml playbooks/deploy_single.yml
```

### Step 4: TBD Deploy the Honeypots
Once the base system is ready, "skin" the servers by deploying the specific honeypot applications and configurations defined in your narrative.
```bash
ansible-playbook -i inventories/op_alpha/inventory.yml playbooks/deploy_honeypots.yml
```

### Step 6: TBD Operational Lifecycle (Isolation and Rotation)
Lantana provides specific "Day 2" workflows for managing active engagements.

**To isolate a compromised node (Kill Switch):** Push a restrictive nftables ruleset to the target host to freeze it for forensic analysis.
```bash
ansible-playbook -i inventories/op_alpha/inventory.yml playbooks/apply_base.yml -e "isolated=true" --tags nftables
```

**To rotate a narrative:** Update your `narrative.yml` with a new persona and re-run the narrative playbook.
```bash
ansible-playbook -i inventories/op_alpha/inventory.yml playbooks/apply_narrative.yml
```

**To decommission the operation:** Use Terraform to destroy the infrastructure and wipe the state.
```bash
cd infra/terraform/envs/op_alpha
terraform destroy
```

---

## License
This project is licensed under the [MIT License](LICENSE).

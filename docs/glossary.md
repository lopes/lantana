# Lantana: Glossary & Terminology

In classic cybersecurity literature, terms like *honeypot*, *decoy*, and *trap* are often used interchangeably. Lantana's taxonomy draws from three primary references: Provos & Holz (*Virtual Honeypots*, 2007) for honeypot classification by interaction level and purpose, Sanders (*Intrusion Detection Honeypots*, 2020) for the production/detection use case, and the **MITRE Engage** framework for the strategic engagement model. This ensures a clear distinction between the strategic intent, the deceptive artifacts, and the underlying physical infrastructure.

---

## 1. Engagement Strategy & Concepts

- **Adversary Engagement:** The overarching, proactive cybersecurity approach of interacting with adversaries. As defined by MITRE Engage, it is the strategic combination of *Denial* and *Deception* to increase the cost and decrease the value of an adversary's cyber operations, while extracting actionable intelligence.
- **Deception:** The intentional use of artifacts (both facts and fictions) to mislead the adversary. Deception causes the attacker to form incorrect estimations and take actions that ultimately benefit the defender (e.g., revealing their toolkit).
- **Denial:** The ability to prevent or impair an adversary's ability to conduct their operations. While deception misleads the attacker, denial restricts their movement, limits their data collection, and disrupts their capabilities.
- **Delay:** A specific tactical outcome or objective within an engagement operation. By forcing an attacker to navigate through a maze of decoys, interact with throttled services, or analyze fake data, defenders impose a heavy time cost. This delays the attacker's progression toward real assets and provides defenders more time to react.
- **Narrative:** The bespoke "story" or persona applied to a set of decoys to attract a specific adversary. A narrative defines the exposed services, the vulnerability profile, and the behavioral traits of the environment.
- **Trap:** The psychological or operational mechanism used to entice an adversary into interacting with a decoy. *Example: "We set a trap by placing a highly privileged honeytoken inside an exposed low-interaction honeypot."*

## 2. Deception Artifacts & Infrastructure

- **Decoy:** A broad, umbrella term for any deceptive artifact designed to mislead an adversary. Honeypots, honeytokens, and fake network topologies are all specific types of decoys.
- **Honeypot:** An information system resource—such as an emulated service, application, or fully vulnerable operating system—whose sole value lies in unauthorized or illicit interaction. *It is the software the adversary attacks.* Honeypots are classified along two orthogonal axes (Provos & Holz, *Virtual Honeypots*, 2007): *interaction level* and *purpose*.
  - **Low-Interaction Honeypot:** A lightweight service emulator (e.g., Cowrie, Dionaea) that mimics specific vulnerabilities or protocols but does not offer a real operating system. Low risk, easy to containerize.
  - **High-Interaction Honeypot:** A real, fully functional system intentionally deployed in a vulnerable state. High risk, requires strict network containment, but yields forensic-grade intelligence.
  - **Production (Detection) Honeypot:** Deployed *inside* an organization's internal network alongside real assets. Any interaction is inherently suspicious, so these honeypots function as tripwires — every touch generates an alert for the threat detection team. Typically low-interaction and low maintenance. Sanders (*Intrusion Detection Honeypots*, 2020) is the definitive reference for this use case.
  - **Research (Intelligence) Honeypot:** Deployed on the *public internet* to attract and study attacker behavior at scale. Produces large volumes of telemetry that must be processed through an analysis pipeline to extract actionable threat intelligence. More complex to operate and requires dedicated data processing infrastructure.
- **Honeytoken:** A specific type of data-based decoy. These are fake digital assets—such as AWS access keys, database credentials, or beaconing documents—left on a host to detect unauthorized access or exfiltration.
- **Node:** A physical machine or virtual machine (VM) that forms the underlying compute layer of the Lantana architecture. Nodes are provisioned by Terraform.
- **Sensor:** The infrastructure role or zone that *hosts* the honeypots and captures the initial telemetry. In Lantana, a Sensor is the listener and the runtime environment (e.g., a node running Podman to host Cowrie containers).
- **Honeywall:** A dedicated security gateway and containment boundary. The honeywall strictly controls, routes, and monitors outbound traffic from the Sensor zone to prevent compromised honeypots from being weaponized against third parties.
- **Collector:** The out-of-band centralized processing zone. It receives raw telemetry from the Honeywall and Sensors, parses it, enriches it, and stores it in the data lake.
- **Operation:** A distinct, isolated deployment within Lantana. Managed as a unique Ansible Inventory, an Operation represents a specific intelligence goal or target adversary persona, allowing multiple deception campaigns to run simultaneously without interference.

## 3. Data & Analytics

- **Telemetry:** The raw data generated by the environment. This includes network connection logs, IDS alerts from the Honeywall, keystrokes from SSH honeypots, and process execution logs from high-interaction hosts.
- **Data Lake:** The centralized repository in the Collector zone where normalized, enriched telemetry is stored (typically in Parquet format) for downstream querying, behavioral analysis, and Threat Intelligence generation.

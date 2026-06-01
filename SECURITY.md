# Security Policy

## Reporting a vulnerability

Use **GitHub Private Vulnerability Reporting** — navigate to the repo → **Security** tab → **Advisories** → **Report a vulnerability**, or go directly to:

> https://github.com/lopes/lantana/security/advisories/new

Do **not** open a public Issue. GitHub Issues are world-readable from creation; Private Vulnerability Reporting is the only confidential channel available.

Include in your report:

- Affected component (pipeline module, Ansible role/playbook, Terraform config, Quadlet definition)
- Version or commit SHA where the issue is reproducible
- Reproduction steps
- Impact assessment
- Suggested remediation, if known

## Response expectations

This is a single-maintainer project.

- Acknowledgement: best effort within **7 days**
- Triage decision: within **30 days**
- No bug bounty program
- Coordinated disclosure: a fix-and-publish window will be agreed inside the advisory before any public disclosure. Default is 90 days from acknowledgement, shortened if a fix lands sooner.

## Scope

**In scope (Lantana platform bugs):**

- Privilege escalation via Ansible playbooks, roles, or systemd units
- OPSEC leaks — any path by which operator-identifying values (WAN IPs, hostnames, ASNs, SSH fingerprints) reach bronze/silver/gold data, reports, STIX output, dashboards, or tracked files. Highest-severity class for this project.
- Auth bypasses in deployed stack components (collector services, dashboard)
- Secrets exposed in logs, error paths, or telemetry
- Unsafe defaults (credentials shipped in config, undeclared open ports)
- Input-handling issues in the pipeline (Polars expressions, VRL transforms, enrichment HTTP clients)
- Container escape paths in Quadlet definitions

**Out of scope:**

- CVEs in upstream projects (Cowrie, Dionaea, Suricata) — these are intentional attack surface. Report to the respective upstreams.
- Malware delivered to `/var/lib/lantana/sensor/dionaea/binaries/` — these are research artifacts, not platform bugs.
- Attacker payloads captured in bronze/silver (passwords, command lines, URLs) — captured intelligence.
- Issues in third-party enrichment providers (AbuseIPDB, VirusTotal, Shodan, GreyNoise, MaxMind) — report to them directly.
- Issues requiring physical host access or pre-existing root
- Denial-of-service against the honeypot — DoS resistance is not a design goal for a disposable sensor.

## Supported versions

| Version | Status |
|---|---|
| `main` (pre-v1.0.0) | Receives fixes |
| After v1.0.0 ships | Latest minor of current major receives fixes; older minors do not |

## Safe harbor

Good-faith research conducted in accordance with this policy will not result in legal action. Research must not involve social engineering of maintainers, testing against deployments you do not own, or accessing captured attacker data beyond what is necessary to demonstrate the issue.

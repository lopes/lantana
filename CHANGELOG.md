# Changelog

All notable changes to Lantana are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — TBD

First stable release. The honeypot-as-code platform is feature-complete for the v1 scope: single-node and multi-node deployments, two production honeypots (Cowrie + Dionaea), a four-provider enrichment pipeline, gold-layer correlation, STIX export, and a Streamlit dashboard.

### Added

- **Zoned architecture** — Honeywall / Sensor / Collector zones, single-node primary, multi-node as an architectural principle.
- **Honeypots:** Cowrie (SSH + Telnet) and Dionaea (FTP, HTTP, EPMAP, SMB, MSSQL, MySQL) via the per-service catalog overlay.
- **Pipeline:** bronze → silver → gold with OCSF normalisation, per-provider risk scores, mean-of-two composite, GreyNoise RIOT short-circuit, and dual circuit-breaker for rate-limit handling.
- **Enrichment integrations:** MaxMind GeoLite2 (wire-speed), AbuseIPDB, Shodan, VirusTotal, GreyNoise Community.
- **Daily Discord brief** with embedded color tied to pipeline-health severity (`lantana-report` timer).
- **STIX 2.1 bundle export** gated on `risk_score >= 40.0`.
- **Datalake retention:** 180-day standard, 14-day emergency prune at >80% disk.
- **OPSEC layers:** Vector source filtering, silver-layer pseudonymisation, gold/report/STIX surface free of operator-identifying values.
- **Ansible automation** with merged-tree Vector config validation handler and dedicated validate playbooks (`validate-single-node`, `validate-multi-node`, `validate-pipeline-cycle`).
- **Terraform provisioning** for Proxmox VMs with cloud-init SSH hardening.
- **CI:** ruff + ruff-format + mypy strict + pytest + terraform fmt/validate + shellcheck + ansible-lint, plus CodeQL on a weekly schedule.

[Unreleased]: https://github.com/lopes/lantana/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/lopes/lantana/releases/tag/v1.0.0

# Lantana: Full Roadmap Plan (Phase 0 + Phase 1 + Phase 2)

## Context

Lantana is a honeypot-as-code platform built on Ansible that deploys dual-stack (IPv4/IPv6) honeypots on Debian 13. It currently has a working single-node deployment with Cowrie (SSH/Telnet honeypot) and a Vector-based telemetry pipeline that writes raw JSON to a bronze datalake. However, a thorough audit reveals: multi-node deployment is broken (variable mismatches, incomplete firewall template, empty network tasks), several security gaps exist, and the entire data processing pipeline (enrichment, normalization, analysis) is unbuilt.

**Project vision:** Lantana serves triple duty -- personal security research, professional threat intelligence tool for SOC teams, and open-source community project. The primary deployment model is **single-node** (all zones on one host), but the multi-node architecture exists as a design principle for separation of concerns -- logical zone boundaries (honeywall/sensor/collector) apply identically regardless of physical topology. Infrastructure is on-prem **VMware/vSphere**, provisioned via Terraform.

**Intelligence focus:** Broad threat landscape monitoring with emphasis on behavioral progression analysis -- detecting and tagging automated scanners (Mirai, etc.), then tracking escalation from scanning to credential attacks to interactive/manual sessions. The gold layer and dashboard must surface this scanner-to-escalation pipeline per IP over time.

**Key decisions:**
- Directory structure: keep `config/ansible/`, add `infra/terraform/` and `pipeline/`
- Package manager: `uv`
- API enrichment: start with free tiers, upgrade path built in
- Output: Streamlit dashboard + STIX machine-readable threat intel + periodic Discord reports (Markdown + STIX zipped bundles)
- OPSEC: honeypot IPs redacted at silver layer (bronze keeps raw for debugging). Gold/reports/STIX never contain infrastructure details
- TLP marking: configurable per-operation (default TLP:GREEN for peer sharing)
- Datalake: per-instance singleton. Multiple operations tag data with operation name (column, not partition). Full isolation requires separate instances.
- Artifacts: download metadata + hashes ingested for VT enrichment. Binaries rotated at 90 days, capped at 100MB per artifact. TTY recording metadata ingested similarly.
- Streamlit: personal console, never shared. Peers get Discord reports + static STIX bundles only. TAXII server deferred to Phase 2+.
- Suricata: default ET ruleset for Phase 1. Custom honeypot-specific rules in Phase 2.
- Documentation: incremental with each phase (open-source readiness)
- No hard deadline -- quality over speed

---

## Phase 2 -- COMPLETE

Expanded honeypot coverage and refined intelligence:

- **Dionaea honeypot role**: Full Ansible role (Quadlet container, Vector pipeline with Layer 1 OPSEC filter, nftables NAT rules for 7 services: FTP, HTTP, RPC, SMB, MSSQL, MySQL, SIP). Config template integrated with `narrative.yml` deception story.
- **Dionaea pipeline**: Bronze schema, OCSF normalizer (connection->NetworkActivity, credential->Authentication, FTP command->ProcessActivity), enrichment runner integration, hash scanning for malware binaries.
- **PhishStats enrichment provider**: IP-based phishing URL intelligence. Registered alongside AbuseIPDB, GreyNoise, Shodan, VirusTotal.
- **Custom Suricata rules**: `lantana.rules` (SID 9000001-9000999) with SSH brute force, SMB null session, MySQL/FTP/MSSQL brute force, SIP scanning, malware download detection. Deployed alongside ET ruleset.
- **Multi-day behavioral progression**: 7-day lookback window tracking IP escalation across days. New `behavioral_progression_multiday` gold table with progression velocity and slow-burn detection.
- **Cowrie file_download normalization**: `cowrie.session.file_download` -> File Activity (OCSF 1001), mapping SHA256 hashes, URLs, and file paths.
- **Gold download metrics**: `downloads_captured`, `top_download_urls`, `top_download_hashes` in daily summary. `+20` malware delivery risk factor in IP reputation.
- **Report malware section**: "Malware Captured" section in Discord daily briefs with download counts, top URLs, and top hashes.
- **STIX malware objects**: `stix2.Malware` + file-hash indicators from captured samples. Slow-burn escalation labels and multi-day `valid_from` dates on IP indicators.
- **Dashboard multi-day progression**: Progression page shows slow-burn IPs table and velocity distribution from the 7-day lookback.
- **IPv4-mapped IPv6 normalization**: `::ffff:` prefix stripped at bronze read time.
- **Integration testing**: VPS data fetch/inject/replay scripts + 6 integration tests against real production data.
- **Datalake env var overrides**: `LANTANA_BRONZE_ROOT`, `LANTANA_SILVER_ROOT`, `LANTANA_GOLD_ROOT` for local development.
- TAXII server: deferred to Phase 3.

**Test suite**: 140 tests (134 unit + 6 integration), ruff + mypy clean.

---

*Full task-level detail for each phase is maintained in the active plan file during implementation.*
*This document serves as the durable reference for project direction and decisions.*

---
name: deploy-sensors
description: >-
  Deployment and validation discipline for Lantana Ansible roles, Vector VRL
  merged-tree validation, self-owned Cowrie and Dionaea rootless Podman Quadlet
  containers, and post-deploy runtime verification playbooks. Load before editing
  Ansible roles, Vector configs, Quadlet templates, or running sensor deployments.
---

# Lantana Sensor, Vector & Quadlet Deployment Discipline (`deploy-sensors`)

Use this skill whenever editing or deploying Ansible roles (`config/ansible/roles/`), Vector configurations (`/etc/vector/`), `containers/{cowrie,dionaea}/`, Quadlet `.container.j2` templates, or running sensor validation playbooks.

---

## 1. Vector Deployment Discipline (Merged-Tree Validation)

Vector loads `/etc/vector/vector.yaml` plus every `/etc/vector/conf.d/*.yaml` as one merged graph. Validating a single `conf.d` file fails with `"No sinks defined"`.

- **Single-node routing (v1.5):** `transforms.enrich_geo.inputs` subscribes directly to `["filter_*"]` in memory; `forward-honeywall.yaml` and `forward-sensor.yaml` are absent on single-node (retained on multi-node).
- **Mandatory rule:** Every Ansible role rendering a Vector config must `notify: "Validate Vector config tree"` (`roles/base/handlers/main.yml`, enumerating `conf.d/*.yaml` via `find`) **before** `"Restart Vector"`.
- **Standard Layer-1 OPSEC filter:** Strip `^::ffff:` once and drop loopback, RFC 1918, link-local, ULA, internal prefixes, and WAN IPv4/IPv6 addresses before ingestion.

---

## 2. Self-Owned Pinned Honeypot Containers & Quadlets (v1.5.1)

Both sensors run from self-owned, CI-verified, **strictly non-egressing** GHCR images built from pinned upstream commit SHAs (`.github/workflows/build-{cowrie,dionaea}.yml`):

1. **Cowrie (`ghcr.io/lopes/lantana-cowrie:v1.5.1`):**
   - Built from pinned `cowrie/cowrie` SHA (`containers/cowrie/Containerfile`) on distroless Debian 13 with repo-constant `UID 999 / GID 999` and build-time `patch_offline.py` short-circuiting `cowrie/core/network.py` + `cowrie/commands/tftp.py` (zero outbound DNS/TCP/UDP) alongside `out_addr = 127.0.0.1` in `cowrie.cfg.j2`.
   - Ownership flows strictly via `UserNS=keep-id:uid=999,gid=999` (never `,U`), and `Pull=never` is enforced in the Quadlet (root imports images offline via `profile_sensor_low/tasks/import_sensor_image.yml`).
   - Health check uses `HealthCmd=CMD python3 /healthcheck.py` (never `CMD-SHELL` or JSON array) + `HealthOnFailure=kill`, `StartLimitIntervalSec=0`, `RestartSec=10s`.
2. **Dionaea (`ghcr.io/lopes/lantana-dionaea:v1.5.1`):**
   - Built from pinned `DinoTools/dionaea` SHA (`containers/dionaea/Containerfile`) with repo-constant `UID 1000 / GID 1000`.
   - Bakes `/opt/dionaea/etc/dionaea/dionaea.cfg` (`modules=python,emu`, `processors=filter_emu`, permanently disabling outbound `curl` and `bistreams`), patches `http.py` (`patch_http.py`) for structured HTTP/POST payload capture without `http-*.tmp` leaks, patches `ftp.py` (`patch_ftp.py`) to reject active `PORT` outbound connects with `502`, ships `lantana_json.py` (HTTP + MSSQL/MySQL + per-session SHA-256 `dionaea.binary.captured`), and uses a non-destructive `entrypoint.sh` (no `cp -a`, preserving host POSIX ACLs).
   - Driven by `roles/dionaea/defaults/main.yml::dionaea_service_catalog`; all Dionaea `.cfg`/`.yaml`/`.py` files must be **7-bit ASCII** (embedded Python 3.6 + PyYAML).
   - Runs strictly non-root (`USER 1000:1000`) with `Pull=never`, `UserNS=keep-id:uid=1000,gid=1000`, `DropCapability=ALL`, `Sysctl=net.ipv4.ip_unprivileged_port_start=0`, `ReadOnly=true`, and `VolatileTmp=true`; never use `,U`.
   - Health check uses app-layer `HealthCmd=CMD python3 /healthcheck.py` (HTTP `GET /` -> `HTTP/1.`, fallback FTP `220`) + `HealthOnFailure=kill`, `StartLimitIntervalSec=0`, `RestartSec=10s`.
   - Logrotate runs under `su stigma stigma` with `maxsize 100M` (checked hourly + forced at `00:00 UTC`) and restarts `dionaea.service` in `postrotate` (matching Cowrie) to avoid `copytruncate` sparse-null holes.
3. **Strict one-way isolation boundary:**
   - Only `vector` holds read-only `u:vector:rX` (default + recursive) on `0750` log dirs (`/var/log/lantana/sensor/{cowrie,dionaea}` and `/var/log/lantana/honeywall/suricata`).
   - `nectar` NEVER receives POSIX ACLs on `/var/lib/lantana/sensor/` (`lantana-grant-read` is removed). `stigma` prunes its own scratch directories hourly via root-owned `lantana-sensor-prune.timer` (`User=stigma`, `/usr/local/libexec/lantana-sensor-prune`, `O_NOFOLLOW` + `dir_fd`, 14d normal / 3d emergency `>80%`), while `stigma` stays locked out (`EACCES`) of datalake/collector.
4. **Honeywall & dark egress hardening:**
   - `acl` and `ethtool` installed via `roles/base/tasks/main.yml`; `/etc/systemd/journald.conf.d/10-lantana.conf` caps `SystemMaxUse=200M`.
   - Suricata runs non-root (`suricata:suricata` systemd drop-in), disables NIC offloads (`lantana-nic-offload.service`), disables raw alert payload/packet/http-body dumps plus `pcap-log` & `file-store` by default, and drops `ltn0` on single-node. Always pass `-l /tmp` when validating with root-run `suricata -T` so a `root:root` `eve.json` is never created before non-root `suricata.service` starts.
   - `nftables` (`firewall-single.nft.j2`) enforces 100% dark runtime egress for `meta skuid stigma ct state new` across WAN, loopback, and `ltn0` (`[LANTANA_OUTPUT_DROP_SENSOR_LO]` / `[LANTANA_OUTPUT_DROP_SENSOR_WAN]` + unconditional `counter drop`), plus per-source dynamic input meters with `level info` + `/etc/sysctl.d/99-lantana-console.conf` (`kernel.printk = 4 4 1 4`).

---

## 3. Post-Deploy Validation & Audit Playbooks

Always run the mechanical validation playbooks from `config/ansible/` (and `audit-host-integrity.yml` periodically / pre-teardown):

```bash
ansible-playbook -i inventories/<op>/inventory.yml tests/validate-single-node.yml
ansible-playbook -i inventories/<op>/inventory.yml tests/validate-canaries.yml
ansible-playbook -i inventories/<op>/inventory.yml tests/validate-sensor-runtime.yml
ansible-playbook -i inventories/<op>/inventory.yml tests/audit-host-integrity.yml
```

- `validate-single-node.yml`: base packages (`acl`, `ethtool`), non-root Suricata, offloads off, `kernel.printk == "4 4 1 4"`, no single-node forwarders, zero PCAPs/file-store, `lantana-sensor-prune.timer`, zero legacy `lantana-grant-read`/ACLs, `journald` `SystemMaxUse=200M`, strict `stigma <-> nectar` boundary, dark egress rules, timers/units.
- `validate-canaries.yml`: Vector 1-in-1-out + loopback/RFC1918/WAN drop canary + external `SSH-2.0-Go` -> Suricata `sid:9000004` + zero `TCPv4 invalid checksum` alerts + active `stigma` WAN/loopback egress block canary (0 Bronze leaks).
- `validate-sensor-runtime.yml`: `UserNS=keep-id`, `Pull=never`, container health, zero log-plugin tracebacks, open JSON log FDs, fresh Bronze NDJSON, zero orphan UIDs.
- `audit-host-integrity.yml`: read-only persistence & compromise triage (`~/.config/systemd/user/`, linger allowlist, shell rc / SSH rc / `authorized_keys`, `/etc/ld.so.preload`, containers, crons, `sshd`, nftables egress counters).

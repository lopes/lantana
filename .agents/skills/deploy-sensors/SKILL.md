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

## 2. Self-Owned Pinned Honeypot Containers & Quadlets (v1.5)

Both sensors run from self-owned, CI-verified GHCR images built from pinned upstream commit SHAs (`.github/workflows/build-{cowrie,dionaea}.yml`):

1. **Cowrie (`ghcr.io/lopes/lantana-cowrie:v1.5`):**
   - Built from pinned `cowrie/cowrie` SHA (`containers/cowrie/Containerfile`) on distroless Debian 13 with repo-constant `UID 999 / GID 999`.
   - Ownership flows strictly via `UserNS=keep-id:uid=999,gid=999` (never `,U`).
   - Health check uses `HealthCmd=CMD python3 /healthcheck.py` (never `CMD-SHELL` or JSON array) + `HealthOnFailure=kill`, `StartLimitIntervalSec=0`, `RestartSec=10s`.
2. **Dionaea (`ghcr.io/lopes/lantana-dionaea:v1.5`):**
   - Built from pinned `DinoTools/dionaea` SHA (`containers/dionaea/Containerfile`) with repo-constant `UID 1000 / GID 1000`.
   - Bakes `/opt/dionaea/etc/dionaea/dionaea.cfg` (`processors=filter_emu`, permanently disabling `bistreams`), patches `http.py` (`patch_http.py`) for structured HTTP/POST payload capture without `http-*.tmp` leaks, ships `lantana_json.py` (HTTP + MSSQL/MySQL + per-session SHA-256 `dionaea.binary.captured`), and uses a non-destructive `entrypoint.sh` (no `cp -a`, preserving host POSIX ACLs).
   - Driven by `roles/dionaea/defaults/main.yml::dionaea_service_catalog`; all Dionaea `.cfg`/`.yaml`/`.py` files must be **7-bit ASCII** (embedded Python 3.6 + PyYAML).
   - Runs strictly non-root (`USER 1000:1000`) with `UserNS=keep-id:uid=1000,gid=1000`, `DropCapability=ALL`, `Sysctl=net.ipv4.ip_unprivileged_port_start=0`, `ReadOnly=true`, and `VolatileTmp=true`; never use `,U`.
   - Health check uses app-layer `HealthCmd=CMD python3 /healthcheck.py` (HTTP `GET /` -> `HTTP/1.`, fallback FTP `220`) + `HealthOnFailure=kill`, `StartLimitIntervalSec=0`, `RestartSec=10s`.
   - Logrotate runs under `su stigma stigma` and restarts `dionaea.service` in `postrotate` (matching Cowrie) to avoid `copytruncate` sparse-null holes.
3. **One-way POSIX ACL boundary:**
   - `u:vector:rX` (default + recursive) on `0750` log dirs (`/var/log/lantana/sensor/{cowrie,dionaea}` and `/var/log/lantana/honeywall/suricata`).
   - `u:nectar:rwX` (default + recursive, refreshed `00:10 UTC` via `/usr/local/sbin/lantana-grant-read`) on sensor scratch dirs (`cowrie/{downloads,tty}`, `dionaea/{binaries,bistreams,tmp}`) so `nectar` (`lantana-prune`) deletes 14d artifacts safely with `O_NOFOLLOW` + `dir_fd` while `stigma` stays locked out (`EACCES`) of datalake/collector.
4. **Honeywall hardening:**
   - `acl` and `ethtool` installed via `roles/base/tasks/main.yml`.
   - Suricata runs non-root (`suricata:suricata` systemd drop-in), disables NIC offloads (`lantana-nic-offload.service`), disables `pcap-log` & `file-store` by default, and drops `ltn0` on single-node. Always pass `-l /tmp` when validating with root-run `suricata -T` so a `root:root` `eve.json` is never created before non-root `suricata.service` starts.
   - `nftables` uses per-source dynamic meters with `level info` + `/etc/sysctl.d/99-lantana-console.conf` (`kernel.printk = 4 4 1 4`) so firewall drops never spam KVM `/dev/tty0`.

---

## 3. Post-Deploy Validation Playbooks

Always run all three mechanical playbooks from `config/ansible/`:

```bash
ansible-playbook -i inventories/<op>/inventory.yml tests/validate-single-node.yml
ansible-playbook -i inventories/<op>/inventory.yml tests/validate-canaries.yml
ansible-playbook -i inventories/<op>/inventory.yml tests/validate-sensor-runtime.yml
```

- `validate-single-node.yml`: base packages (`acl`, `ethtool`), non-root Suricata, offloads off, `kernel.printk == "4 4 1 4"`, no single-node forwarders, zero PCAPs/file-store, timers/units.
- `validate-canaries.yml`: Vector 1-in-1-out + loopback/RFC1918/WAN drop canary + external `SSH-2.0-Go` -> Suricata `sid:9000004` + zero `TCPv4 invalid checksum` alerts.
- `validate-sensor-runtime.yml`: container health, zero log-plugin tracebacks, open JSON log FDs, fresh Bronze NDJSON, zero orphan UIDs.

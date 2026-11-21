# Honeypots

Lantana v1.5 ships two honeypots: **Cowrie** (SSH + Telnet) and **Dionaea**
(SMB, FTP, HTTP, MSSQL, MySQL, EPMAP/DCERPC). Both run from **self-owned, pinned GHCR container images** as rootless Podman containers under the `stigma` user (UID 2001), are configured via Ansible roles under `config/ansible/roles/`, and ship event NDJSON to the collector via Vector.

This document covers the image sourcing strategy, per-honeypot defaults and runtime constraints, and how to disable a specific protocol post-deploy.

## Design principle: all services enabled by default

Every protocol a honeypot supports is enabled on every deploy. There is
intentionally no inventory-level toggle for individual sub-services —
exposing each protocol as a per-operation knob would create N×M states
to validate, and Lantana prioritises a simple, predictable surface over
fine-grained tuning.

**Disabling a sub-service is a manual on-server operation.** The
procedures below take effect immediately on a single host but are
**not persisted across re-deploys** — running `deploy_honeypots.yml`
again will re-render the canonical config and restart the container,
reverting any local edits. That is intended: a re-deploy is the
authoritative source of truth.

If a protocol needs to be permanently off for a given operation, edit the
honeypot's Ansible role/template and accept that the change applies to
every host using that role.

## Known limitations

- **Dionaea SIP is intentionally absent.** The upstream SIP module's privilege-drop sequence creates an ownership race on `accounts.sqlite`. `templates/services-enabled/sip.yaml.j2` stays in the repo if a future build resolves it.
- **Dionaea MSSQL version string is hardcoded upstream.** The MSSQL responder reports a fixed TDS version regardless of `narrative.services.mssql.version`. Connections and `sql_command` bodies still capture cleanly.

*(Resolved in v1.5: Dionaea download URL + per-session `src_ip` attribution, MSSQL/MySQL `sql_command` capture, structured HTTP/POST payload capture without `http-*.tmp` leaks, disabled `bistreams` disk bloat, and self-owned pinned GHCR images eliminating rolling-tag UID drift.)*

## Image sourcing strategy

Both honeypots run from **self-owned pinned images** built in this repository (`containers/cowrie/` and `containers/dionaea/`) from pinned upstream git commits and published to GitHub Container Registry by `.github/workflows/build-{cowrie,dionaea}.yml`:

| Honeypot | Default image (`defaults/main.yml`) | Pinned upstream ref | In-container UID/GID |
|---|---|---|---|
| Cowrie | `ghcr.io/lopes/lantana-cowrie:v1.5` (`cowrie_image`) | `cowrie/cowrie` `v3.1.7` (`8e36327f...`) | `999:999` (`UserNS=keep-id:uid=999,gid=999`) |
| Dionaea | `ghcr.io/lopes/lantana-dionaea:v1.5` (`dionaea_image`) | `DinoTools/dionaea` (`4e459f1b...`) | `1000:1000` (subuid `100999`, no `,U`) |

**Why self-owned images?** Rolling third-party tags (`cowrie/cowrie:latest`, `dinotools/dionaea:nightly`) silently broke production twice in Operation Alpha when upstream shifted UIDs (`998 -> 999`) or changed entrypoint ownership behaviour. Owning the Containerfiles turns in-container UIDs into repo constants, moves upstream rebases into explicit PRs gated by `validate-sensor-runtime.yml`, and lets us ship three clean Dionaea extensions:

1. **Baked `/opt/dionaea/etc/dionaea/dionaea.cfg`** setting `processors=filter_emu` (eliminating multi-gigabyte `bistreams/` growth).
2. **`patch_http.py`** patching Dionaea's `http.py` so JSON/non-form POST bodies (e.g. `/v1/chat/completions`, `/mcp`) are captured safely without `cgi.FieldStorage` crashes or leaked `http-*.tmp` files in `binaries/`.
3. **`lantana_json.py` ihandler** replacing upstream `log_json`, emitting UTC `Z` timestamps, structured HTTP request/POST fields, MSSQL/MySQL `sql_command` bodies, and attributed `dionaea.binary.captured` events (carrying `src_ip`, SHA-256 `shasum`, and `download_url`) on `dionaea.download.complete.{unique,again}`.
4. **Non-destructive `entrypoint.sh`** that preserves host POSIX ACLs (`u:vector:rX` on logs, `u:nectar:rwX` on scratch dirs) across container restarts instead of wiping them with `cp -a`.

Operators can override `cowrie_image` or `dionaea_image` per inventory (e.g. `localhost/lantana-dionaea:v1.5` for local/staging builds).

## Cowrie

- **Container image:** `ghcr.io/lopes/lantana-cowrie:v1.5` (override via `cowrie_image`).
- **Quadlet unit:** `sensor-cowrie` (`/etc/containers/systemd/users/2001/cowrie.container`).
- **Config file:** `/etc/lantana/sensor/cowrie/cowrie.cfg` (rendered from `roles/cowrie/templates/cowrie.cfg.j2`).
- **Health check:** `HealthCmd=CMD python3 /healthcheck.py` (never `CMD-SHELL` or JSON array) with `HealthOnFailure=kill`.
- **Ownership:** `UserNS=keep-id:uid=999,gid=999` (never `,U`). Host bind-mount directories stay owned by `stigma`, with `u:vector:rX` on logs and `u:nectar:rwX` on `downloads/` and `tty/`.

### Default protocol surface

| Protocol | External port | Container port | Honeywall DNAT |
|----------|---------------|----------------|----------------|
| SSH      | 22            | 2222           | 22 → sensor:2222 |
| Telnet   | 23            | 2223           | 23 → sensor:2223 |

Both protocols are governed by `enabled = true` flags in `cowrie.cfg`.

### Disabling SSH or Telnet on a running honeypot

SSH to the host as the `lantana` admin user, then:

```bash
# Edit the rendered config — flip enabled = true to false for the
# protocol you want to disable. Example: turn telnet off.
sudo $EDITOR /etc/lantana/sensor/cowrie/cowrie.cfg

# Restart the Cowrie container so it re-reads the config.
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 \
  systemctl --user restart cowrie.service

# Confirm — Cowrie should no longer accept connections on the disabled port.
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 \
  systemctl --user status cowrie.service
```

To stop accepting the packet at the firewall too, remove the matching line from `/etc/lantana/honeywall/nftables/sensors/cowrie.nft` and reload nftables (`sudo systemctl reload nftables`). Either change reverts on the next `deploy_honeypots.yml` run.

## Dionaea

- **Container image:** `ghcr.io/lopes/lantana-dionaea:v1.5` (override via `dionaea_image`).
- **Quadlet unit:** `sensor-dionaea` (`/etc/containers/systemd/users/2001/dionaea.container`).
- **Config layout:** `/etc/lantana/sensor/dionaea/services-enabled/<svc>.yaml` (one file per protocol in `dionaea_service_catalog`) and `/etc/lantana/sensor/dionaea/ihandlers-enabled/` (`lantana_json.yaml` + `store.yaml`), both bind-mounted read-only over `/opt/dionaea/etc/dionaea/{services,ihandlers}-enabled/`.
- **Health check:** application-layer `/etc/lantana/sensor/dionaea/healthcheck.py` (asserts worker PID, live listening sockets across catalog ports, and writable JSON log FD) with `HealthOnFailure=kill` so silent hangs auto-restart.

### Container model and constraints

Four invariants remain load-bearing in `roles/dionaea/`:

1. **Per-service and ihandler directory overlays.** The image bakes `/opt/dionaea/etc/dionaea/dionaea.cfg` (`processors=filter_emu`). Ansible mounts `services-enabled/` and `ihandlers-enabled/` `:ro` over the bundled directories so only our 6 catalog services and `lantana_json` + `store` ihandlers load.
2. **Five specific capabilities stay added.** The Quadlet starts from `DropCapability=ALL` and adds only:
   - `NET_BIND_SERVICE` — bind privileged ports (`21, 80, 135, 445`) inside the container.
   - `SETUID` + `SETGID` — drop from container-root to `dionaea` (`UID 1000`). Without these, dionaea exits silently with status `133`.
   - `CHOWN` + `FOWNER` — non-destructive `entrypoint.sh` ensures data/log subdirectories are writable by `dionaea:dionaea` without stripping host POSIX ACLs.
3. **No `,U` and no `UserNS=keep-id`.** Dionaea runs as a two-user container (root entrypoint -> `dionaea` UID `1000` = host subuid `100999`). `,U` races the entrypoint and leaves `dionaea.json` unwritable; host access for Vector and `nectar` flows strictly through POSIX ACLs (`u:vector:rX` on logs, `u:nectar:rwX` via `lantana-grant-read` on `binaries/`, `bistreams/`, `tmp/`).
4. **7-bit ASCII only in service and ihandler YAMLs.** `templates/services-enabled/*.yaml.j2` and `templates/ihandlers-enabled/*.yaml.j2` must stay pure 7-bit ASCII (enforced at deploy time by Ansible's `validate:` check). Use `--`, `->`, and straight quotes only.

### Default protocol surface

Defined in `config/ansible/roles/dionaea/defaults/main.yml` under `dionaea_service_catalog`:

| Protocol | WAN port | Host/sensor published port | Container port | Notes |
|----------|----------|----------------------------|----------------|-------|
| FTP      | 21       | 8021                       | 21             | Banner from `narrative.services.ftp.banner` |
| HTTP     | 80       | 8080                       | 80             | `Server:` header from `narrative.services.http.server_header`; `patch_http.py` + `lantana_json` capture POST/JSON payloads cleanly |
| EPMAP    | 135      | 8135                       | 135            | DCE/RPC endpoint mapper; no persona fields |
| SMB      | 445      | 8445                       | 445            | Workgroup / native OS / native LAN manager / server name from narrative |
| MSSQL    | 1433     | 8433                       | 1433           | Captures `sql_command` via `lantana_json`; version string remains hardcoded upstream |
| MySQL    | 3306     | 8306                       | 3306           | Server version from `narrative.services.mysql.version`; captures `sql_command` via `lantana_json` |

Dionaea has no native SSH (22) or Telnet (23) listener — those belong exclusively to Cowrie.

### Disabling a Dionaea sub-service on a running honeypot

Each service is a single YAML file under `/etc/lantana/sensor/dionaea/services-enabled/`. To disable a service temporarily:

```bash
# Example: disable the EPMAP listener.
sudo mv /etc/lantana/sensor/dionaea/services-enabled/epmap.yaml \
        /etc/lantana/sensor/dionaea/services-enabled/epmap.yaml.disabled

# Restart Dionaea so it re-globs the services directory.
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 \
  systemctl --user restart dionaea.service
```

To drop it at the firewall too, edit `/etc/lantana/honeywall/nftables/sensors/dionaea.nft` and run `sudo systemctl reload nftables`. Both revert on the next `deploy_honeypots.yml` run.

### Adding a new protocol permanently

- **Dionaea:** add (or remove) a catalog entry in `config/ansible/roles/dionaea/defaults/main.yml` and drop a matching ASCII-only `templates/services-enabled/<svc>.yaml.j2`. The Quadlet, nftables rules, and validation playbooks derive from the catalog automatically.
- **Cowrie:** edit `roles/cowrie/templates/cowrie.cfg.j2` and re-deploy.

## Validation

After any deploy, run the three post-deploy validation playbooks from `config/ansible/`:

1. `tests/validate-single-node.yml` — asserts users, SSH, `ltn0`, nftables meters, NIC offloads, Suricata non-root user, logrotate, timers, and active honeypot ports.
2. `tests/validate-sensor-runtime.yml` — asserts Quadlet invariants, container health (`healthy`), zero plugin tracebacks, worker log FDs, and fresh Bronze NDJSON.
3. `tests/validate-canaries.yml` — injects active synthetic probes proving Vector 1-in-1-out delivery, Layer-1 edge filtering, and Suricata `sid:9000004` detection with zero invalid-checksum alerts.

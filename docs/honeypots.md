# Honeypots

Lantana ships two honeypots in v1.0.0: **Cowrie** (SSH + Telnet) and **Dionaea**
(SMB, FTP, HTTP, MSSQL, MySQL, EPMAP/DCERPC). Both run as rootless
Podman containers under the `stigma` user (UID 2001), are configured via
Ansible roles under `config/ansible/roles/`, and ship event NDJSON to
the collector via Vector.

This document covers what each honeypot exposes by default and how to
disable a specific protocol post-deploy.

## Design principle: all services enabled by default

Every protocol a honeypot supports is enabled on every deploy. There is
intentionally no inventory-level toggle for individual sub-services —
exposing each protocol as a per-operation knob would create N×M states
to validate, and v1.0.0 prioritises a simple, predictable surface over
fine-grained tuning.

**Disabling a sub-service is a manual on-server operation.** The
procedures below take effect immediately on a single host but are
**not persisted across re-deploys** — running `deploy_honeypots.yml`
again will re-render the canonical config and restart the container,
reverting any local edits. That is intended: a re-deploy is the
authoritative source of truth.

If a protocol needs to be permanently off for a given operation, the
right move is to edit the honeypot's Ansible role/template and accept
that the change applies to every host using that role.

## Known limitations (v1.0.0)

These are documented constraints in the v1.0.0 honeypot surface — not bugs. Each has a deferred fix tracked for a future cut. Full rationale is in the per-honeypot sections below.

- **Dionaea SIP is intentionally absent.** The dinotools image's privilege-drop model creates an unfixable ownership race on the SIP module's `accounts.sqlite`. The `templates/services-enabled/sip.yaml.j2` file is preserved in the repo so a future image fix lets us re-enable SIP without re-implementing the template. See [Dionaea → Default protocol surface](#default-protocol-surface-1) for details.
- **Dionaea MSSQL version string is hardcoded upstream.** The MSSQL responder reports a fixed version regardless of `narrative.services.mssql.version`. Tracked for v1.1, blocked on an upstream patch. See the [MSSQL row of the Dionaea protocol table](#default-protocol-surface-1).
- **Dionaea download URL + binary metadata stops at the dionaea bus.** Captured payloads land in `/var/lib/lantana/sensor/dionaea/binaries/` but the URL + hash never reach `dionaea.json` (and therefore never reach bronze → silver → STIX). Surfacing this needs a small custom ihandler; tracked on the project Roadmap in the [README](/README.md#roadmap).
- **Dionaea MSSQL / MySQL command bodies stop at the dionaea bus.** Same upstream constraint — the bundled `log_json` ihandler emits connection lifecycle + credentials only. Tracked on the Roadmap.
- **Dionaea binary hashing uses MD5 (and SHA-512 via `store`) — not SHA-256.** The IOC pipeline (`file_hash_sha256`, STIX file indicators, VT lookup) assumes SHA-256. Fix is on the Roadmap.
- **Dionaea restart breaks log_json on existing containers.** Initial start works because the file descriptor is acquired before the privilege drop; subsequent restarts can't reopen the stigma-owned file. Operationally invisible on fresh deploys; only surfaces when an operator bounces the container. Fix is on the Roadmap.

## Cowrie

Container image: `docker.io/cowrie/cowrie:latest`.
Quadlet unit:   `sensor-cowrie` (managed via `/etc/containers/systemd/users/2001/cowrie.container`).
Config file:    `/etc/lantana/sensor/cowrie/cowrie.cfg` (rendered by Ansible
                from `roles/cowrie/templates/cowrie.cfg.j2`).

### Default protocol surface

| Protocol | External port | Container port | Honeywall DNAT |
|----------|---------------|----------------|----------------|
| SSH      | 22            | 2222           | 22 → sensor:2222 |
| Telnet   | 23            | 2223           | 23 → sensor:2223 |

Both protocols are governed by `enabled = true` flags in `cowrie.cfg`:

```ini
[ssh]
enabled = true
...

[telnet]
enabled = true
...
```

### Disabling SSH or Telnet on a running honeypot

SSH to the VPS as the `lantana` admin user, then:

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

The honeywall's nftables DNAT for the now-disabled port stays in
place — packets still get DNATted to the sensor, but Cowrie will
reject the connection at the application layer. To stop accepting
the packet at the firewall too, also remove the matching line from
`/etc/lantana/honeywall/nftables/sensors/cowrie.nft` and reload
nftables:

```bash
sudo $EDITOR /etc/lantana/honeywall/nftables/sensors/cowrie.nft
sudo systemctl reload nftables
```

Either change is reverted on the next `deploy_honeypots.yml` run.

## Dionaea

Container image: `docker.io/dinotools/dionaea:nightly`.
Quadlet unit:   `sensor-dionaea` (managed via `/etc/containers/systemd/users/2001/dionaea.container`).
Config layout:  `/etc/lantana/sensor/dionaea/services-enabled/<svc>.yaml` (one file
                per protocol; bind-mounted read-only over the container's
                `/opt/dionaea/etc/dionaea/services-enabled/` directory). Dionaea's
                bundled `dionaea.cfg` globs every `*.yaml` in that directory at
                startup. A parallel `ihandlers-enabled/` directory holds incident
                handler configs (we ship only `log_json.yaml` — it streams every
                attacker connection to NDJSON for the Vector → bronze pipeline).

### Container model and constraints

Five non-obvious choices are load-bearing. Future template changes
must keep them intact or dionaea will silently exit on startup with
no log lines.

1. **Image tag: `:nightly`, not `:latest`.** `docker.io/dinotools/dionaea:latest`
   is frozen at the 2020-11-30 0.11.0 release and has not been rebuilt
   since. Its config tree is half-empty — many of the layout assumptions
   you'd make from reading the upstream source don't hold. `:nightly`
   is rebuilt daily by the upstream CI from the same 0.11.0 source plus
   current OS-package security fixes. Always pull `:nightly`.

2. **Per-service directory overlay, not a single-file overlay.** The
   image's bundled `/opt/dionaea/etc/dionaea/dionaea.cfg` (INI format)
   is what dionaea reads at startup. It globs `services-enabled/*.yaml`
   and `ihandlers-enabled/*.yaml`. Mounting a single `dionaea.yaml`
   anywhere does nothing — dionaea never reads that path. Lantana's
   Quadlet bind-mounts our `services-enabled/` and `ihandlers-enabled/`
   directories `:ro` over the bundled ones, replacing the image's
   default 16 services with our 6 and the default 6 ihandlers with just
   `log_json` (which is what the Vector pipeline consumes).

3. **`Environment=DIONAEA_FORCE_INIT_CONF=1` + `DIONAEA_FORCE_INIT_DATA=1`
   are required.** The image's entrypoint script seeds `dionaea.cfg`
   from `template/etc/` only if `/opt/dionaea/etc/dionaea/` doesn't
   exist. Our bind-mounts of `services-enabled/` and `ihandlers-enabled/`
   cause Podman to auto-create the parent dir, defeating that check.
   The two `FORCE_INIT` env vars override the check and force the seed
   to run every boot.

4. **Five specific capabilities must stay added.** The Quadlet starts
   from `DropCapability=ALL`, then adds back exactly what the bundled
   entrypoint needs:
   - `NET_BIND_SERVICE` — dionaea binds privileged ports (21, 80, 135,
     445) inside the container.
   - `SETUID` + `SETGID` — the entrypoint invokes
     `dionaea -u dionaea -g dionaea`, which calls `setuid()`/`setgid()`
     to drop from container-root to the `dionaea` user before binding
     non-privileged ports.
   - `CHOWN` + `FOWNER` — `init_lib`'s `cp -a` preserves ownership when
     seeding state dirs; without these the warnings flood stderr and
     downstream tasks misread the noise as failure.

   Without `SETUID`/`SETGID`, dionaea exits silently with status 133
   immediately after the `Starting dionaea ...` line, no traceback, no
   error log. That's the canary for a missing capability.

5. **`ReadOnly=true` is incompatible with this image.** The entrypoint
   has to write the seeded `dionaea.cfg` (and other config fixtures)
   into `/opt/dionaea/etc/dionaea/`. With `ReadOnly=true` enabled, the
   seed fails silently and dionaea launches with no config. Lantana's
   Quadlet does NOT set `ReadOnly=true` on the dionaea container;
   `DropCapability=ALL` + the explicit five-cap allowlist + rootless
   user namespace + `NoNewPrivileges=true` carry the containment load
   instead.

### ASCII-only constraint in service yamls

The image runs Python 3.6, whose `PyYAML` falls back to the ASCII
codec when reading files without a UTF-8 BOM. Any non-ASCII byte in
a `services-enabled/*.yaml` or `ihandlers-enabled/*.yaml` file
(em-dashes, arrows, smart quotes) triggers
`UnicodeDecodeError` deep inside `yaml.safe_load`, which causes the
*entire* service-registration loop to abort — not just the one bad
file. Effect: zero services bind, no clean error reaches stderr.

**All comment text and string values in `templates/services-enabled/*.yaml.j2`
and `templates/ihandlers-enabled/*.yaml.j2` must be 7-bit ASCII.** Use
`--` instead of `—`, `->` instead of `→`, straight quotes only. The
templates in `dionaea.container.j2` and `dionaea.nft.j2` are not
affected because systemd-Quadlet and nftables both handle UTF-8 fine.

### Default protocol surface

The full set of services Lantana enables in Dionaea is defined in
`config/ansible/roles/dionaea/defaults/main.yml` under
`dionaea_service_catalog`. As of v1.0.0:

| Protocol | External port | Container port | Notes |
|----------|---------------|----------------|-------|
| FTP      | 21            | 21             | Banner from `narrative.services.ftp.banner` |
| HTTP     | 80            | 80             | `Server:` header from `narrative.services.http.server_header`; serves the wwwroot persona page |
| EPMAP    | 135           | 135            | DCE/RPC endpoint mapper; no persona fields |
| SMB      | 445           | 445            | Workgroup / native OS / native LAN manager / server name from narrative |
| MSSQL    | 1433          | 1433           | Version string is hardcoded in the upstream module (v1.1 TODO) |
| MySQL    | 3306          | 3306           | Server version from `narrative.services.mysql.version` |

Dionaea has no native SSH (22) or Telnet (23) listener — those ports
belong exclusively to Cowrie.

**SIP intentionally disabled in v1.0.0.** The dinotools image's
privilege-drop model creates an unfixable ownership race on the SIP
module's `accounts.sqlite` (the root supervisor opens the file first,
the dionaea-user worker can't write to it post-drop). The
`templates/services-enabled/sip.yaml.j2` file is kept in the repo so a
future image fix lets us re-enable SIP by re-adding the catalog entry
in `roles/dionaea/defaults/main.yml`.

### Disabling a Dionaea sub-service on a running honeypot

Each service is a single YAML file under
`/etc/lantana/sensor/dionaea/services-enabled/`. To disable a service,
delete or rename its file and restart the container:

```bash
# Example: disable the EPMAP (DCE/RPC endpoint mapper) listener.
sudo mv /etc/lantana/sensor/dionaea/services-enabled/epmap.yaml \
        /etc/lantana/sensor/dionaea/services-enabled/epmap.yaml.disabled

# Restart Dionaea so it re-globs the services directory.
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 \
  systemctl --user restart dionaea.service
```

As with Cowrie, the honeywall's nftables DNAT for the now-disabled port
stays in place. Packets reach the sensor but get rejected by the
container's network stack (nothing's listening on the published port).
To clean up at the firewall too:

```bash
sudo $EDITOR /etc/lantana/honeywall/nftables/sensors/dionaea.nft
sudo systemctl reload nftables
```

Both changes are reverted on the next `deploy_honeypots.yml` run.

### Adding a new protocol permanently

Per-operation manual edits are not the right tool for "we want this
protocol off for every deploy of op_X" or "we want a new protocol
turned on." For those, edit the role:

- **Dionaea:** add (or remove) a catalog entry in
  `config/ansible/roles/dionaea/defaults/main.yml`, and drop a matching
  `templates/services/<svc>.yaml.j2` if adding. The Quadlet, nftables
  rules, and the validation playbook all derive from the catalog and
  pick up the change automatically.
- **Cowrie:** Cowrie's protocol surface is set by the upstream image
  and toggled via `cowrie.cfg.j2`. Edit the template and re-deploy.

## Validation

After any deploy, `tests/validate-single-node.yml` asserts:

1. Each honeypot listed in `sensor_honeypots` has its user-systemd
   `<honeypot>.service` reporting `active`.
2. Cowrie's TCP ports (2222, 2223) are listening on the sensor IP.
3. Dionaea's TCP ports (every `pub_port` in the catalog) are listening
   on the sensor IP.

If an operator has manually disabled a sub-service post-deploy, the
matching port-listening assertion will fail. That failure is the
intended signal that the host has drifted from the deployed baseline
and the next `deploy_honeypots.yml` run will revert the local change.

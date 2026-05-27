# Honeypots

Lantana ships two honeypots in v1.0.0: **Cowrie** (SSH + Telnet) and **Dionaea**
(SMB, FTP, HTTP, MSSQL, MySQL, EPMAP/DCERPC, SIP). Both run as rootless
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
| SIP      | 5060 TCP/UDP  | 5060 TCP/UDP   | Generic persona; no narrative integration |

Dionaea has no native SSH (22) or Telnet (23) listener — those ports
belong exclusively to Cowrie.

### Disabling a Dionaea sub-service on a running honeypot

Each service is a single YAML file under
`/etc/lantana/sensor/dionaea/services-enabled/`. To disable a service,
delete or rename its file and restart the container:

```bash
# Example: disable SIP on the running host.
sudo mv /etc/lantana/sensor/dionaea/services-enabled/sip.yaml \
        /etc/lantana/sensor/dionaea/services-enabled/sip.yaml.disabled

# Restart Dionaea so it re-globs the services directory.
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 \
  systemctl --user restart dionaea.service

# Confirm — SIP should no longer listen inside the container.
sudo -u stigma XDG_RUNTIME_DIR=/run/user/2001 \
  podman exec sensor-dionaea ss -lntu | grep -i 5060   # expect empty
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

---
name: deploy-sensors
description: >-
  Deployment and validation discipline for Lantana Ansible roles, Vector VRL
  merged-tree validation, Cowrie and Dionaea rootless Podman Quadlet containers,
  and post-deploy runtime verification playbooks. Load before editing Ansible
  roles, Vector configs, Quadlet templates, or running sensor deployments.
---

# Lantana Sensor, Vector & Quadlet Deployment Discipline (`deploy-sensors`)

Use this skill whenever editing or deploying Ansible roles (`config/ansible/roles/`), Vector configurations (`/etc/vector/`), Cowrie/Dionaea Quadlet `.container.j2` templates, or running sensor validation playbooks.

---

## 1. Vector Deployment Discipline (Merged-Tree Validation)

Vector configs span multiple files: `/etc/vector/vector.yaml` (main, with the keepalive blackhole sink) plus every `conf.d/*.yaml` (honeypot pipelines, firewall, receiver). Vector loads them as a single merged tree at startup, but `vector validate <file>` on a single `conf.d` file fails on `"No sinks defined"` — sinks live in `forward-honeywall.yaml` / `forward-sensor.yaml`, while sources and transforms live elsewhere.

A broken VRL fragment renders fine via Ansible's `template` module, the `Restart Vector` task succeeds (systemd starts the process), then Vector exits `78/CONFIG`, systemd's restart-on-failure policy kicks in, and you get a crashloop with zero source ingestion.

**Mandatory rule: Every Ansible role that renders a Vector config must `notify:` the merged-tree validate handler BEFORE the Vector restart fires.** The handler lives once in `roles/base/handlers/main.yml`:

```yaml
- name: "Validate Vector config tree"
  become: true
  ansible.builtin.shell: |
    set -e
    extra_files=$(find /etc/vector/conf.d -maxdepth 1 -name '*.yaml' 2>/dev/null || true)
    vector validate --no-environment /etc/vector/vector.yaml $extra_files
  changed_when: false
```

- `find` enumerates `conf.d` files rather than relying on a shell glob because on a **fresh install** the handler can fire from the base role before any `conf.d/*.yaml` has been templated (leaving `/etc/vector/conf.d/*.yaml` literal and crashing Vector with `78/CONFIG`).
- Order `notify: "Validate Vector config tree"` immediately after the render task and before `"Restart Vector"`.

---

## 2. Honeypot Container & Quadlet Invariants (Cowrie & Dionaea)

Several Cowrie and Dionaea decisions are load-bearing — reverting any of them causes silent failures (status `133`, zero bound ports, or lost TTY command logs). Full details live in `docs/honeypots.md` and `docs/troubleshooting.md`:

1. **Dionaea image is pinned to `docker.io/dinotools/dionaea:nightly`, never `:latest`:** `:latest` was frozen on 2020-11-30 with a half-empty config tree; `:nightly` is the actively rebuilt 0.11.0 tag.
2. **Per-service directory overlay (`services-enabled/<svc>.yaml`), not single-file:** Driven by `roles/dionaea/defaults/main.yml::dionaea_service_catalog` (single source of truth for per-service YAMLs, Quadlet `PublishPort` lines, nftables DNAT rules, and `validate-single-node.yml` port assertions).
3. **All Dionaea service YAML content must be 7-bit ASCII:** The dinotools image runs Python 3.6 + PyYAML, which falls back to ASCII without a BOM. Any non-ASCII byte (em-dash `—`, arrow `→`, smart quote) triggers `UnicodeDecodeError` and aborts the entire service-registration loop (zero ports bind). Use `--` and `->`.
4. **Five capabilities must stay added in Dionaea's Quadlet:** Drop all, then add `NET_BIND_SERVICE`, `SETUID`, `SETGID` (without these, entrypoint `-u dionaea -g dionaea` exits `133` silently), `CHOWN`, and `FOWNER`.
5. **`ReadOnly=true` is incompatible with Dionaea:** The entrypoint seeds configs into `/opt/dionaea/etc/dionaea/`. Keep `DIONAEA_FORCE_INIT_CONF=1` and `DIONAEA_FORCE_INIT_DATA=1` set so bind-mounts don't defeat the entrypoint's `test ! -d` seed check.
6. **SIP is intentionally absent from v1.0.0:** Hits an unfixable SQLite ownership race between supervisor (UID 0) and worker (`dionaea`). Keep `templates/services-enabled/sip.yaml.j2` dormant.
7. **Cowrie health check must use `HealthCmd=CMD python3 /healthcheck.py` (never `CMD-SHELL` or JSON array):** The Cowrie image has no `sh` or `nc`, and Podman 5.4.2 Quadlet misparses JSON arrays as a single-element string. Verify with `podman inspect sensor-cowrie --format "{{json .Config.Healthcheck.Test}}"` (must show `["CMD","python3","/healthcheck.py"]`).
8. **Cowrie ownership flows via `UserNS=keep-id:uid=999,gid=999`, never `,U`:** `,U` only chowns at initial volume creation and fails silently when upstream bumps container UIDs.
9. **Dionaea ownership flows from the entrypoint, never `,U` or `UserNS=keep-id`:** Dionaea runs a two-user runtime (supervisor UID 0, worker UID 1000). `,U` races the entrypoint by re-chowning files back to container root (`stigma`), leaving the worker unable to open `dionaea.json`.

---

## 3. Post-Deploy Validation Playbooks

Always verify deployments mechanically from `config/ansible/`:

1. **Base host & units (`validate-single-node.yml`):**
   ```bash
   ansible-playbook -i inventories/op_single/inventory.yml tests/validate-single-node.yml -vvv
   ```
   Asserts users, network, firewall, log directories, and the four `lantana-*.timer` + five `.service` units.
2. **Sensor runtime & bronze freshness (`validate-sensor-runtime.yml`, after ~30 s settle window):**
   ```bash
   ansible-playbook -i inventories/op_single/inventory.yml tests/validate-sensor-runtime.yml -vvv
   ```
   Asserts Cowrie/Dionaea Quadlet ownership (`UserNS=keep-id` for Cowrie, no `,U` for either), container health/restart counts, zero log-plugin tracebacks since `StartedAt`, open write FDs on `cowrie.json` / `dionaea.json`, fresh bronze NDJSON (`sensor_freshness_window_seconds`, default 120 s), and zero orphan-UID files.

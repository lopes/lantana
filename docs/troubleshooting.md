# Lantana Operations: Troubleshooting Guide

This document outlines standard operating procedures for debugging and troubleshooting the Lantana honeypot infrastructure.

---

## Podman Quadlets & Sensor Management

Lantana utilizes Podman Quadlets to manage honeypot sensors. Quadlets allow us to write declarative `.container` files that systemd automatically translates into native `.service` files.

Because sensors run under a dedicated, non-interactive service account, standard `systemctl` commands from an admin account will fail without proper environment context.

### The Management Wrapper Context

To interact with the container user's systemd session, we must explicitly pass the runtime directory and D-Bus session. Furthermore, running `sudo` from a directory this user cannot read (like `/home/lantana`) will result in an immediate `Permission denied` error due to how the kernel handles the Current Working Directory.

#### Always change to a neutral directory before debugging

```sh
cd /tmp
```

#### Export the necessary variables (or use the wrapper if deployed)

```sh
CONTAINER_USER="stigma" # Default service account for sensors
CONTAINER_UID=$(id -u $CONTAINER_USER)
CONTAINER_ENV="env XDG_RUNTIME_DIR=/run/user/$CONTAINER_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$CONTAINER_UID/bus"
```

### Common Operations

#### Reloading Quadlets (Required after modifying a `.container` file)

```sh
sudo -u $CONTAINER_USER $CONTAINER_ENV systemctl --user daemon-reload
```

#### Checking Sensor Status & Restarting

```sh
sudo -u $CONTAINER_USER $CONTAINER_ENV systemctl --user status cowrie.service
sudo -u $CONTAINER_USER $CONTAINER_ENV systemctl --user restart cowrie.service
```

#### Tailing Sensor Logs

Because the container is managed by the user's systemd daemon, logs are routed to the systemd journal for that specific user.

```sh
sudo -u $CONTAINER_USER $CONTAINER_ENV journalctl --user -u cowrie.service -f
```

### Storage and Permission Flags

When debugging volume mounts in the `.container` files, verify the correct flags are applied based on the use case:

- `UserNS=keep-id`: Maps the user running the container to the exact same UID inside the container. Essential for honeypots that write logs directly to host-mounted directories.
- `:Z`: SELinux/AppArmor private container security label. Prevents cross-container data leakage.
- `:U`: Podman automatically `chown`s the source directory on the host to match the container's internal UID/GID.

---

## Nftables Filtering & Routing

Lantana uses `nftables` for strict blast-radius containment and routing traffic to the rootless decoys.

### Viewing the Active Ruleset

To see exactly what is loaded into the kernel right now (including dynamic sets):

```sh
sudo nft list ruleset
```

### Live Packet Tracing

If a decoy is not receiving traffic, utilize nftables native tracing. First, add a trace rule to your prerouting chain:

```sh
sudo nft add rule inet filter prerouting ip saddr <YOUR_TEST_IP> meta nftrace set 1
```

Then, monitor the flow in real-time to see exactly which chain is dropping or accepting the packet:

```sh
sudo nft monitor trace
```

### Debugging Dual-Stack

Ensure your rules use the `inet` family to cover both IPv4 and IPv6. If IPv6 is failing, verify your rules aren't explicitly matching `ip daddr` (IPv4 only) instead of `ip6 daddr` or generic port matches.

---

## Suricata Intrusion Detection

Suricata monitors the honeypot interfaces to provide out-of-band detection and telemetry enrichment.

### Validating Configuration Syntax

Before restarting Suricata, always test the YAML configuration and rule syntax:

```sh
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### Live Reloading Rules

Do not restart the Suricata service just to update rules, as this drops packets. Use the built-in command tool:

```sh
sudo suricatasc -c ruleset-reload
```

### Testing Signatures against PCAPs

If you need to verify if a Suricata rule correctly fires against a specific attack payload, test it offline against a packet capture using `jq` to parse the structured output:

```sh
sudo suricata -c /etc/suricata/suricata.yaml -r /tmp/test-attack.pcap -l /tmp/suricata-test-logs/
cat /tmp/suricata-test-logs/eve.json | jq 'select(.event_type=="alert")'
```

---

## Systemd & Debian Core

### Verifying Lingering

If containers fail to start on boot, verify that lingering is actually enabled for the service account. A directory matching the user's name should exist in `/var/lib/systemd/linger/`:

```sh
ls -l /var/lib/systemd/linger/$CONTAINER_USER
```

### Checking Global System State

If the Debian host is acting erratically, check for degraded units. This is often the fastest way to find a failing mount or crashed agent.

```sh
systemctl --failed
```

### Ansible Fact Caching Issues

If Ansible is acting on outdated host data during playbook runs, clear the fact cache manually on the control node or force fact gathering:

```sh
ansible-playbook site.yml -e "ansible_facts_parallel=false" --flush-cache
```

### Ansible Debug Task

Whenever a task is failing due to variable errors, you can add the following task before the one that's failing to check out the values:

```yaml
- name: "Debug variable"
  debug:
    var: network # replace by the variable you're debugging
```

---

## Tests

In an "as-code" project, the usual workflow is:

1. Update the code with the changes you want to see.
2. Run deployment playbooks to apply changes in the environment.
3. Check the new behavior.

No more script-oriented manual patching. It is all defined in the code.

> [!WARNING]
> The only exception to this workflow is when you must rapidly test or debug specific behaviors directly on the sensor. If you manually alter configurations outside of Ansible to test a hypothesis, that node is now **tainted**. Once testing is complete, the node must be reprovisioned to eliminate state drift.

### Testing SSH Honeypots

SSH honeypots will usually accept almost any public key offered to them, allowing automatic login.

Use the command below to test SSH connections to decoys. It explicitly disables key exchange mechanisms and known-hosts checks, ensuring you do not mix real workstation configurations with the test environment, nor accidentally leak your real SSH identities to the honeypot:

```sh
ssh -o PubkeyAuthentication=no -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -v -6 root@fd99:10:50:99::100 -p 60090
```

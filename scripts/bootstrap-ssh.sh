#!/bin/sh
# Bootstrap SSH hardening on a fresh Debian VPS.
# Connects as an existing sudo user on port 22, creates the lantana admin
# user, injects an SSH public key, hardens sshd, and restarts the daemon.
#
# Arguments:
#   $1  HOST     Remote host IP or hostname (required)
#   $2  KEY      Path to SSH private key for initial connection (required)
#   $3  SSH_PORT SSH port to configure on the remote host (required)
#
# Example:
#   scripts/bootstrap-ssh.sh 203.0.113.10 ~/.ssh/id_ed25519 60090

set -eu

HOST="${1:?Usage: $0 <host> <key> <ssh_port>}"
KEY="${2:?Usage: $0 <host> <key> <ssh_port>}"
SSH_PORT="${3:?Usage: $0 <host> <key> <ssh_port>}"

PUBKEY_FILE="${KEY}.pub"

if [ ! -f "$KEY" ]; then
  echo "Error: private key not found: $KEY" >&2
  exit 1
fi

if [ ! -f "$PUBKEY_FILE" ]; then
  echo "Error: public key not found: $PUBKEY_FILE" >&2
  exit 1
fi

PUBKEY="$(cat "$PUBKEY_FILE")"

echo "=== Lantana SSH Bootstrap ==="
echo "Host:     $HOST (connecting on port 22)"
echo "Key:      $KEY"
echo "Pubkey:   $PUBKEY_FILE"
echo "SSH port: $SSH_PORT (will be configured on remote)"
echo ""
echo "Bootstrapping remote host ..."
echo ""

ssh -p 22 -i "$KEY" "$HOST" << REMOTE
set -eu

# Create lantana admin user
if ! id lantana >/dev/null 2>&1; then
  sudo useradd -m -s /bin/bash -G sudo lantana
  echo "Created user: lantana"
else
  echo "User lantana already exists"
fi

# Passwordless sudo
if [ ! -f /etc/sudoers.d/lantana ]; then
  echo 'lantana ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/lantana >/dev/null
  sudo chmod 0440 /etc/sudoers.d/lantana
  echo "Configured passwordless sudo"
fi

# Inject SSH public key
sudo mkdir -p /home/lantana/.ssh
echo '$PUBKEY' | sudo tee /home/lantana/.ssh/authorized_keys >/dev/null
sudo chmod 700 /home/lantana/.ssh
sudo chmod 600 /home/lantana/.ssh/authorized_keys
sudo chown -R lantana:lantana /home/lantana/.ssh
echo "Injected SSH public key"

# Hardened sshd config
sudo tee /etc/ssh/sshd_config.d/00-lantana.conf >/dev/null << SSHD
Port $SSH_PORT
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
ChallengeResponseAuthentication no
AuthenticationMethods publickey
X11Forwarding no
SSHD
echo "Wrote sshd hardening config (port $SSH_PORT)"

# Validate and restart
sudo sshd -t
sudo systemctl restart sshd
echo "sshd restarted on port $SSH_PORT"
REMOTE

echo ""
echo "=== Bootstrap complete ==="
echo ""
echo "Verify with:"
echo "  ssh -p $SSH_PORT -i $KEY lantana@$HOST 'id && uname -a'"

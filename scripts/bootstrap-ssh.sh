#!/bin/sh
# Bootstrap SSH hardening on a fresh Debian VPS.
# Connects as an existing sudo user on port 22, creates the lantana admin
# user, injects an SSH public key, hardens sshd, and restarts the daemon.
#
# Arguments:
#   $1  HOST     Remote host IP or hostname (required)
#   $2  SSH_USER Existing sudo user on the remote host for initial connection (required)
#   $3  KEY      Path to SSH private key for initial connection (required)
#   $4  SSH_PORT SSH port to configure on the remote host (required)
#
# Example:
#   scripts/bootstrap-ssh.sh 203.0.113.10 debian ~/.ssh/id_ed25519 60090

set -eu

HOST="${1:?Usage: $0 <host> <ssh_user> <key> <ssh_port>}"
SSH_USER="${2:?Usage: $0 <host> <ssh_user> <key> <ssh_port>}"
KEY="${3:?Usage: $0 <host> <ssh_user> <key> <ssh_port>}"
SSH_PORT="${4:?Usage: $0 <host> <ssh_user> <key> <ssh_port>}"

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
echo "Host:     $SSH_USER@$HOST (connecting on port 22)"
echo "Key:      $KEY"
echo "Pubkey:   $PUBKEY_FILE"
echo "SSH port: $SSH_PORT (will be configured on remote)"
echo ""
echo "Bootstrapping remote host ..."
echo ""

ssh -p 22 -i "$KEY" "${SSH_USER}@${HOST}" << REMOTE
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

# Comment out any active Port 22 in main sshd_config (some cloud images set it explicitly)
sudo sed -i -E 's/^[[:space:]]*Port[[:space:]]+22[[:space:]]*$/#&/' /etc/ssh/sshd_config

# Hardened sshd config (sole Port directive => sshd listens only on the custom port)
sudo tee /etc/ssh/sshd_config.d/00-lantana.conf >/dev/null << SSHD
Port $SSH_PORT
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
ChallengeResponseAuthentication no
AuthenticationMethods publickey
X11Forwarding no
SSHD
echo "Wrote sshd hardening config (port $SSH_PORT, port 22 disabled)"

# Disable socket activation (ssh.socket overrides the Port directive on Debian 13)
if systemctl list-unit-files ssh.socket >/dev/null 2>&1; then
  sudo systemctl disable --now ssh.socket
  echo "Disabled ssh.socket (was overriding Port directive)"
fi

# Validate and restart the ssh service (Debian uses 'ssh', not 'sshd')
sudo sshd -t
sudo systemctl enable ssh.service
sudo systemctl restart ssh.service
echo "ssh.service restarted on port $SSH_PORT"
REMOTE

echo ""
echo "=== Bootstrap complete ==="
echo ""
echo "Verify with:"
echo "  ssh -p $SSH_PORT -i $KEY lantana@$HOST 'id && uname -a'"

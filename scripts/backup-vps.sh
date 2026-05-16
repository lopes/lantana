#!/bin/sh
# Back up all Lantana data from a remote VPS before wipe/rebuild.
# Downloads /etc/lantana, /var/log/lantana, /var/lib/lantana via tar-over-SSH.
#
# Arguments:
#   $1  HOST     Remote host IP or hostname (required)
#   $2  SSH_USER SSH user on the remote host (required)
#   $3  KEY      Path to SSH private key (required)
#   $4  PORT     SSH port on the remote host (required)
#   $5  DEST     Local destination directory (required)
#
# Example:
#   scripts/backup-vps.sh 203.0.113.10 lantana ~/.ssh/id_ed25519 60090 ./backups/pre-wipe

set -eu

HOST="${1:?Usage: $0 <host> <ssh_user> <key> <port> <dest>}"
SSH_USER="${2:?Usage: $0 <host> <ssh_user> <key> <port> <dest>}"
KEY="${3:?Usage: $0 <host> <ssh_user> <key> <port> <dest>}"
PORT="${4:?Usage: $0 <host> <ssh_user> <key> <port> <dest>}"
DEST="${5:?Usage: $0 <host> <ssh_user> <key> <port> <dest>}"

if [ ! -f "$KEY" ]; then
  echo "Error: private key not found: $KEY" >&2
  exit 1
fi

mkdir -p "$DEST"

echo "=== Lantana VPS Backup ==="
echo "Host:  $SSH_USER@$HOST:$PORT"
echo "Key:   $KEY"
echo "Dest:  $DEST"
echo ""
echo "Streaming tar over SSH (sudo on remote) ..."
echo ""

ssh -p "$PORT" -i "$KEY" "${SSH_USER}@${HOST}" \
  "sudo tar cf - /etc/lantana /var/log/lantana /var/lib/lantana 2>/dev/null" \
  | tar xvf - -C "$DEST" --strip-components=1

echo ""
echo "=== Backup complete ==="
echo "Location: $DEST"
echo "---"
du -sh "$DEST/etc" "$DEST/var/log" "$DEST/var/lib" 2>/dev/null || true
echo "---"
du -sh "$DEST"

#!/bin/sh
# Back up all Lantana data from a remote VPS before wipe/rebuild.
# Downloads /etc/lantana, /var/log/lantana, /var/lib/lantana via tar-over-SSH.
#
# Arguments:
#   $1  HOST  Remote host IP or hostname (required)
#   $2  KEY   Path to SSH private key (required)
#   $3  PORT  SSH port on the remote host (required)
#   $4  DEST  Local destination directory (required)
#
# Example:
#   scripts/backup-vps.sh 203.0.113.10 ~/.ssh/id_ed25519 60090 ./backups/pre-wipe

set -eu

HOST="${1:?Usage: $0 <host> <key> <port> <dest>}"
KEY="${2:?Usage: $0 <host> <key> <port> <dest>}"
PORT="${3:?Usage: $0 <host> <key> <port> <dest>}"
DEST="${4:?Usage: $0 <host> <key> <port> <dest>}"

if [ ! -f "$KEY" ]; then
  echo "Error: private key not found: $KEY" >&2
  exit 1
fi

mkdir -p "$DEST"

echo "=== Lantana VPS Backup ==="
echo "Host:  $HOST:$PORT"
echo "Key:   $KEY"
echo "Dest:  $DEST"
echo ""
echo "Streaming tar over SSH (sudo on remote) ..."
echo ""

ssh -p "$PORT" -i "$KEY" "lantana@$HOST" \
  "sudo tar cf - /etc/lantana /var/log/lantana /var/lib/lantana 2>/dev/null" \
  | tar xvf - -C "$DEST" --strip-components=1

echo ""
echo "=== Backup complete ==="
echo "Location: $DEST"
echo "---"
du -sh "$DEST/etc" "$DEST/var/log" "$DEST/var/lib" 2>/dev/null || true
echo "---"
du -sh "$DEST"

#!/bin/sh
# Fetch ALL raw honeypot data from a Lantana VPS.
# Uses sudo+tar over SSH to capture logs and datalake, regardless of file ownership.
# Output lands in pipeline/tests/fixtures/live/ for integration tests.
#
# Arguments:
#   $1  HOST  Remote host IP or hostname (required)
#   $2  KEY   Path to SSH private key (required)
#   $3  PORT  SSH port on the remote host (required)
#
# Example:
#   scripts/fetch-vps-data.sh 203.0.113.10 ~/.ssh/id_ed25519 60090

set -eu

HOST="${1:?Usage: $0 <host> <key> <port>}"
KEY="${2:?Usage: $0 <host> <key> <port>}"
PORT="${3:?Usage: $0 <host> <key> <port>}"

if [ ! -f "$KEY" ]; then
  echo "Error: private key not found: $KEY" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="$SCRIPT_DIR/../pipeline/tests/fixtures/live"

mkdir -p "$DEST"

echo "=== Lantana VPS Data Fetch ==="
echo "Host:  lantana@$HOST:$PORT"
echo "Key:   $KEY"
echo "Dest:  $DEST"
echo ""
echo "Streaming tar over SSH (sudo on remote, verbose) ..."
echo ""

ssh -p "$PORT" -i "$KEY" "lantana@$HOST" \
  "sudo tar cf - /var/log/lantana /var/lib/lantana 2>/dev/null" \
  | tar xvf - -C "$DEST" --strip-components=1

echo ""
echo "=== Fetch complete ==="
echo "Data in: $DEST"
echo "---"
du -sh "$DEST/log" "$DEST/lib" 2>/dev/null || true
echo "---"
find "$DEST" -maxdepth 4 -type d 2>/dev/null

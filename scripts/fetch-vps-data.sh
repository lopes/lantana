#!/bin/sh
# Fetch ALL raw honeypot data from a Lantana VPS.
# Uses sudo+tar over SSH to capture everything regardless of file ownership.
#
# Usage: scripts/fetch-vps-data.sh [host] [port] [user] [key]

set -eu

HOST="${1:?Usage: $0 <host> [port] [user] [key]}"
PORT="${2:-60090}"
USER="${3:-debian}"
KEY="${4:-$HOME/.ssh/id_ed25519}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="$SCRIPT_DIR/../pipeline/tests/fixtures/live"

mkdir -p "$DEST"

echo "Host:  $USER@$HOST:$PORT"
echo "Key:   $KEY"
echo "Dest:  $DEST"
echo ""
echo "Streaming tar over SSH (sudo on remote, verbose) ..."
echo "You will see filenames as they are extracted."
echo ""

ssh -p "$PORT" -i "$KEY" "$USER@$HOST" \
  "sudo tar cf - /var/log/lantana /var/lib/lantana 2>/dev/null" \
  | tar xvf - -C "$DEST" --strip-components=1

echo ""
echo "Done. Data in: $DEST"
echo "---"
du -sh "$DEST/log" "$DEST/lib" 2>/dev/null || true
echo "---"
find "$DEST" -maxdepth 4 -type d 2>/dev/null

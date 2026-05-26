#!/usr/bin/env bash
# Test upload rate limiting end-to-end.
#
# Usage:
#   PEER=1.2.3.4 PORT=9999 RATE=1048576 BURST=2097152 SIZE_MB=100 ./test-upload.sh
#
# Prereqs:
#   - qos service running on this machine, attached to the egress interface
#   - python3 recv.py running on $PEER:$PORT
#   - socat, curl, dd installed locally
set -euo pipefail

PEER="${PEER:?PEER is required (remote receiver IP)}"
PORT="${PORT:-9999}"
RATE="${RATE:-1048576}"        # 1 MB/s default
BURST="${BURST:-2097152}"      # 2 MB default
SIZE_MB="${SIZE_MB:-100}"
SOCK="${SOCK:-/var/run/qos.sock}"
FILE="${FILE:-/tmp/upload.bin}"
URL="http://${PEER}:${PORT}/upload"

if [[ ! -f "$FILE" ]]; then
  echo "[setup] creating ${SIZE_MB}MB test file at $FILE"
  dd if=/dev/zero of="$FILE" bs=1M count="$SIZE_MB" status=none
fi

run_curl() {
  local label=$1
  echo "=== $label ==="
  curl -sS -T "$FILE" -o /dev/null \
    -w "  speed_upload: %{speed_upload} B/s   time: %{time_total}s\n" \
    "$URL"
}

send_cmd() {
  local cmd=$1
  echo "  $cmd"
  echo "$cmd" | sudo socat - "UNIX-CONNECT:$SOCK"
}

echo "PEER=$PEER PORT=$PORT RATE=$RATE BURST=$BURST SIZE=${SIZE_MB}MB"
echo

run_curl "baseline (no rule)"
echo

echo "=== add upload rule ==="
send_cmd "{\"command\":\"add\",\"ip\":\"${PEER}/32\",\"rate\":${RATE},\"burst\":${BURST},\"direction\":\"upload\"}"
echo

run_curl "with rate limit"
echo

echo "=== delete rule ==="
send_cmd "{\"command\":\"delete\",\"ip\":\"${PEER}/32\",\"direction\":\"upload\"}"
echo

run_curl "after delete (should match baseline)"

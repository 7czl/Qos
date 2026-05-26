#!/usr/bin/env bash
# docker-data-root.sh — Configure Docker to use a custom data-root directory.
#
# Default behavior:
#   1. Create the target data-root directory (default: /data/docker)
#   2. Merge {"data-root": "..."} into /etc/docker/daemon.json idempotently
#      (preserves any existing keys via python3 JSON merge)
#   3. Restart docker if it's running, or start+enable it if not
#   4. Validate that "Docker Root Dir" matches the target
#
# Usage:
#   sudo ./docker-data-root.sh                              # /data/docker
#   sudo ./docker-data-root.sh --root /mnt/big/docker
#   sudo ./docker-data-root.sh --root /data/docker --no-restart  # config only
#
# Notes:
#   - If Docker is already running with images/containers in the OLD data-root,
#     this script will NOT migrate that data. The daemon will start fresh under
#     the new path. Migrate manually with `rsync -aHAX OLD/ NEW/` BEFORE running
#     this script if you need to preserve images.
#   - SELinux: a custom data-root may need its label set; the script will run
#     `chcon -Rt container_var_lib_t` if SELinux is enforcing.
set -euo pipefail

DATA_ROOT="/data/docker"
DAEMON_JSON="/etc/docker/daemon.json"
RESTART=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)        DATA_ROOT="$2"; shift 2 ;;
    --daemon-json) DAEMON_JSON="$2"; shift 2 ;;
    --no-restart)  RESTART=0; shift ;;
    -h|--help)
      sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "error: this script must be run as root (use sudo)" >&2
  exit 1
fi

have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || { echo "error: missing required command: $1" >&2; exit 1; }; }

need systemctl
need python3

if ! have docker; then
  echo "error: docker is not installed. Install it first (e.g. yum install docker)" >&2
  exit 1
fi

echo "=== Docker data-root setup ==="
echo "  data-root:    $DATA_ROOT"
echo "  daemon.json:  $DAEMON_JSON"
echo "  restart:      $([[ $RESTART -eq 1 ]] && echo yes || echo no)"
echo

# --- Step 1: Stop docker so the new config takes effect cleanly ---
DOCKER_WAS_RUNNING=0
if systemctl is-active --quiet docker; then
  DOCKER_WAS_RUNNING=1
  if [[ "$RESTART" -eq 1 ]]; then
    echo "[1/5] Docker is running; stopping it before reconfiguring..."
    systemctl stop docker
  else
    echo "[1/5] Docker is running; --no-restart given so leaving it for now"
    echo "      NOTE: changes to data-root require a docker restart to take effect"
  fi
else
  echo "[1/5] Docker is not running"
fi

# --- Step 2: Create the data-root directory ---
echo
echo "[2/5] Creating $DATA_ROOT..."
mkdir -p "$DATA_ROOT"
chmod 711 "$DATA_ROOT"

# Try to set SELinux context if SELinux is enforcing. Failures are non-fatal
# because some systems don't have the container policy installed.
if have getenforce && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]] && have chcon; then
  echo "      SELinux is enforcing; applying container_var_lib_t label"
  chcon -Rt container_var_lib_t "$DATA_ROOT" 2>/dev/null || \
    echo "      (chcon failed — may need 'sudo dnf install -y container-selinux')"
fi

# --- Step 3: Merge data-root into /etc/docker/daemon.json ---
echo
echo "[3/5] Updating $DAEMON_JSON..."
mkdir -p "$(dirname "$DAEMON_JSON")"

# Backup before mutating, but only on first run.
if [[ -f "$DAEMON_JSON" && ! -f "${DAEMON_JSON}.orig" ]]; then
  cp "$DAEMON_JSON" "${DAEMON_JSON}.orig"
  echo "      backed up -> ${DAEMON_JSON}.orig"
fi

# Use python3 to merge so existing keys are preserved.
python3 - "$DAEMON_JSON" "$DATA_ROOT" <<'PYEOF'
import json
import os
import sys

path, data_root = sys.argv[1], sys.argv[2]

config = {}
if os.path.exists(path):
    with open(path) as f:
        text = f.read().strip()
    if text:
        try:
            config = json.loads(text)
        except json.JSONDecodeError as e:
            print(f"error: existing {path} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)
        if not isinstance(config, dict):
            print(f"error: {path} top-level must be a JSON object", file=sys.stderr)
            sys.exit(1)

config["data-root"] = data_root

with open(path, "w") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PYEOF

chmod 644 "$DAEMON_JSON"
echo "      content:"
sed 's/^/      /' "$DAEMON_JSON"

# --- Step 4: Start/restart docker and enable on boot ---
echo
echo "[4/5] Starting docker..."
systemctl enable docker >/dev/null 2>&1 || true
if [[ "$RESTART" -eq 1 ]] || [[ "$DOCKER_WAS_RUNNING" -eq 0 ]]; then
  systemctl start docker
  # Give the daemon a moment to come up
  for _ in 1 2 3 4 5; do
    if docker info >/dev/null 2>&1; then break; fi
    sleep 1
  done
fi

# --- Step 5: Validate ---
echo
echo "[5/5] Validating..."
ACTUAL_ROOT="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
if [[ -z "$ACTUAL_ROOT" ]]; then
  echo "error: docker info failed — is the daemon running?" >&2
  systemctl --no-pager status docker | tail -10 || true
  exit 1
fi

if [[ "$ACTUAL_ROOT" == "$DATA_ROOT" ]]; then
  echo "      Docker Root Dir: $ACTUAL_ROOT  ✓"
else
  echo "warning: Docker Root Dir is '$ACTUAL_ROOT', expected '$DATA_ROOT'" >&2
  if [[ "$RESTART" -eq 0 ]]; then
    echo "         (you used --no-restart; restart docker for changes to apply)" >&2
  fi
  exit 1
fi

echo
echo "=== Done ==="
docker info 2>/dev/null | grep -E 'Docker Root Dir|Storage Driver|Server Version'

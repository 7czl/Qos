#!/usr/bin/env bash
# install.sh — One-shot installer for the QoS eBPF rate limiter.
#
# Downloads the qos binary from GitHub releases, generates and installs
# the systemd units and helper scripts, and starts the service.
#
# Usage:
#   sudo bash install.sh
#   sudo bash install.sh --iface eth0           # specify interface (default: ens5)
#   sudo bash install.sh --version v0.4.0       # specify release version
#   sudo bash install.sh --binary /tmp/qos      # use a local binary instead of downloading
#
# Quick install (no clone needed):
#   curl -fsSL https://raw.githubusercontent.com/7czl/Qos/main/deploy/install.sh \
#     | sudo bash
set -euo pipefail

# --- Defaults ---
RELEASE_URL_BASE="https://github.com/7czl/Qos/releases/download"
VERSION="v0.4.0"
IFACE="ens5"
SOCKET_PATH="/var/run/qos.sock"
LOCAL_BINARY=""

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)      VERSION="$2"; shift 2 ;;
    --iface)        IFACE="$2"; shift 2 ;;
    --socket-path)  SOCKET_PATH="$2"; shift 2 ;;
    --binary)       LOCAL_BINARY="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
  echo "error: this script must be run as root (use sudo)" >&2
  exit 1
fi

# --- Prereq check ---
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || { echo "error: missing required command: $1" >&2; exit 1; }; }

need curl
need systemctl
need install
need python3

echo "=== QoS Rate Limiter Installer ==="
echo "  version:     $VERSION"
echo "  interface:   $IFACE"
echo "  socket:      $SOCKET_PATH"
echo

# --- Step 1: Stop existing services (if upgrading) ---
echo "[1/7] Stopping existing services (if any)..."
systemctl stop qos-rules 2>/dev/null || true
systemctl stop qos 2>/dev/null || true

# --- Step 2: Get the binary ---
echo "[2/7] Installing qos binary to /usr/local/bin/qos..."
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [[ -n "$LOCAL_BINARY" ]]; then
  if [[ ! -f "$LOCAL_BINARY" ]]; then
    echo "error: --binary path not found: $LOCAL_BINARY" >&2
    exit 1
  fi
  cp "$LOCAL_BINARY" "$TMPDIR/qos"
else
  URL="${RELEASE_URL_BASE}/${VERSION}/qos"
  echo "      downloading $URL"
  curl -fsSL -o "$TMPDIR/qos" "$URL"
fi

install -m 755 "$TMPDIR/qos" /usr/local/bin/qos

# Restore SELinux context (no-op if SELinux is disabled or restorecon is missing).
# Required on RHEL/Fedora/Amazon Linux when SELinux is enforcing — without this,
# systemd may fail to exec the binary with "Permission denied".
if have restorecon; then
  restorecon -v /usr/local/bin/qos || true
fi

echo "      $(/usr/local/bin/qos --help 2>&1 | head -1 || true)"

# --- Step 3: Install qos-load-rules helper ---
echo "[3/7] Installing /usr/local/bin/qos-load-rules..."
cat > /usr/local/bin/qos-load-rules <<'PYEOF'
#!/usr/bin/env python3
"""Load persistent QoS rules from a JSON file via the UDS control socket."""
import json
import os
import socket
import sys
import time

RULES_FILE = sys.argv[1] if len(sys.argv) > 1 else "/etc/qos/rules.json"
SOCK_PATH = os.environ.get("QOS_SOCK", "/var/run/qos.sock")
WAIT_TIMEOUT_S = 15


def wait_for_socket(path: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.2)
    return False


def main() -> int:
    if not os.path.exists(RULES_FILE):
        print(f"[qos-load-rules] no rules file at {RULES_FILE}, nothing to do",
              file=sys.stderr)
        return 0

    with open(RULES_FILE) as f:
        rules = json.load(f)

    if not isinstance(rules, list):
        print(f"[qos-load-rules] {RULES_FILE} must contain a JSON array",
              file=sys.stderr)
        return 1

    if not wait_for_socket(SOCK_PATH, WAIT_TIMEOUT_S):
        print(f"[qos-load-rules] timed out waiting for {SOCK_PATH}", file=sys.stderr)
        return 1

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK_PATH)
    rw = s.makefile("rwb", buffering=0)

    failures = 0
    for rule in rules:
        rw.write((json.dumps(rule) + "\n").encode())
        resp_line = rw.readline()
        if not resp_line:
            print(f"[qos-load-rules] connection closed unexpectedly", file=sys.stderr)
            failures += 1
            break
        resp = json.loads(resp_line)
        ip = rule.get("ip", "<list>")
        direction = rule.get("direction", "download")
        status = resp.get("status")
        msg = resp.get("message", "")
        if status == "ok":
            print(f"[qos-load-rules] OK    {direction:>8}  {ip}", file=sys.stderr)
        else:
            print(f"[qos-load-rules] FAIL  {direction:>8}  {ip}  -> {msg}",
                  file=sys.stderr)
            failures += 1

    rw.close()
    s.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF
chmod 755 /usr/local/bin/qos-load-rules

# --- Step 4: Generate qos.service ---
echo "[4/7] Writing /etc/systemd/system/qos.service..."
cat > /etc/systemd/system/qos.service <<EOF
[Unit]
Description=QoS - eBPF Rate Limiter (upload + download)
Documentation=https://github.com/7czl/Qos
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/qos --iface ${IFACE} --socket-path ${SOCKET_PATH}

# Log level: info by default. Change to debug/warn/error as needed.
Environment=RUST_LOG=info

# Run as root (required for eBPF)
User=root
Group=root

# Cleanup: remove the UDS socket file on stop. The eBPF programs and TC
# filters detach automatically when the process exits.
ExecStopPost=-/usr/bin/rm -f ${SOCKET_PATH}

# Restart policy
Restart=on-failure
RestartSec=5

# eBPF / kernel capabilities required to load and attach TC programs.
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_PERFMON

# eBPF maps require locked memory.
LimitMEMLOCK=infinity

NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF

# --- Step 5: Generate qos-rules.service ---
echo "[5/7] Writing /etc/systemd/system/qos-rules.service..."
cat > /etc/systemd/system/qos-rules.service <<'EOF'
[Unit]
Description=Load persistent QoS rules
Documentation=https://github.com/7czl/Qos
After=qos.service
Requires=qos.service
ConditionPathExists=/etc/qos/rules.json

[Service]
Type=oneshot
ExecStart=/usr/local/bin/qos-load-rules /etc/qos/rules.json
RemainAfterExit=yes
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# --- Step 6: Set up /etc/qos/ ---
echo "[6/7] Setting up /etc/qos/..."
mkdir -p /etc/qos
if [[ ! -f /etc/qos/rules.json ]]; then
  cat > /etc/qos/rules.json <<'EOF'
[
  {
    "command": "add",
    "ip": "10.0.0.0/8",
    "rate": 1048576,
    "burst": 2097152,
    "direction": "download"
  }
]
EOF
  chmod 644 /etc/qos/rules.json
  echo "      Created /etc/qos/rules.json (default example, edit as needed)"
else
  echo "      /etc/qos/rules.json already exists, not overwriting"
fi

# --- Step 7: Enable and start ---
echo "[7/7] Enabling and starting services..."
systemctl enable qos.service >/dev/null
systemctl enable qos-rules.service >/dev/null
systemctl start qos.service
sleep 1
systemctl start qos-rules.service || {
  echo "warning: qos-rules.service failed to start" >&2
  systemctl --no-pager status qos-rules.service | tail -10 || true
}

echo
echo "=== Installation complete ==="
echo
systemctl --no-pager status qos.service | head -5 || true
echo
systemctl --no-pager status qos-rules.service | head -5 || true
echo
echo "Useful commands:"
echo "  sudo systemctl status qos                  # service status"
echo "  sudo journalctl -u qos -f                  # live logs"
echo "  sudo vi /etc/qos/rules.json                # edit persistent rules"
echo "  sudo systemctl restart qos-rules           # reload rules from file"
echo "  echo '{\"command\":\"list\"}' | sudo socat - UNIX-CONNECT:${SOCKET_PATH}"

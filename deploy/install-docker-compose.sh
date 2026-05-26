#!/usr/bin/env bash
# install-docker-compose.sh — Install the docker-compose CLI plugin.
#
# Downloads the standalone docker-compose binary from GitHub releases.
# Idempotent: if the requested version is already installed, exits early.
#
# Usage:
#   sudo ./install-docker-compose.sh                          # latest stable
#   sudo ./install-docker-compose.sh --version v2.29.7        # pin a version
#   sudo ./install-docker-compose.sh --prefix /usr/bin        # custom install dir
#   sudo ./install-docker-compose.sh --as-plugin              # install as docker CLI plugin
#
# After install:
#   docker-compose --version                                  # standalone usage
#   docker compose --version                                  # if --as-plugin was used
set -euo pipefail

VERSION="latest"
PREFIX="/usr/local/bin"
AS_PLUGIN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    VERSION="$2"; shift 2 ;;
    --prefix)     PREFIX="$2"; shift 2 ;;
    --as-plugin)  AS_PLUGIN=1; shift ;;
    -h|--help)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
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

need curl
need uname

OS="$(uname -s)"     # Linux / Darwin
ARCH="$(uname -m)"   # x86_64 / aarch64
echo "=== docker-compose installer ==="
echo "  version:   $VERSION"
echo "  os/arch:   ${OS}/${ARCH}"

# Resolve installation target
if [[ "$AS_PLUGIN" -eq 1 ]]; then
  # Standard CLI plugin location for system-wide installs
  TARGET_DIR="/usr/libexec/docker/cli-plugins"
  TARGET_NAME="docker-compose"
  echo "  target:    ${TARGET_DIR}/${TARGET_NAME} (CLI plugin)"
else
  TARGET_DIR="$PREFIX"
  TARGET_NAME="docker-compose"
  echo "  target:    ${TARGET_DIR}/${TARGET_NAME} (standalone)"
fi
echo

# Build download URL
if [[ "$VERSION" == "latest" ]]; then
  URL="https://github.com/docker/compose/releases/latest/download/docker-compose-${OS}-${ARCH}"
else
  URL="https://github.com/docker/compose/releases/download/${VERSION}/docker-compose-${OS}-${ARCH}"
fi

# --- Step 1: Skip if already installed at the requested version ---
TARGET_PATH="${TARGET_DIR}/${TARGET_NAME}"
if [[ -x "$TARGET_PATH" ]] && [[ "$VERSION" != "latest" ]]; then
  CURRENT="$("$TARGET_PATH" version --short 2>/dev/null || true)"
  WANTED="${VERSION#v}"
  if [[ "$CURRENT" == "$WANTED" ]]; then
    echo "[skip] ${TARGET_NAME} ${CURRENT} already installed at ${TARGET_PATH}"
    exit 0
  fi
fi

# --- Step 2: Download to a temp file, then atomically install ---
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "[1/3] Downloading ${URL}..."
curl -fsSL -o "${TMPDIR}/docker-compose" "$URL"

# Sanity check: file should be > 1MB (compose binary is ~60MB)
SIZE=$(wc -c < "${TMPDIR}/docker-compose")
if [[ "$SIZE" -lt 1048576 ]]; then
  echo "error: downloaded file is suspiciously small (${SIZE} bytes)" >&2
  echo "       download URL: $URL" >&2
  exit 1
fi

# --- Step 3: Install ---
echo "[2/3] Installing to ${TARGET_PATH}..."
mkdir -p "$TARGET_DIR"
install -m 755 "${TMPDIR}/docker-compose" "$TARGET_PATH"

# Restore SELinux context if applicable
if have restorecon; then
  restorecon -v "$TARGET_PATH" >/dev/null 2>&1 || true
fi

# --- Step 4: Verify ---
echo "[3/3] Verifying..."
if [[ "$AS_PLUGIN" -eq 1 ]]; then
  # Plugin mode: invoke via `docker compose`
  if have docker; then
    INSTALLED_VERSION=$(docker compose version --short 2>/dev/null || true)
  else
    INSTALLED_VERSION=$("$TARGET_PATH" version --short 2>/dev/null || true)
    echo "      (docker not installed; verified via direct invocation)"
  fi
else
  INSTALLED_VERSION=$("$TARGET_PATH" version --short 2>/dev/null || true)
fi

if [[ -z "$INSTALLED_VERSION" ]]; then
  echo "error: installation succeeded but binary failed to report version" >&2
  echo "       try running: $TARGET_PATH --version" >&2
  exit 1
fi

echo "      docker-compose ${INSTALLED_VERSION}  ✓"
echo
echo "=== Done ==="
if [[ "$AS_PLUGIN" -eq 1 ]]; then
  echo "Use:  docker compose <command>"
else
  echo "Use:  docker-compose <command>"
fi

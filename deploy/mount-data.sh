#!/usr/bin/env bash
# mount-data.sh — Format and persistently mount a block device.
#
# Default action:
#   1. Verify the target device exists and is not already mounted
#   2. If the device has NO existing filesystem, format it as XFS
#      (refuses to overwrite existing filesystems unless --force is given)
#   3. Create the mount point
#   4. Add an /etc/fstab entry by UUID (idempotent — won't duplicate)
#   5. Run `mount -a` and show the result
#
# Usage:
#   sudo ./mount-data.sh                                    # /dev/nvme1n1 -> /data, xfs
#   sudo ./mount-data.sh --device /dev/nvme1n1 --mount /data
#   sudo ./mount-data.sh --device /dev/sdb --mount /var/lib/docker --fs ext4
#   sudo ./mount-data.sh --force                            # reformat existing FS (DESTRUCTIVE)
#
# WARNING:
#   mkfs is DESTRUCTIVE. This script refuses to format a device that already
#   contains a filesystem unless --force is explicitly passed. Always verify
#   the target device with `lsblk` first.
set -euo pipefail

DEVICE="/dev/nvme1n1"
MOUNT="/data"
FS_TYPE="xfs"
MOUNT_OPTS="defaults,nofail"
FSTAB_DUMP=0
FSTAB_PASS=2
FORCE=0

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --device)      DEVICE="$2"; shift 2 ;;
    --mount)       MOUNT="$2"; shift 2 ;;
    --fs)          FS_TYPE="$2"; shift 2 ;;
    --opts)        MOUNT_OPTS="$2"; shift 2 ;;
    --force)       FORCE=1; shift ;;
    -h|--help)
      sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
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

need lsblk
need blkid
need mkfs."$FS_TYPE"
need mount

echo "=== Block Device Setup ==="
echo "  device:  $DEVICE"
echo "  mount:   $MOUNT"
echo "  fs:      $FS_TYPE"
echo "  opts:    $MOUNT_OPTS"
echo

# --- Step 1: Verify device exists and is a block device ---
echo "[1/6] Checking device..."
if [[ ! -b "$DEVICE" ]]; then
  echo "error: $DEVICE is not a block device" >&2
  echo
  echo "Available block devices:"
  lsblk
  exit 1
fi

# Show what we're about to touch
lsblk "$DEVICE"

# --- Step 2: Refuse to operate on a device that's already in use ---
echo
echo "[2/6] Checking if device is already mounted..."
if findmnt --source "$DEVICE" >/dev/null 2>&1; then
  CURRENT_MOUNT=$(findmnt -no TARGET --source "$DEVICE")
  if [[ "$CURRENT_MOUNT" == "$MOUNT" ]]; then
    echo "      $DEVICE is already mounted at $MOUNT — verifying fstab entry only"
  else
    echo "error: $DEVICE is already mounted at $CURRENT_MOUNT (expected $MOUNT)" >&2
    echo "       refusing to operate on a mounted device" >&2
    exit 1
  fi
fi

# --- Step 3: Detect existing filesystem and decide whether to format ---
echo
echo "[3/6] Detecting existing filesystem..."
EXISTING_FS=$(blkid -o value -s TYPE "$DEVICE" 2>/dev/null || true)
if [[ -n "$EXISTING_FS" ]]; then
  echo "      device already has filesystem: $EXISTING_FS"
  if [[ "$FORCE" -eq 1 ]]; then
    echo "      --force given, will reformat as $FS_TYPE (DATA WILL BE LOST)"
    read -p "      type the device path '$DEVICE' to confirm: " CONFIRM
    if [[ "$CONFIRM" != "$DEVICE" ]]; then
      echo "error: confirmation mismatch, aborting" >&2
      exit 1
    fi
    mkfs -t "$FS_TYPE" -f "$DEVICE"
  else
    echo "      keeping existing filesystem (use --force to reformat)"
    if [[ "$EXISTING_FS" != "$FS_TYPE" ]]; then
      echo "warning: existing fs ($EXISTING_FS) differs from requested fs ($FS_TYPE)" >&2
      echo "         fstab entry will use existing fs type ($EXISTING_FS)" >&2
      FS_TYPE="$EXISTING_FS"
    fi
  fi
else
  echo "      no filesystem detected, formatting as $FS_TYPE..."
  mkfs -t "$FS_TYPE" "$DEVICE"
fi

# --- Step 4: Create mount point and ensure it's a directory ---
echo
echo "[4/6] Creating mount point $MOUNT..."
mkdir -p "$MOUNT"

# --- Step 5: Get UUID and update /etc/fstab idempotently ---
echo
echo "[5/6] Updating /etc/fstab..."
UUID=$(blkid -o value -s UUID "$DEVICE")
if [[ -z "$UUID" ]]; then
  echo "error: could not read UUID for $DEVICE" >&2
  exit 1
fi
echo "      UUID=$UUID"

# Backup fstab on first run
if [[ ! -f /etc/fstab.orig ]]; then
  cp /etc/fstab /etc/fstab.orig
  echo "      backed up /etc/fstab -> /etc/fstab.orig"
fi

FSTAB_LINE="UUID=$UUID  $MOUNT  $FS_TYPE  $MOUNT_OPTS  $FSTAB_DUMP $FSTAB_PASS"

# Idempotent update: if a line for this UUID or this mount point exists, replace it.
if grep -qE "^[[:space:]]*UUID=${UUID}[[:space:]]" /etc/fstab; then
  echo "      fstab entry for UUID=$UUID already exists, replacing"
  sed -i.bak "/^[[:space:]]*UUID=${UUID}[[:space:]]/d" /etc/fstab
elif grep -qE "[[:space:]]${MOUNT}[[:space:]]" /etc/fstab; then
  echo "      fstab entry for mount $MOUNT already exists, replacing"
  sed -i.bak "\|[[:space:]]${MOUNT}[[:space:]]|d" /etc/fstab
fi

echo "$FSTAB_LINE" >> /etc/fstab
echo "      added: $FSTAB_LINE"

# --- Step 6: Mount and verify ---
echo
echo "[6/6] Mounting and verifying..."
# Unmount if mounted (so mount -a goes through fstab)
if findmnt --source "$DEVICE" --target "$MOUNT" >/dev/null 2>&1; then
  umount "$MOUNT"
fi
mount -a

if findmnt --source "$DEVICE" --target "$MOUNT" >/dev/null 2>&1; then
  echo "      successfully mounted $DEVICE at $MOUNT"
else
  echo "error: $DEVICE did not mount at $MOUNT after mount -a" >&2
  echo "       check /etc/fstab and dmesg for details" >&2
  exit 1
fi

echo
echo "=== Done ==="
df -hT "$MOUNT"

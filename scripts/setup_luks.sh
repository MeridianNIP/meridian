#!/usr/bin/env bash
# =====================================================================
# Meridian · Interactive LUKS volume setup for PostgreSQL data
# =====================================================================
# DESTRUCTIVE. Formats a whole block device. Run AFTER install.sh if you
# answered "yes" to the LUKS prompt and want to move postgres data onto
# the encrypted volume. Requires postgres to be stopped during migration.
#
# Usage:
#   sudo /opt/meridian/scripts/setup_luks.sh /dev/sdb
# =====================================================================

set -euo pipefail

C_RESET=$'\e[0m'; C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_CYAN=$'\e[36m'; C_BOLD=$'\e[1m'
info() { printf '%s[INFO]%s  %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s  %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
err()  { printf '%s[ERR ]%s  %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }

readonly MAPPER_NAME="meridian-pg"
readonly MOUNT_POINT="/var/lib/postgresql"
readonly PG_VERSION_DIR="${MOUNT_POINT}/15"

[[ $(id -u) -eq 0 ]] || die "must be root"
DEVICE=${1:-}
[[ -n "$DEVICE" ]] || die "usage: setup_luks.sh /dev/<device>"
[[ -b "$DEVICE" ]] || die "not a block device: $DEVICE"

for cmd in cryptsetup mkfs.ext4 rsync lsblk blkid systemctl; do
  command -v "$cmd" >/dev/null || die "missing prerequisite: $cmd"
done

# --- Confirmation ----------------------------------------------------
cat <<CAUTION

${C_BOLD}${C_RED}═══════════════════════════════════════════════════════════════════${C_RESET}
${C_BOLD}${C_RED}   DESTRUCTIVE OPERATION                                           ${C_RESET}
${C_BOLD}${C_RED}═══════════════════════════════════════════════════════════════════${C_RESET}

This script will:
  1. Stop PostgreSQL.
  2. ${C_RED}FORMAT ${DEVICE} — ALL DATA ON IT WILL BE DESTROYED.${C_RESET}
  3. Create a LUKS2 container on ${DEVICE}, open as /dev/mapper/${MAPPER_NAME}.
  4. Format it ext4, mount at ${MOUNT_POINT}.
  5. Copy existing PG data onto the encrypted volume.
  6. Add an fstab + crypttab entry so it unlocks at boot.
  7. Restart PostgreSQL.

Device info:
CAUTION
lsblk -no NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT "$DEVICE" || true
echo
read -rp "Type the full device path (${DEVICE}) to confirm destruction: " CONFIRM
[[ "$CONFIRM" == "$DEVICE" ]] || die "confirmation mismatch; aborted"

read -rsp "Enter a passphrase for the LUKS volume (will be asked at every boot): " PASS1; echo
read -rsp "Confirm passphrase: " PASS2; echo
[[ "$PASS1" == "$PASS2" ]] || die "passphrase mismatch"
[[ ${#PASS1} -ge 12 ]] || die "passphrase must be at least 12 characters"

# --- Stop PG ---------------------------------------------------------
info "Stopping PostgreSQL..."
systemctl stop postgresql

# --- Back up existing data -------------------------------------------
BACKUP_STAGE="/var/lib/meridian/tmp/pg-preluks-$(date +%s)"
mkdir -p "$BACKUP_STAGE"
if [[ -d "$MOUNT_POINT" ]] && [[ -n "$(ls -A "$MOUNT_POINT" 2>/dev/null)" ]]; then
  info "Staging existing data to $BACKUP_STAGE..."
  rsync -aHAX --numeric-ids "$MOUNT_POINT/" "$BACKUP_STAGE/"
else
  warn "No existing data at $MOUNT_POINT; this will be a fresh volume."
fi

# --- Create LUKS2 container ------------------------------------------
info "Creating LUKS2 on ${DEVICE}..."
echo -n "$PASS1" | cryptsetup luksFormat --type luks2 \
  --cipher aes-xts-plain64 --key-size 512 --hash sha256 \
  --pbkdf argon2id --iter-time 2000 \
  "$DEVICE" -
echo -n "$PASS1" | cryptsetup open "$DEVICE" "$MAPPER_NAME" -

info "Creating ext4 filesystem..."
mkfs.ext4 -L "meridian-pg" "/dev/mapper/${MAPPER_NAME}"

# --- Mount + restore -------------------------------------------------
mkdir -p "$MOUNT_POINT"
mount "/dev/mapper/${MAPPER_NAME}" "$MOUNT_POINT"
chown postgres:postgres "$MOUNT_POINT"
chmod 0700 "$MOUNT_POINT"

if [[ -n "$(ls -A "$BACKUP_STAGE" 2>/dev/null)" ]]; then
  info "Restoring data onto encrypted volume..."
  rsync -aHAX --numeric-ids "$BACKUP_STAGE/" "$MOUNT_POINT/"
fi

# --- crypttab + fstab -------------------------------------------------
UUID=$(blkid -s UUID -o value "$DEVICE")
[[ -n "$UUID" ]] || die "could not read UUID of $DEVICE"

if ! grep -q "$MAPPER_NAME" /etc/crypttab 2>/dev/null; then
  echo "${MAPPER_NAME}  UUID=${UUID}  none  luks,discard" >> /etc/crypttab
fi
if ! grep -q "/dev/mapper/${MAPPER_NAME}" /etc/fstab; then
  echo "/dev/mapper/${MAPPER_NAME}  ${MOUNT_POINT}  ext4  defaults,noatime  0 2" >> /etc/fstab
fi

# --- Start PG --------------------------------------------------------
systemctl daemon-reload
info "Starting PostgreSQL..."
systemctl start postgresql
systemctl is-active --quiet postgresql || die "postgres failed to start on new volume"

ok "LUKS volume ${MAPPER_NAME} active at ${MOUNT_POINT}."
warn "Staging copy preserved at ${BACKUP_STAGE} — delete with: rm -rf ${BACKUP_STAGE}"
warn "Passphrase will be requested on every boot. Consider binding to TPM with systemd-cryptenroll."

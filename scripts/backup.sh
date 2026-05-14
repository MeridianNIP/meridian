#!/usr/bin/env bash
# =====================================================================
# Meridian · Full backup
# =====================================================================
# Creates a dated .tar.zst bundle containing:
#   · pg_dump (custom format, compressed)
#   · /etc/meridian (config)
#   · /var/lib/meridian/uploads (file repo)
#   · branding assets
#
# Master keys (/etc/meridian/secrets/*) are NOT included by default —
# pass --include-keys to add them. Without keys the backup is useless
# against a future install; with keys it is a full disaster-recovery
# bundle that must be stored with the same care as the original.
#
# Usage:
#   sudo /opt/meridian/scripts/backup.sh
#   sudo /opt/meridian/scripts/backup.sh --include-keys
#   sudo /opt/meridian/scripts/backup.sh --output /mnt/offsite/
# =====================================================================

set -euo pipefail

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_CYAN=$'\e[36m'
info() { printf '%s[INFO]%s  %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s  %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[ERR ]%s  %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

readonly DEFAULT_OUT="/var/lib/meridian/backups/full"
readonly DB_NAME="${MERIDIAN_DB_NAME:-meridian}"

INCLUDE_KEYS=0
OUT_DIR="$DEFAULT_OUT"

while (( $# )); do
  case "$1" in
    --include-keys) INCLUDE_KEYS=1 ;;
    --output|-o)    OUT_DIR="$2"; shift ;;
    -h|--help)      grep -E '^# ' "$0" | head -25; exit 0 ;;
    *)              die "unknown flag: $1" ;;
  esac
  shift
done

[[ $(id -u) -eq 0 ]] || die "must be root"

mkdir -p "$OUT_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

info "Dumping PostgreSQL database '${DB_NAME}'..."
# Pipe pg_dump's output through stdout rather than -f path. Postgres's
# systemd unit ships with PrivateTmp=true, so the postgres user sees a
# different /tmp than the calling shell — writing -f /tmp/... fails
# with EACCES even when the dir is 0755. stdout works because the file
# descriptor is set up in our shell and inherited by sudo's child.
sudo -u postgres pg_dump -Fc -Z 6 "$DB_NAME" > "${STAGE}/db.dump"

info "Collecting config + data..."
rsync -a --quiet /etc/meridian/ "$STAGE/etc-meridian/"
if [[ -d /var/lib/meridian/uploads ]]; then
  rsync -a --quiet /var/lib/meridian/uploads/ "$STAGE/uploads/"
fi
if [[ -d /var/lib/meridian/branding ]]; then
  rsync -a --quiet /var/lib/meridian/branding/ "$STAGE/branding/"
fi

if (( INCLUDE_KEYS )); then
  warn "Including master keys. This bundle is now full DR-grade; store it offline."
  rsync -a --quiet /etc/meridian/secrets/ "$STAGE/secrets/"
else
  # Remove any accidental copies that rsync may have grabbed.
  rm -rf "$STAGE/etc-meridian/secrets" 2>/dev/null || true
fi

cat > "$STAGE/MANIFEST" <<MANIFEST
meridian_backup_version: 1
created_at:              ${STAMP}
host:                    $(hostname -f)
db:                      ${DB_NAME}
includes_keys:           $([[ $INCLUDE_KEYS -eq 1 ]] && echo yes || echo no)
components:              $(cd "$STAGE" && ls -1 | tr '\n' ' ')
MANIFEST

OUT_FILE="${OUT_DIR}/meridian-backup-${STAMP}.tar.zst"
info "Compressing → ${OUT_FILE}"
tar -C "$STAGE" -cf - . | zstd -q -19 -o "$OUT_FILE"
chmod 0600 "$OUT_FILE"

SIZE=$(du -h "$OUT_FILE" | cut -f1)
ok "Backup complete: ${OUT_FILE} (${SIZE})"
if (( ! INCLUDE_KEYS )); then
  warn "Without master keys, this bundle cannot be restored onto a fresh host."
  warn "Keep a separate, secured copy of /etc/meridian/secrets/."
fi

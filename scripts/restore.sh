#!/usr/bin/env bash
# =====================================================================
# Meridian · Restore from a backup.sh bundle
# =====================================================================
# DESTRUCTIVE. Replaces the current database and /etc/meridian contents
# with the backup. Stops services during the operation; restarts them on
# success.
#
# Usage:
#   sudo /opt/meridian/scripts/restore.sh /path/to/meridian-backup-XYZ.tar.zst
#   sudo /opt/meridian/scripts/restore.sh --dry-run /path/to/backup.tar.zst
# =====================================================================

set -euo pipefail

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_CYAN=$'\e[36m'; C_BOLD=$'\e[1m'
info() { printf '%s[INFO]%s  %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s  %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[ERR ]%s  %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

DRY_RUN=0
readonly DB_NAME="${MERIDIAN_DB_NAME:-meridian}"
readonly DB_USER="${MERIDIAN_DB_USER:-meridian}"

while (( $# )); do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) grep -E '^# ' "$0" | head -15; exit 0 ;;
    *)         BUNDLE="$1" ;;
  esac
  shift
done

[[ $(id -u) -eq 0 ]] || die "must be root"
[[ -n "${BUNDLE:-}" ]] || die "usage: restore.sh [--dry-run] <bundle.tar.zst>"
[[ -r "$BUNDLE" ]] || die "cannot read bundle: $BUNDLE"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
info "Extracting bundle..."
zstd -d -c "$BUNDLE" | tar -C "$STAGE" -xf -

[[ -f "$STAGE/MANIFEST" ]] || die "bundle missing MANIFEST — not a Meridian backup"
cat "$STAGE/MANIFEST"

echo
cat <<DANGER
${C_BOLD}${C_YELLOW}About to replace:${C_RESET}
  · database  '${DB_NAME}' (drop + recreate + pg_restore)
  · /etc/meridian  (config tree)
  · /var/lib/meridian/uploads  (file repo)
  · /var/lib/meridian/branding  (if present in bundle)
DANGER

if (( DRY_RUN )); then
  ok "Dry run complete. Bundle verified. No changes made."
  exit 0
fi

read -rp "Type 'RESTORE' to proceed: " CONFIRM
[[ "$CONFIRM" == "RESTORE" ]] || die "confirmation mismatch; aborted"

info "Stopping services..."
systemctl stop meridian-app meridian-celery meridian-beat 2>/dev/null || true

info "Restoring database..."
sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DROP DATABASE IF EXISTS "${DB_NAME}";
CREATE DATABASE "${DB_NAME}" OWNER "${DB_USER}";
SQL
sudo -u postgres pg_restore -d "$DB_NAME" --clean --if-exists --no-owner \
  --role "$DB_USER" "${STAGE}/db.dump"

info "Restoring /etc/meridian..."
rsync -a --delete "$STAGE/etc-meridian/" /etc/meridian/

for d in uploads branding secrets; do
  if [[ -d "$STAGE/$d" ]]; then
    info "Restoring /var/lib/meridian/${d} ..."
    mkdir -p "/var/lib/meridian/${d}"
    rsync -a --delete "$STAGE/${d}/" "/var/lib/meridian/${d}/"
    chown -R meridian:meridian "/var/lib/meridian/${d}"
  fi
done

info "Starting services..."
systemctl start meridian-app meridian-celery meridian-beat

sleep 3
for u in meridian-app meridian-celery meridian-beat; do
  systemctl is-active --quiet "$u" || die "$u did not start. See: journalctl -u $u"
done

ok "Restore complete. Log in and verify before dismissing the old bundle."

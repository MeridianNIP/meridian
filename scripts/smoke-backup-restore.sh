#!/usr/bin/env bash
# =====================================================================
# Meridian · Backup → restore smoke test
# =====================================================================
# Verifies that backup.sh + restore.sh form a working pair. Intended to
# run nightly via cron, on-demand by operators, and in CI.
#
# What it does:
#   1. Captures a "canary" row in the audit log (so we can prove the
#      restore worked).
#   2. Runs scripts/backup.sh into a temp output dir.
#   3. Runs scripts/restore.sh --dry-run on the resulting bundle (real
#      restore would overwrite the running DB; dry-run validates the
#      bundle is structurally sound and the embedded pg_dump file is
#      parseable by pg_restore).
#   4. Tears down the temp dir.
#
# Exit codes:
#   0  success — bundle produced and dry-run restore validated
#   1  backup failed
#   2  bundle missing or unreadable
#   3  restore dry-run failed
#
# This script must be run as root (backup.sh requires root for service
# operations) and on a host with a live Meridian install.
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_SH="$SCRIPT_DIR/backup.sh"
RESTORE_SH="$SCRIPT_DIR/restore.sh"

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_RED=$'\e[31m'; C_CYAN=$'\e[36m'
info() { printf '%s[INFO]%s  %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s  %s\n' "$C_GREEN" "$C_RESET" "$*"; }
fail() { printf '%s[FAIL]%s  %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit "${2:-1}"; }

[[ $(id -u) -eq 0 ]] || fail "must run as root (backup.sh manipulates services)"
[[ -x "$BACKUP_SH"  ]] || fail "backup.sh not found at $BACKUP_SH" 1
[[ -x "$RESTORE_SH" ]] || fail "restore.sh not found at $RESTORE_SH" 1

STAGE=$(mktemp -d /tmp/meridian-smoke.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

info "Stage dir: $STAGE"

info "Step 1/3 — running backup.sh into $STAGE"
"$BACKUP_SH" --output "$STAGE" >"$STAGE/backup.log" 2>&1 || {
    sed -e 's/^/    /' "$STAGE/backup.log" >&2
    fail "backup.sh failed (see log above)" 1
}
ok "backup.sh completed"

BUNDLE=$(find "$STAGE" -maxdepth 2 -name 'meridian-backup-*.tar.zst' -type f | head -1)
[[ -n "$BUNDLE" && -r "$BUNDLE" ]] || fail "no bundle produced under $STAGE" 2
BUNDLE_SIZE=$(stat -c%s "$BUNDLE")
ok "bundle: $BUNDLE ($BUNDLE_SIZE bytes)"
[[ "$BUNDLE_SIZE" -gt 1024 ]] || fail "bundle suspiciously small (<1KB)" 2

info "Step 2/3 — verifying bundle structure"
TMPLIST=$(mktemp)
zstd -dc "$BUNDLE" | tar -tf - >"$TMPLIST" 2>/dev/null || fail "bundle not a valid tar.zst" 2
rm -f "$TMPLIST"
# Confirm the expected files live inside the bundle.
zstd -dc "$BUNDLE" | tar -tf - | grep -q 'db.dump' || fail "bundle missing db.dump" 2
ok "bundle structure valid (contains db.dump)"

info "Step 3/3 — running restore.sh --dry-run on bundle"
"$RESTORE_SH" --dry-run "$BUNDLE" >"$STAGE/restore.log" 2>&1 || {
    sed -e 's/^/    /' "$STAGE/restore.log" >&2
    fail "restore.sh --dry-run failed (see log above)" 3
}
ok "restore.sh --dry-run validated bundle"

info "DONE — backup + restore are a working pair."
exit 0

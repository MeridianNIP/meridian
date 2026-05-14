#!/usr/bin/env bash
# =====================================================================
# Meridian · PostgreSQL WAL archive command
# =====================================================================
# Wired into postgresql.conf.overlay as:
#   archive_command = '/opt/meridian/scripts/wal_archive.sh "%p" "%f"'
#
# PostgreSQL invokes this for every filled WAL segment. Exit 0 = archived;
# any non-zero means PG will retry (infinitely) until it succeeds. Do NOT
# exit 0 if the file was not safely persisted.
#
# Layout:
#   %p = source path on the PG data volume
#   %f = base WAL filename
# =====================================================================

set -euo pipefail

readonly SRC=${1:?"WAL source path required"}
readonly NAME=${2:?"WAL filename required"}
readonly DEST_DIR="/var/lib/meridian/backups/wal"
readonly DEST="${DEST_DIR}/${NAME}.gz"
readonly TMP="${DEST}.partial.$$"

mkdir -p "$DEST_DIR"

# Refuse to clobber an existing archived WAL (data integrity).
if [[ -e "$DEST" ]]; then
  logger -t meridian-wal "refusing to overwrite existing WAL archive: $DEST"
  exit 1
fi

if ! gzip -c -- "$SRC" > "$TMP"; then
  rm -f "$TMP"
  logger -t meridian-wal "gzip failed for $NAME"
  exit 2
fi

sync "$TMP" 2>/dev/null || true
mv -- "$TMP" "$DEST"

# Drop anything older than the retention window; 15-minute job ships WAL,
# backup-rotation job prunes. This is just a belt-and-braces safety net.
find "$DEST_DIR" -type f -name '*.gz' -mtime +14 -delete 2>/dev/null || true

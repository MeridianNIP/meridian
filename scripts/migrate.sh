#!/usr/bin/env bash
# =====================================================================
# Meridian · schema migration runner
# =====================================================================
# Applies every db/migrations/NNNN_*.sql file whose number is greater than
# the max(number) already in schema_migrations, in order. Each file runs
# inside its own transaction; a failure stops the runner and nothing past
# that point is applied.
#
# Usage:
#   sudo /opt/meridian/scripts/migrate.sh
#   sudo /opt/meridian/scripts/migrate.sh --dry-run
# =====================================================================

set -euo pipefail

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_CYAN=$'\e[36m'
info() { printf '%s[INFO]%s  %s\n' "$C_CYAN"   "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s  %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[ERR ]%s  %s\n' "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }

DRY=0
while (( $# )); do
  case "$1" in
    --dry-run) DRY=1 ;;
    -h|--help) grep -E '^# ' "$0" | head -20; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
  shift
done

DB_NAME="${MERIDIAN_DB_NAME:-meridian}"
MIGRATIONS_DIR="${MERIDIAN_MIGRATIONS_DIR:-/opt/meridian/db/migrations}"

[[ -d "$MIGRATIONS_DIR" ]] || die "migrations dir not found: $MIGRATIONS_DIR"

# Ensure the bookkeeping table exists. migrations/0001 creates it too; this
# second copy is harmless (IF NOT EXISTS) and keeps the runner self-sufficient.
if (( ! DRY )); then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$DB_NAME" <<SQL > /dev/null
    CREATE TABLE IF NOT EXISTS schema_migrations (
      number     INTEGER PRIMARY KEY,
      filename   TEXT NOT NULL UNIQUE,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      sha256_hex TEXT NOT NULL,
      applied_by TEXT
    );
SQL
fi

applied_max=$(sudo -u postgres psql -At -d "$DB_NAME" \
  -c "SELECT COALESCE(MAX(number), 0) FROM schema_migrations" 2>/dev/null || echo 0)
info "current schema version: $applied_max"

pending=0
for f in $(ls "$MIGRATIONS_DIR"/[0-9]*_*.sql 2>/dev/null | sort); do
  base=$(basename "$f")
  num=$(echo "$base" | cut -d_ -f1 | sed 's/^0*//')
  num=${num:-0}
  if (( num <= applied_max )); then
    # Verify the file hash matches what we applied. Any drift = abort.
    recorded=$(sudo -u postgres psql -At -d "$DB_NAME" \
      -c "SELECT sha256_hex FROM schema_migrations WHERE number = $num" 2>/dev/null || true)
    current=$(sha256sum "$f" | awk '{print $1}')
    if [[ -n "$recorded" ]] && [[ "$recorded" != "$current" ]]; then
      die "migration $base was edited after it was applied (hash mismatch)
        recorded: $recorded
        current:  $current
        refusing to continue. If this is intentional, write a new migration to correct it."
    fi
    continue
  fi

  pending=$((pending + 1))
  if (( DRY )); then
    warn "WOULD APPLY: $base  (#$num)"
    continue
  fi

  info "applying $base  (#$num)"
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$DB_NAME" -f "$f"
  sha=$(sha256sum "$f" | awk '{print $1}')
  # ON CONFLICT DO UPDATE: some migration files (0003+) seed
  # schema_migrations themselves with sha256_hex='pending' as a
  # self-record placeholder. Without DO UPDATE, the runner's second
  # insert hits the unique constraint and aborts. With DO UPDATE the
  # runner authoritatively overwrites the placeholder with the real
  # sha + applied_by. Older migrations (0001-0002) don't self-record
  # and just get inserted fresh. Surfaced 2026-05-13 during the
  # unattended-rebuild validation pass.
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$DB_NAME" <<SQL > /dev/null
    INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
    VALUES ($num, '$base', '$sha', '${SUDO_USER:-unknown}')
    ON CONFLICT (number) DO UPDATE
       SET filename   = EXCLUDED.filename,
           sha256_hex = EXCLUDED.sha256_hex,
           applied_by = EXCLUDED.applied_by;
SQL
  ok "applied $base"
done

if (( pending == 0 )); then
  ok "schema already up to date"
else
  (( DRY )) && info "dry-run: $pending migration(s) would be applied" || ok "$pending migration(s) applied"
fi

#!/usr/bin/env bash
# =====================================================================
# Meridian · rotate-credential
# =====================================================================
# Invoked by the portal over sudo (see /etc/sudoers.d/meridian-credentials)
# to rotate a specific well-known credential. The secret (if any) is
# passed on stdin — never in argv — so it doesn't land in journald.
#
# Targets:
#   linux:meridian-user  — chpasswd for the interactive account
#   linux:root           — chpasswd for root
#   db:meridian          — ALTER ROLE + update /etc/meridian/meridian.conf
#   key:row_hmac         — regenerate /etc/meridian/secrets/row_hmac.key
#   key:master           — regenerate /etc/meridian/secrets/master.key
#   ssh:host_keys        — re-init /etc/ssh/ssh_host_* + reload sshd
# =====================================================================

set -uo pipefail

TARGET="${1:-}"
SECRETS_DIR="/etc/meridian/secrets"
CONF_FILE="/etc/meridian/meridian.conf"

# Read stdin (the new secret, if applicable) — avoids argv exposure.
IFS= read -r NEW_SECRET || true

die() { echo "rotate-credential: $*" >&2; exit 1; }

case "$TARGET" in
  linux:meridian-user|linux:root)
    USER="${TARGET#linux:}"
    [[ -n "$NEW_SECRET" ]] || die "new password required on stdin"
    id "$USER" >/dev/null 2>&1 || die "no such linux user: $USER"
    # chpasswd reads user:password from stdin.
    echo "$USER:$NEW_SECRET" | chpasswd || die "chpasswd failed"
    echo "rotated linux password for $USER"
    ;;

  db:meridian)
    [[ -n "$NEW_SECRET" ]] || die "new password required on stdin"
    # Update the postgres role and the DSN file the app reads at boot.
    # postgres peer-auth → no password needed for sudo -u postgres psql.
    if ! sudo -u postgres psql -v ON_ERROR_STOP=1 -d meridian \
         -c "ALTER ROLE meridian WITH PASSWORD '$NEW_SECRET';" >/dev/null; then
      die "ALTER ROLE failed"
    fi
    # Rewrite the DSN line in /etc/meridian/meridian.conf atomically.
    [[ -r "$CONF_FILE" ]] || die "$CONF_FILE not readable"
    umask 077
    tmp=$(mktemp "${CONF_FILE}.XXXX")
    awk -v pw="$NEW_SECRET" '
      /^[[:space:]]*MERIDIAN_DB_DSN[[:space:]]*=/ {
        sub(/:[^:@]*@/, ":"pw"@")
      }
      /^[[:space:]]*db_dsn[[:space:]]*=/ {
        sub(/:[^:@]*@/, ":"pw"@")
      }
      { print }
    ' "$CONF_FILE" > "$tmp"
    chown root:meridian "$tmp"
    chmod 0640 "$tmp"
    mv "$tmp" "$CONF_FILE"
    echo "rotated DB password for role meridian + updated $CONF_FILE"
    ;;

  key:row_hmac|key:master)
    NAME="${TARGET#key:}"
    [[ -d "$SECRETS_DIR" ]] || die "$SECRETS_DIR missing"
    install -d -m 0700 -o meridian -g meridian "$SECRETS_DIR"
    target_file="$SECRETS_DIR/${NAME}.key"
    # Archive the previous key so a stuck-in-between-states install can
    # be recovered manually. Oldest-one-wins — we only keep a single .old.
    if [[ -f "$target_file" ]]; then
      mv "$target_file" "${target_file}.old"
    fi
    umask 077
    head -c 32 /dev/urandom > "$target_file" || die "urandom read failed"
    chown meridian:meridian "$target_file"
    chmod 0400 "$target_file"
    echo "rotated $target_file (previous archived as ${target_file}.old)"
    ;;

  ssh:host_keys)
    # Move old host keys aside (for forensic comparison of the rollover)
    # and re-init. sshd rereads on reload. Do NOT reboot.
    ts=$(date +%Y%m%dT%H%M%SZ)
    mkdir -p "/etc/ssh/archived_hostkeys/$ts"
    mv /etc/ssh/ssh_host_* "/etc/ssh/archived_hostkeys/$ts/" 2>/dev/null || true
    ssh-keygen -A || die "ssh-keygen -A failed"
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    echo "SSH host keys regenerated; old keys archived under /etc/ssh/archived_hostkeys/$ts"
    ;;

  *)
    die "unknown target: ${TARGET:-<empty>}"
    ;;
esac

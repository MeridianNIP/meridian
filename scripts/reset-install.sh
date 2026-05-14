#!/usr/bin/env bash
# =====================================================================
# Meridian · reset-install.sh
# Rolls back a failed/partial install so install.sh can run fresh.
# =====================================================================
# Stops:   meridian-app, meridian-celery, meridian-beat systemd units
# Drops:   PostgreSQL meridian database + role (names read from state
#          file when present, else defaults to "meridian")
# Removes: /opt/meridian, /etc/meridian, /var/lib/meridian,
#          /var/log/meridian, /etc/systemd/system/meridian-*.service,
#          /etc/nginx/sites-{available,enabled}/meridian +
#          /etc/nginx/snippets/meridian_proxy.conf,
#          /etc/apparmor.d/opt.meridian.app,
#          /etc/fail2ban/jail.d/jail.meridian.conf,
#          /etc/logrotate.d/meridian
# Leaves:  LUKS volumes (data-destructive — handled manually),
#          /etc/letsencrypt (certs may be reused),
#          meridian/ddi-ssh users + groups (install.sh is idempotent),
#          /root/meridian-install.log and state file (may be useful).
# =====================================================================

set -euo pipefail

readonly INSTALL_ROOT="/opt/meridian"
readonly CONFIG_ROOT="/etc/meridian"
readonly DATA_ROOT="/var/lib/meridian"
readonly LOG_ROOT="/var/log/meridian"
readonly STATE_FILE="/root/meridian-install.state"

DRY_RUN=0
ASSUME_YES=0
DB_NAME="meridian"
DB_USER="meridian"

C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'
C_BLUE=$'\e[34m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'
info() { printf '%s[INFO]%s  %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s  %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
err()  { printf '%s[ERR ]%s  %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }

# Run cmd, or just echo it under --dry-run.
run() {
  if (( DRY_RUN )); then
    printf '  + %s\n' "$*"
  else
    eval "$@"
  fi
}

usage() {
  cat <<EOF
Usage: sudo $0 [--dry-run] [--yes]

Undoes a partial Meridian install on this host so install.sh can run fresh.

  --dry-run   Print what would run; change nothing.
  --yes, -y   Skip the confirmation prompt.

Safe to run multiple times. Items that are already absent are skipped.
EOF
}

parse_args() {
  while (( $# )); do
    case "$1" in
      --dry-run) DRY_RUN=1 ;;
      --yes|-y)  ASSUME_YES=1 ;;
      -h|--help) usage; exit 0 ;;
      *)         die "Unknown flag: $1 (try --help)" ;;
    esac
    shift
  done
}

load_db_names() {
  if [[ -r "$STATE_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    info "Using DB name/user from $STATE_FILE: ${DB_NAME}/${DB_USER}"
  else
    info "No state file — assuming defaults: DB=${DB_NAME}, user=${DB_USER}"
  fi
}

confirm() {
  (( ASSUME_YES )) && return 0
  printf '\n%s%sThis will destroy the current Meridian install on this host.%s\n' \
         "$C_BOLD" "$C_RED" "$C_RESET"
  printf 'Only proceed if you intend to re-run install.sh.\n'
  printf 'Type %sWIPE%s to continue: ' "$C_BOLD" "$C_RESET"
  local ans; read -r ans
  [[ "$ans" == "WIPE" ]] || die "Aborted."
}

stop_services() {
  info "Stopping systemd units"
  for u in meridian-app meridian-celery meridian-beat; do
    run "systemctl stop $u >/dev/null 2>&1 || true"
    run "systemctl disable $u >/dev/null 2>&1 || true"
    run "rm -f /etc/systemd/system/$u.service"
  done
  run "systemctl daemon-reload"
  ok "Services stopped and unit files removed"
}

drop_database() {
  info "Dropping PostgreSQL database + role"
  if ! systemctl is-active --quiet postgresql 2>/dev/null; then
    warn "PostgreSQL not running — skipping DB drop"
    return 0
  fi
  run "sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"DROP DATABASE IF EXISTS ${DB_NAME};\" >/dev/null"
  run "sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"DROP ROLE IF EXISTS ${DB_USER};\" >/dev/null"
  ok "DB + role dropped"
}

remove_nginx() {
  info "Removing Nginx vhost"
  run "rm -f /etc/nginx/sites-available/meridian /etc/nginx/sites-enabled/meridian"
  run "rm -f /etc/nginx/snippets/meridian_proxy.conf"
  if command -v nginx >/dev/null && systemctl is-active --quiet nginx 2>/dev/null; then
    run "nginx -t >/dev/null 2>&1 && systemctl reload nginx || true"
  fi
  ok "Nginx vhost removed"
}

remove_apparmor() {
  local prof="/etc/apparmor.d/opt.meridian.app"
  [[ -e "$prof" ]] || (( DRY_RUN )) || return 0
  info "Removing AppArmor profile"
  run "apparmor_parser -R $prof >/dev/null 2>&1 || true"
  run "rm -f $prof"
  ok "AppArmor profile removed"
}

remove_fail2ban() {
  local jail="/etc/fail2ban/jail.d/jail.meridian.conf"
  [[ -e "$jail" ]] || (( DRY_RUN )) || return 0
  info "Removing fail2ban jail"
  run "rm -f $jail"
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    run "systemctl reload fail2ban >/dev/null 2>&1 || true"
  fi
  ok "fail2ban jail removed"
}

remove_logrotate() {
  local f="/etc/logrotate.d/meridian"
  [[ -e "$f" ]] || (( DRY_RUN )) || return 0
  info "Removing logrotate config"
  run "rm -f $f"
  ok "logrotate config removed"
}

remove_dirs() {
  info "Removing install directories"
  for d in "$INSTALL_ROOT" "$CONFIG_ROOT" "$DATA_ROOT" "$LOG_ROOT"; do
    run "rm -rf $d"
  done
  ok "Directories removed"
}

main() {
  parse_args "$@"
  [[ $(id -u) -eq 0 ]] || die "Must run as root (sudo)."
  (( DRY_RUN )) && warn "DRY-RUN: no changes will be made."
  load_db_names
  confirm
  stop_services
  drop_database
  remove_nginx
  remove_apparmor
  remove_fail2ban
  remove_logrotate
  remove_dirs
  echo
  ok "Reset complete. Re-run: sudo ./install.sh"
  info "Preserved: $STATE_FILE (if present), /root/meridian-install.log, /etc/letsencrypt"
}

main "$@"

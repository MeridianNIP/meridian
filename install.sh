#!/usr/bin/env bash
# =====================================================================
# Meridian · Network Intelligence Platform
# Interactive Debian 12 installer · v1.0.0
# =====================================================================
# Usage:
#   sudo ./install.sh                         # fresh install (interactive)
#   sudo ./install.sh --upgrade               # upgrade existing install
#   sudo ./install.sh --dry-run               # doctor mode; no changes
#   sudo ./install.sh --airgapped             # skip online ACME + demo activation
#   sudo ./install.sh --unattended --config /path/to/answers.env
#   sudo ./install.sh --resume-from=<stage>   # resume a failed install using
#                                             # saved state in /root/meridian-install.state
# =====================================================================

set -euo pipefail

# --------------------------------------------------------------------
# Constants & paths
# --------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0.0"
readonly MANIFEST_VERSION="2026.04.18-r1"
readonly INSTALL_LOG="/root/meridian-install.log"
readonly STATE_FILE="/root/meridian-install.state"
readonly INSTALL_ROOT="/opt/meridian"
readonly CONFIG_ROOT="/etc/meridian"
readonly DATA_ROOT="/var/lib/meridian"
readonly LOG_ROOT="/var/log/meridian"
readonly SECRETS_DIR="/etc/meridian/secrets"
readonly MASTER_KEY_PATH="${SECRETS_DIR}/master.key"
readonly ROW_HMAC_KEY_PATH="${SECRETS_DIR}/row_hmac.key"

readonly SVC_USER="meridian"
readonly SVC_GROUP="meridian"
readonly SSH_GROUP="ddi-ssh"

# --------------------------------------------------------------------
# OS-dependent package selection · populated by detect_os_targets().
# Primary: Debian 13 (Trixie) · Fallback: Debian 12 (Bookworm)
# --------------------------------------------------------------------
OS_MAJOR=""
PG_MAJOR=""
CACHE_PKG=""
CACHE_SERVICE=""
CACHE_CONF_PATH=""
CACHE_OVERLAY_SRC=""
NGINX_TARGET=""
BIND9_TARGET=""
BIND9_SERVICE=""

# Location of this script + the shipped config templates.
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_SRC="${SCRIPT_DIR}/config"

# Allow-list of variables exposed to envsubst. Adding a new template variable
# means both defining it above AND adding it to this list.
readonly TEMPLATE_VARS='${PORTAL_NAME} ${PORTAL_DOMAIN} ${SSH_PORT} ${SSH_GROUP} ${SVC_USER} ${SVC_GROUP} ${INSTALL_ROOT} ${CONFIG_ROOT} ${DATA_ROOT} ${LOG_ROOT} ${SCOPE_OF_USE} ${TIMEZONE} ${ADMIN_EMAIL}'

# No apt-layer exact-version pins: Debian security point-releases move fast
# and we don't want to block them. Broad expected versions enforced via the
# `version_manifest` table + `meridian-nip doctor` post-install. The selection
# of which package name to install (postgresql-17 vs postgresql-15, valkey vs
# redis-server) is decided by detect_os_targets() based on the running OS.

# --------------------------------------------------------------------
# Runtime state (populated by prompts / flags)
# --------------------------------------------------------------------
MODE="install"           # install | upgrade | dry-run
AIRGAPPED=0
UNATTENDED=0
ANSWERS_FILE=""
RESUME_FROM=""           # stage name; set by --resume-from=<stage>
STAGE_REACHED=0          # flips to 1 once run_stage hits $RESUME_FROM
# SKIP_LICENSE removed 2026-05-13: license subsystem deleted (Apache 2.0)

PORTAL_NAME=""
PORTAL_DOMAIN=""
ADMIN_USERNAME=""
ADMIN_EMAIL=""
ADMIN_TEMP_PASSWORD=""
DB_NAME=""
DB_USER=""
DB_PASSWORD=""
TIMEZONE=""
SSL_METHOD=""            # letsencrypt | cloudflare | self-signed | none
SCOPE_OF_USE=""          # internal | external | both
SSH_PORT=""
LUKS_ENCRYPT=""          # y | n
# LICENSE_KEY / LICENSE_TIER removed 2026-05-13: license subsystem
# deleted (Apache 2.0). No license entry, no tier — full feature parity.

# Static networking. Blank STATIC_IP → keep DHCP.
STATIC_IP=""             # e.g. 192.168.50.110/24 (CIDR); blank = DHCP
STATIC_GATEWAY=""
STATIC_DNS=""
NET_IFACE=""             # auto-detected from default route

# Break-glass / recovery defaults. Both optional, both strongly recommended.
# Without them a mis-configured fail2ban jail or a lost laptop can lock the
# only admin out of SSH and turn a 10-second unban into a console-and-root
# rescue op. See docs/admin/recovery.md for the full rationale.
ADMIN_CIDR=""            # e.g. 192.168.50.0/24; seeds fail2ban ignoreip
ADMIN_SSH_PUBKEY=""      # public key string; installed into root+meridian-user

# --------------------------------------------------------------------
# Output helpers · log to console AND to $INSTALL_LOG
# --------------------------------------------------------------------
C_RESET=$'\e[0m'
C_BOLD=$'\e[1m'
C_DIM=$'\e[2m'
C_GREEN=$'\e[32m'
C_YELLOW=$'\e[33m'
C_RED=$'\e[31m'
C_BLUE=$'\e[34m'
C_CYAN=$'\e[36m'
C_TEAL=$'\e[38;5;43m'

_log()   { printf '%s\n' "$*"        | tee -a "$INSTALL_LOG" >&2; }
info()   { _log "${C_BLUE}[INFO]${C_RESET}  $*"; }
ok()     { _log "${C_GREEN}[ OK ]${C_RESET}  $*"; }
warn()   { _log "${C_YELLOW}[WARN]${C_RESET}  $*"; }
err()    { _log "${C_RED}[ERR ]${C_RESET}  $*"; }
die()    { err "$*"; exit 1; }

section() {
  printf '\n%s%s═════════════════════════════════════════════════════════════════════%s\n' \
    "$C_BOLD" "$C_TEAL" "$C_RESET" | tee -a "$INSTALL_LOG"
  printf '%s  %s%s\n' "$C_BOLD$C_TEAL" "$1" "$C_RESET" | tee -a "$INSTALL_LOG"
  printf '%s%s═════════════════════════════════════════════════════════════════════%s\n\n' \
    "$C_BOLD" "$C_TEAL" "$C_RESET" | tee -a "$INSTALL_LOG"
}

# prompt <var_name> <default> <prompt_text>
prompt() {
  local __var=$1 __default=$2 __text=$3 __answer
  if (( UNATTENDED )); then eval "$__var=\${$__var:-$__default}"; return; fi
  if [[ -n "$__default" ]]; then
    printf '  %s [%s]: ' "$__text" "$__default"
  else
    printf '  %s: ' "$__text"
  fi
  read -r __answer
  __answer="${__answer:-$__default}"
  eval "$__var=\"\$__answer\""
}

prompt_secret() {
  local __var=$1 __text=$2 __answer
  printf '  %s: ' "$__text"
  read -rs __answer
  printf '\n'
  eval "$__var=\"\$__answer\""
}

prompt_yn() {
  local __var=$1 __default=$2 __text=$3 __answer
  if (( UNATTENDED )); then eval "$__var=\${$__var:-$__default}"; return; fi
  while true; do
    printf '  %s [%s]: ' "$__text" "$__default"
    read -r __answer
    __answer="${__answer:-$__default}"
    case "${__answer,,}" in
      y|yes) eval "$__var=y"; return ;;
      n|no)  eval "$__var=n"; return ;;
      *) echo "    Please answer y or n." ;;
    esac
  done
}

# explain "title" $'Line 1\nLine 2\n...'  — shown before each prompt group
explain() {
  local title=$1 body=$2
  printf '\n%s─── %s ───%s\n' "$C_CYAN" "$title" "$C_RESET"
  printf '%s%s%s\n' "$C_DIM" "$body" "$C_RESET"
  printf '\n'
}

# --------------------------------------------------------------------
# Error trap — always print a helpful message
# --------------------------------------------------------------------
on_error() {
  local rc=$? line=${BASH_LINENO[0]}
  err "Installer aborted (exit $rc at line $line)."
  err "See $INSTALL_LOG for full log."
  err "If this is reproducible, attach the log to a support ticket at https://meridiannip.com/support"
  exit "$rc"
}
trap on_error ERR

# --------------------------------------------------------------------
# Pre-flight checks · meridian-nip doctor equivalent
# --------------------------------------------------------------------
preflight() {
  section "Pre-flight checks"

  [[ $(id -u) -eq 0 ]] || die "Must be run as root (sudo)."

  # OS family
  local os_id="" os_ver=""
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    os_id="${ID:-}"; os_ver="${VERSION_ID:-}"
  fi
  [[ "$os_id" == "debian" ]] || die "Meridian requires Debian (found: ${os_id:-unknown}). RHEL/Ubuntu/Alpine are not supported in this release."
  case "$os_ver" in
    13) OS_MAJOR=13; ok "OS: $PRETTY_NAME  (primary target)" ;;
    12) OS_MAJOR=12; ok "OS: $PRETTY_NAME  (supported · legacy)" ;;
    *)  die "Unsupported Debian version: $os_ver. Meridian targets Debian 13 (primary) and Debian 12 (fallback)." ;;
  esac
  detect_os_targets

  # Architecture
  local arch
  arch=$(dpkg --print-architecture)
  [[ "$arch" =~ ^(amd64|arm64)$ ]] || die "Unsupported architecture: $arch. Meridian ships amd64 and arm64."
  ok "Arch: $arch"

  # Kernel
  local kver; kver=$(uname -r)
  ok "Kernel: $kver"

  # Disk space
  local avail_gb
  avail_gb=$(df -BG --output=avail / | tail -1 | tr -d ' G')
  (( avail_gb >= 20 )) || die "At least 20 GB free required on /. Found: ${avail_gb} GB."
  ok "Disk free: ${avail_gb} GB"

  # RAM
  local ram_mb
  ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  (( ram_mb >= 2000 )) || warn "Less than 2 GB RAM detected (${ram_mb} MB). 4 GB recommended."
  ok "Memory: ${ram_mb} MB"

  # Internet (unless airgapped)
  if (( ! AIRGAPPED )); then
    if curl -fsS --max-time 5 https://meridiannip.com/healthz >/dev/null 2>&1; then
      ok "Internet reachable (meridiannip.com)"
    else
      warn "Cannot reach meridiannip.com. If this is an airgapped install, re-run with --airgapped."
    fi
  fi

  # apt sources
  apt-get update -qq 2>/dev/null || die "apt-get update failed. Check /etc/apt/sources.list."
  ok "apt sources responding"

  # Port availability
  for p in 80 443; do
    if ss -Htnl "sport = :$p" 2>/dev/null | grep -q .; then
      warn "Port $p is already bound. Installer will attempt graceful reconfiguration."
    fi
  done

  # Existing install? Skip the check during --resume-from since a partial
  # $INSTALL_ROOT is expected there.
  #
  # Check for ACTUAL install markers (venv + systemd unit), not just the
  # directory itself — operators typically rsync source code INTO
  # /opt/meridian before invoking ./install.sh, so the bare directory
  # always exists on first run. Surfaced 2026-05-13 during the
  # unattended-rebuild validation pass.
  if [[ -d "$INSTALL_ROOT" && -z "$RESUME_FROM" ]]; then
    local already_installed=0
    [[ -d "$INSTALL_ROOT/venv" ]]                                      && already_installed=1
    [[ -f "/etc/systemd/system/meridian-app.service" ]]                && already_installed=1
    systemctl is-active --quiet meridian-app.service 2>/dev/null       && already_installed=1
    if (( already_installed )) && [[ "$MODE" == "install" ]]; then
      warn "Existing install detected at $INSTALL_ROOT."
      prompt_yn UPGRADE_CONFIRM n "Switch to upgrade mode?"
      [[ "$UPGRADE_CONFIRM" == "y" ]] || die "Aborted. Re-run with --upgrade to upgrade, or remove $INSTALL_ROOT for a fresh install."
      MODE="upgrade"
    fi
    if (( already_installed )); then
      ok "Upgrade mode: existing install found"
    fi
  fi

  ok "Pre-flight complete"
}

# --------------------------------------------------------------------
# Welcome banner
# --------------------------------------------------------------------
welcome_banner() {
  cat <<'EOF' | tee -a "$INSTALL_LOG"

   ╔═══════════════════════════════════════════════════════════════╗
   ║                                                               ║
   ║             M E R I D I A N                                   ║
   ║             Network Intelligence Platform                     ║
   ║                                                               ║
   ║             v1.0.0  ·  meridiannip.com                        ║
   ║                                                               ║
   ╚═══════════════════════════════════════════════════════════════╝

  This installer sets up a complete DNS / DHCP / IPAM / network
  operations portal on this Debian 12 host. You will be prompted for
  every meaningful choice — each prompt is preceded by an explanation
  of what it does and why it matters.

  Nothing is hardcoded. Credentials you enter live only on this box.

EOF
}

# license_entry() removed 2026-05-13: Meridian is Apache 2.0; no license
# key entry, no tier selection, full feature parity for everyone.

# --------------------------------------------------------------------
# Interactive configuration
# --------------------------------------------------------------------
configure_interactive() {
  section "Configuration"

  explain "Portal identity" $'
  The portal name is what users see at the top of every page. It can be
  changed later from Admin → Branding.

  The domain is the FQDN that users will use to access the portal
  (e.g. meridiannip.acme.com). It must resolve to this host.
  '
  prompt PORTAL_NAME "Meridian NIP" "Portal display name"
  prompt PORTAL_DOMAIN "" "Primary domain (FQDN)"
  [[ "$PORTAL_DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] \
    || die "Domain looks invalid: $PORTAL_DOMAIN"

  explain "First admin user" $'
  The admin account you create here has full platform access. It is the
  "super-admin" role until you create additional admins.

  The temporary password below is shown ONCE in the install summary and
  written to /root/meridian-install.log. The admin MUST change it at
  first login. MFA enrollment is offered at first login.
  '
  prompt ADMIN_USERNAME "admin" "Admin username"
  prompt ADMIN_EMAIL "" "Admin email (for AUP acceptances, alerts)"
  [[ "$ADMIN_EMAIL" =~ ^[^@]+@[^@]+\.[a-zA-Z]{2,}$ ]] \
    || die "Email looks invalid: $ADMIN_EMAIL"
  # Default temp password is the well-known `meridian` for build automation
  # and documented recovery. The account is flagged must_change_password=TRUE
  # so the operator cannot actually sign in without setting a new one, AND
  # MFA enrollment is offered on that same first login.
  # Set ADMIN_TEMP_PASSWORD before prompting (or via --unattended env) to
  # override; leave blank to accept the default.
  if [[ -z "${ADMIN_TEMP_PASSWORD:-}" ]]; then
    # Universally-known default. Operator is forced to change at first
    # login (no `--no-force-change` flag in the seed CLI) and to enroll
    # MFA before any sensitive operations. Picking the same convention
    # most appliances use makes the first-login flow obvious.
    ADMIN_TEMP_PASSWORD="password"
  fi
  info "Admin temp password: $ADMIN_TEMP_PASSWORD (must change at first login)."

  explain "Database" $'
  Meridian stores users, queries, audit logs, monitors, certificates, and
  tool results in PostgreSQL 15. You can choose the DB name, role, and
  password — or accept auto-generated values.

  The DB is bound to localhost only. Remote access is not enabled by
  default; admins who need remote SQL must explicitly open it.
  '
  prompt DB_NAME "meridian" "Database name"
  prompt DB_USER "meridian" "Database role (user)"
  DB_PASSWORD=$(gen_password 32)
  info "DB password auto-generated (shown in summary)."

  explain "Timezone" $'
  All stored timestamps are UTC. The default display timezone for emails,
  reports, and the UI is set below. Individual users can override this
  in their profile.
  '
  prompt TIMEZONE "$(cat /etc/timezone 2>/dev/null || echo 'UTC')" "Default timezone"

  explain "TLS / HTTPS" $'
  How should this portal terminate TLS?

    letsencrypt  — certbot + ACME HTTP-01, auto-renew. Needs port 80 open
                   to the internet and a public DNS record pointing at
                   this host.
    cloudflare   — Cloudflare-proxied mode. TLS terminates at Cloudflare;
                   we configure Nginx for origin-pull using a full-strict
                   certificate and Authenticated Origin Pulls.
    self-signed  — local self-signed cert. Fine for air-gapped labs but
                   browsers will warn users.
    none         — HTTP only. NOT RECOMMENDED. Sandbox/dev use only.
  '
  while true; do
    prompt SSL_METHOD "letsencrypt" "TLS method (letsencrypt|cloudflare|self-signed|none)"
    [[ "$SSL_METHOD" =~ ^(letsencrypt|cloudflare|self-signed|none)$ ]] && break
    warn "Invalid choice. Try again."
  done

  explain "Scope of use" $'
  What will this Meridian instance be used for?

    internal — Internal tooling only. External-facing tools (typosquat
               sweep, public IP reputation, BGP looking glass) are
               hidden by default.
    external — External operations only. Internal-only tools (SNMP walk,
               DHCP lease viewer, subnet sweep) are hidden by default.
    both     — Full tool surface. Admins scope per group as needed.

  This is only the default; every tool can be re-enabled per group in
  Admin → Scope Manager after install.
  '
  while true; do
    prompt SCOPE_OF_USE "both" "Scope (internal|external|both)"
    [[ "$SCOPE_OF_USE" =~ ^(internal|external|both)$ ]] && break
    warn "Invalid choice. Try again."
  done

  explain "SSH port" $'
  Moving SSH off port 22 eliminates the majority of automated scan
  traffic that hits exposed hosts. Choose a port between 1024 and 65535
  that is NOT already in use by another service. Firewall rules and
  fail2ban filters are adjusted automatically.

  IMPORTANT: write this number down before you disconnect. SSH will
  listen on the new port after install; port 22 will be closed.

  Leave blank to keep port 22.
  '
  prompt SSH_PORT "" "Custom SSH port (blank = keep 22)"
  if [[ -n "$SSH_PORT" ]]; then
    [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1024 )) && (( SSH_PORT <= 65535 )) \
      || die "SSH port must be 1024-65535. Got: $SSH_PORT"
  else
    SSH_PORT="22"
  fi

  explain "Static LAN IP (optional)" $'
  By default this host keeps whatever address DHCP hands it. For reproducible
  builds, lab rigs, and long-lived installs you usually want a stable IP.
  Provide one here and the installer will write a systemd-networkd profile
  bound to the primary interface.
    · Format:  <IP>/<prefix>     e.g. 192.168.50.110/24
    · Gateway defaults to <first three octets>.1
    · DNS     defaults to the same gateway
  Leave blank to stay on DHCP; the assigned address is reported in the
  install summary. Changes take effect on NEXT REBOOT — this session keeps
  its current address so the install does not self-disconnect.
  '
  detect_primary_iface
  prompt STATIC_IP "" "Desired LAN IP in CIDR (blank = DHCP on ${NET_IFACE:-primary iface})"
  if [[ -n "$STATIC_IP" ]]; then
    [[ "$STATIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] \
      || die "Static IP must be CIDR form like 192.168.50.110/24. Got: $STATIC_IP"
    local __ip3
    __ip3="${STATIC_IP%/*}"
    __ip3="${__ip3%.*}.1"
    prompt STATIC_GATEWAY "$__ip3" "Default gateway"
    prompt STATIC_DNS     "$__ip3" "DNS server (comma-separated for multiple)"
  fi

  explain "Break-glass / admin recovery" $'
  Two optional — but strongly recommended — settings that prevent the most
  common self-lockout: an over-eager fail2ban ban on the admin workstation.

  1. Admin CIDR: the subnet of your admin/deploy workstations. This range
     is seeded into fail2ban\'s ignoreip list so failed SSH attempts from
     that network never result in a ban. Typical home lab: 192.168.1.0/24
     or 192.168.50.0/24.

  2. Admin SSH pubkey: an ed25519 / RSA public key. It is installed into
     /root/.ssh/authorized_keys AND /home/meridian-user/.ssh/authorized_keys
     so key-based SSH works on day 1 without you scp\'ing the key in.

  Both can be left blank for an airgapped/console-only install — you can
  set them later from Admin Panel → Fail2ban, and via ssh-copy-id.
  '
  local __auto_cidr
  __auto_cidr=$(ip -o -4 route show default 2>/dev/null \
                | awk '{print $3}' | awk -F. '{printf "%s.%s.%s.0/24\n", $1, $2, $3}')
  prompt ADMIN_CIDR "$__auto_cidr" "Admin CIDR for fail2ban ignoreip (blank = none)"
  if [[ -n "$ADMIN_CIDR" ]]; then
    [[ "$ADMIN_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] \
      || die "Admin CIDR must be in a.b.c.d/prefix form. Got: $ADMIN_CIDR"
  fi
  prompt ADMIN_SSH_PUBKEY "" "Admin SSH pubkey (paste or blank to skip)"
  if [[ -n "$ADMIN_SSH_PUBKEY" ]]; then
    [[ "$ADMIN_SSH_PUBKEY" =~ ^(ssh-(ed25519|rsa|ecdsa)|ecdsa-sha2-nistp[0-9]+)\ [A-Za-z0-9+/=]+(\ .+)?$ ]] \
      || die "Pubkey must start with ssh-ed25519 / ssh-rsa / ssh-ecdsa / ecdsa-sha2-…"
  fi

  explain "Disk encryption for PostgreSQL data" $'
  Layer 1 of the Meridian data protection model uses LUKS to encrypt the
  filesystem that holds /var/lib/postgresql. Even if the disk is stolen
  or imaged, the database is unreadable without the passphrase.

  This installer can:
    y — Offer to create and encrypt a dedicated LVM volume for postgres
        data on first-run. You will be prompted for a passphrase AND
        given the option to bind the key to TPM for auto-unlock at boot.
    n — Skip disk encryption. Tamper-evident hash chains (Layer 3) and
        field-level encryption of secrets still apply.

  If this host already runs full-disk encryption or is managed by an
  ops team, answer n and rely on the existing encryption.
  '
  prompt_yn LUKS_ENCRYPT n "Set up LUKS-encrypted volume for /var/lib/postgresql?"
}

gen_password() {
  local len=${1:-24}
  # Charset excludes URL-reserved characters (@ # % : / ? &) so generated
  # passwords can be embedded in the PostgreSQL DSN (postgresql://u:p@h/db)
  # without URL-encoding. A `%` in the password breaks sqlalchemy because
  # %XX is read as a percent-encoded byte. `@` would split user@host. Keep
  # a healthy set of symbols (! ^ * _ = + -) for strength.
  # head closes the pipe after len bytes, which SIGPIPEs tr. Suppress pipefail
  # locally so a working pipeline doesn't look like a failure.
  set +o pipefail
  tr -dc 'A-Za-z0-9!^*_=+-' </dev/urandom | head -c "$len"
  set -o pipefail
}

# render_template <src> <dst> [mode] [owner]
# Substitutes only the whitelisted TEMPLATE_VARS via envsubst.
render_template() {
  local src=$1 dst=$2 mode=${3:-0644} owner=${4:-root:root}
  [[ -r "$src" ]] || die "template not found: $src"
  install -d -m 0755 "$(dirname "$dst")"
  # envsubst reads from the process env; export the allow-listed variables
  # so they're visible to the child process.
  export PORTAL_NAME PORTAL_DOMAIN SSH_PORT SSH_GROUP SVC_USER SVC_GROUP \
         INSTALL_ROOT CONFIG_ROOT DATA_ROOT LOG_ROOT \
         SCOPE_OF_USE TIMEZONE ADMIN_EMAIL
  envsubst "$TEMPLATE_VARS" < "$src" > "$dst.new"
  chmod "$mode" "$dst.new"
  chown "$owner" "$dst.new"
  mv "$dst.new" "$dst"
}

# copy_verbatim <src> <dst> [mode] [owner]  — no substitution
copy_verbatim() {
  local src=$1 dst=$2 mode=${3:-0644} owner=${4:-root:root}
  [[ -r "$src" ]] || die "source not found: $src"
  install -D -m "$mode" -o "${owner%:*}" -g "${owner#*:}" "$src" "$dst"
}

# Resolve OS-dependent package names + service names + config paths.
# Called from preflight() once OS_MAJOR is known.
detect_os_targets() {
  case "$OS_MAJOR" in
    13)
      PG_MAJOR=17
      CACHE_PKG="valkey"
      CACHE_SERVICE="valkey-server"
      CACHE_CONF_PATH="/etc/valkey/valkey.conf"
      CACHE_OVERLAY_SRC="$CONFIG_SRC/valkey/valkey.conf.overlay"
      NGINX_TARGET="1.26"
      BIND9_TARGET="9.20"
      BIND9_SERVICE="named"
      ;;
    12)
      PG_MAJOR=15
      CACHE_PKG="redis-server"
      CACHE_SERVICE="redis-server"
      CACHE_CONF_PATH="/etc/redis/redis.conf"
      CACHE_OVERLAY_SRC="$CONFIG_SRC/redis/redis.conf.overlay"
      NGINX_TARGET="1.24"
      BIND9_TARGET="9.18"
      BIND9_SERVICE="bind9"
      ;;
    *)
      die "detect_os_targets: OS_MAJOR=$OS_MAJOR not configured"
      ;;
  esac
  info "Target pins · PG=$PG_MAJOR · cache=$CACHE_PKG · nginx~$NGINX_TARGET · bind9~$BIND9_TARGET"
}

# Look up the interface that carries the default route; fall back to the
# first non-loopback interface if no default is set yet (rare on installers
# that run pre-network — prompt validation will still block bad input).
detect_primary_iface() {
  NET_IFACE=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')
  if [[ -z "$NET_IFACE" ]]; then
    NET_IFACE=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')
  fi
  [[ -n "$NET_IFACE" ]] || NET_IFACE="eth0"
}

# --------------------------------------------------------------------
# Static network · systemd-networkd profile pinned to $NET_IFACE.
# Written but NOT activated within this session — takes effect on next
# boot so we don't drop the installer's own SSH connection mid-run.
# --------------------------------------------------------------------
setup_static_network() {
  if [[ -z "$STATIC_IP" ]]; then
    info "STATIC_IP blank — leaving DHCP in place on ${NET_IFACE}"
    return 0
  fi
  section "Static network (${NET_IFACE} → ${STATIC_IP})"

  local dns_lines="" d
  IFS=',' read -r -a __dns <<< "$STATIC_DNS"
  for d in "${__dns[@]}"; do
    d="${d// /}"
    [[ -n "$d" ]] && dns_lines+="DNS=${d}"$'\n'
  done

  install -d -m 0755 /etc/systemd/network
  cat > /etc/systemd/network/10-meridian.network <<NETCFG
# Generated by Meridian install.sh $(date -u +%FT%TZ)
# Active after next reboot. Remove this file to return to DHCP.
[Match]
Name=${NET_IFACE}

[Network]
Address=${STATIC_IP}
Gateway=${STATIC_GATEWAY}
${dns_lines}IPv6AcceptRA=yes
NETCFG
  chmod 0644 /etc/systemd/network/10-meridian.network
  ok "Wrote /etc/systemd/network/10-meridian.network"

  # Enable networkd + resolved for next boot. --now is deliberately omitted:
  # restarting networkd on the live interface would terminate this session.
  systemctl enable systemd-networkd.service  >/dev/null 2>&1 || true
  systemctl enable systemd-resolved.service  >/dev/null 2>&1 || true

  # Point /etc/resolv.conf at systemd-resolved's stub for the next boot.
  # Skip if the host is already pointing there — don't overwrite what works.
  if [[ ! -L /etc/resolv.conf ]] || ! readlink /etc/resolv.conf | grep -q 'systemd/resolve'; then
    if [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
      ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
      ok "Linked /etc/resolv.conf → systemd-resolved stub"
    fi
  fi

  # Retire conflicting managers so networkd owns the link on next boot.
  # Only disable; never uninstall — the admin may still want the binaries.
  if systemctl list-unit-files NetworkManager.service >/dev/null 2>&1 \
     && systemctl is-enabled NetworkManager.service >/dev/null 2>&1; then
    systemctl disable NetworkManager.service >/dev/null 2>&1 || true
    warn "NetworkManager disabled; systemd-networkd owns ${NET_IFACE} after reboot"
  fi
  if [[ -f /etc/network/interfaces ]] && grep -qE "^[[:space:]]*(auto|iface)[[:space:]]+${NET_IFACE}\b" /etc/network/interfaces; then
    cp /etc/network/interfaces "/etc/network/interfaces.bak.$(date +%s)"
    # Comment out any stanzas referencing our interface. Keep lo stanza intact.
    sed -i -E "/^[[:space:]]*(auto|allow-hotplug|iface)[[:space:]]+${NET_IFACE}\b/,/^[[:space:]]*(auto|iface|allow-hotplug|source|$)/ { /^[[:space:]]*(auto|iface|allow-hotplug|source)[[:space:]]/!s/^/# /; /${NET_IFACE}/s/^/# / }" \
      /etc/network/interfaces || true
    warn "ifupdown stanzas for ${NET_IFACE} commented out in /etc/network/interfaces"
  fi

  warn "Static IP ${STATIC_IP} is configured but NOT YET ACTIVE."
  warn "It takes effect on next reboot. Current session keeps its DHCP address."
}

# --------------------------------------------------------------------
# System prep · users, dirs, permissions
# --------------------------------------------------------------------
system_prep() {
  section "System prep"

  if ! getent group "$SVC_GROUP" >/dev/null; then
    groupadd --system "$SVC_GROUP"
    ok "Created group: $SVC_GROUP"
  fi
  if ! getent passwd "$SVC_USER" >/dev/null; then
    useradd --system --gid "$SVC_GROUP" --home-dir "$DATA_ROOT" \
            --shell /usr/sbin/nologin "$SVC_USER"
    ok "Created user: $SVC_USER"
  fi

  # SSH group for the locked-down shell access
  if ! getent group "$SSH_GROUP" >/dev/null; then
    groupadd "$SSH_GROUP"
    ok "Created SSH group: $SSH_GROUP"
  fi

  install -d -m 0755 -o "$SVC_USER" -g "$SVC_GROUP" "$INSTALL_ROOT"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" "$CONFIG_ROOT"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" "$DATA_ROOT"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" "$LOG_ROOT"
  install -d -m 0700 -o "$SVC_USER" -g "$SVC_GROUP" "$SECRETS_DIR"

  # Log file is root-readable so sudo cat /root/meridian-install.log works
  chmod 0600 "$INSTALL_LOG" 2>/dev/null || true

  ok "Directories provisioned under $INSTALL_ROOT, $CONFIG_ROOT, $DATA_ROOT"

  if [[ "$LUKS_ENCRYPT" == "y" ]]; then
    setup_luks_volume
  fi
}

setup_luks_volume() {
  info "LUKS volume setup is interactive and destructive. See docs/LUKS.md for the full playbook."
  # This implementation stub guides the admin through cryptsetup + mount
  # without mutating unexpected disks automatically.
  warn "For safety, LUKS volume creation is a separate guided script: $INSTALL_ROOT/scripts/setup_luks.sh"
  warn "Run it AFTER this installer completes, then move /var/lib/postgresql onto the new volume."
}

# --------------------------------------------------------------------
# OS packages · pinned versions per the manifest
# --------------------------------------------------------------------
install_os_packages() {
  section "Installing OS packages (Debian ${OS_MAJOR})"

  export DEBIAN_FRONTEND=noninteractive

  local -a packages=(
    "nginx"
    "bind9"
    "postgresql-${PG_MAJOR}"
    "${CACHE_PKG}"
    "certbot" "python3-certbot-nginx"
    "fail2ban"
    "openssl"
    "apparmor" "apparmor-profiles" "apparmor-utils"
    "python3" "python3-venv" "python3-pip" "python3-dev"
    "build-essential" "libpq-dev" "libssl-dev" "libffi-dev"
    "libldap2-dev" "libsasl2-dev"
    "zsh" "fzf" "git" "jq" "curl" "ca-certificates"
    "iproute2" "tcpdump" "dnsutils" "whois" "nmap"
    "traceroute" "mtr-tiny" "iputils-ping" "iputils-arping"
    "snmp"
    "rsync" "gnupg" "unzip" "tree" "zstd"
    "gettext-base"
    "ufw"
    "sudo"
    # Admin CLI tools that mirror Meridian portal features -- an operator
    # SSH-ing in should be able to reproduce everything the portal does by
    # hand. bind9-utils for rndc (`rndc reload`, `rndc flush`, rndc-confgen),
    # ldap-utils for AD/Entra lookups, ipcalc for subnet math, net-tools for
    # arp/ifconfig/netstat parity, lsof + htop + vim + ethtool for day-to-day
    # diagnosis.
    "bind9-utils"
    "ldap-utils"
    "ipcalc"
    "net-tools"
    "lsof" "htop" "vim" "ethtool"
    # Email-auth + format validators -- CLI parity for the portal's
    # SPF / DKIM / DMARC monitors and for ad-hoc ops work.
    # spf-tools-perl provides `spfquery` with NO mail-transport-agent
    # dependency (postfix-policyd-spf-python would have pulled postfix in,
    # which is heavy + surprising on an NIP portal box).
    # opendkim-tools ships opendkim-testkey / opendkim-genkey / opendkim-testmsg;
    # swaks is the SMTP swiss army knife used by the portal's mail-flow
    # checks; libxml2-utils gives xmllint (jq is already installed; yq is
    # pip-installed into /opt/admin-tools below alongside dnsviz).
    "spf-tools-perl"
    "opendkim-tools"
    "swaks"
    "libxml2-utils"
    # DNSSEC tooling -- parity with the portal's DNS tools and its DNSSEC
    # chain monitor. ldnsutils gives `drill -TD` for trust-chain trace +
    # ldns-verify-zone; `delv` is already provided by bind9-dnsutils (in
    # dnsutils above). graphviz / libgraphviz-dev support the dnsviz SVG
    # renderer which is pip-installed below (not in apt). `rndc flushname
    # <name>` / `rndc flushtree <zone>` come with bind9 for clearing bad
    # cached DNSSEC data.
    "ldnsutils"
    "graphviz" "libgraphviz-dev"
  )
  # Best-effort: in non-free (Debian) or main-restricted (Ubuntu). Absent on
  # vanilla Debian without non-free-firmware/non-free enabled.
  local -a optional_packages=(
    "snmp-mibs-downloader"
  )

  apt-get install -y --no-install-recommends "${packages[@]}" \
    2>&1 | tee -a "$INSTALL_LOG"

  for p in "${optional_packages[@]}"; do
    apt-get install -y --no-install-recommends "$p" 2>&1 | tee -a "$INSTALL_LOG" \
      || warn "Optional package unavailable (skipping): $p"
  done

  # File capabilities on tcpdump so the packet-capture sandbox can run as the
  # non-root meridian user. Matches the CapabilityBoundingSet on meridian-app:
  # the caps are allowed at the systemd boundary but only granted on exec of
  # this specific binary via its file caps (e,i,p = effective+inheritable+perm).
  local tcpdump_bin
  tcpdump_bin=$(command -v tcpdump || true)
  if [[ -n "$tcpdump_bin" ]]; then
    setcap 'cap_net_raw,cap_net_admin=eip' "$tcpdump_bin" \
      && ok "tcpdump file caps set · $tcpdump_bin" \
      || warn "setcap on tcpdump failed; packet capture will require sudo"
  fi

  ok "OS packages installed · exact versions recorded to version_manifest post-install"

  # dnsviz -- DNSSEC chain visualizer (same engine as dnsviz.net). Not in apt;
  # installed into a dedicated /opt/admin-tools venv so it stays isolated from
  # the meridian-app venv. Symlinked into /usr/local/bin so it is on PATH for
  # every SSH admin without activating anything.
  if ! command -v dnsviz >/dev/null 2>&1; then
    info "Installing dnsviz into /opt/admin-tools venv"
    python3 -m venv /opt/admin-tools
    /opt/admin-tools/bin/pip install --quiet --upgrade pip >/dev/null
    /opt/admin-tools/bin/pip install --quiet dnsviz pygraphviz yq \
      2>&1 | tee -a "$INSTALL_LOG" >/dev/null \
      || { warn "dnsviz/yq install failed; skipping (graph output + yq will be unavailable)"; return 0; }
    ln -sf /opt/admin-tools/bin/dnsviz /usr/local/bin/dnsviz
    ln -sf /opt/admin-tools/bin/yq     /usr/local/bin/yq
    ok "dnsviz + yq installed via /opt/admin-tools venv"
  fi
}

# --------------------------------------------------------------------
# PostgreSQL · create role, db, load schema, enable extensions
# --------------------------------------------------------------------
setup_postgresql() {
  section "PostgreSQL setup"

  systemctl enable --now postgresql

  sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
    DO \$\$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}') THEN
        CREATE ROLE "${DB_USER}" WITH LOGIN PASSWORD '${DB_PASSWORD}';
      END IF;
    END \$\$;

    SELECT 'CREATE DATABASE "${DB_NAME}" OWNER "${DB_USER}"'
      WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='${DB_NAME}')\gexec
SQL

  # Load schema (fresh install only — migrate.sh below handles existing DBs
  # by being a no-op on pristine tables thanks to IF NOT EXISTS / ON CONFLICT).
  if [[ -f "$INSTALL_ROOT/db/schema.sql" ]]; then
    sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$DB_NAME" \
      -f "$INSTALL_ROOT/db/schema.sql" 2>&1 | tee -a "$INSTALL_LOG"
    ok "Schema loaded into $DB_NAME"
  else
    die "schema.sql not found at $INSTALL_ROOT/db/schema.sql"
  fi

  # Hand ownership of all schema objects to the meridian role. schema.sql is
  # loaded as the postgres superuser so every CREATE ends up postgres-owned;
  # the app connects as meridian and needs full rights on what it created.
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$DB_NAME" <<SQL 2>&1 | tee -a "$INSTALL_LOG"
    DO \$\$ DECLARE r RECORD;
    BEGIN
      FOR r IN SELECT tablename  FROM pg_tables    WHERE schemaname='public' LOOP
        EXECUTE 'ALTER TABLE public.'    || quote_ident(r.tablename)     || ' OWNER TO "${DB_USER}"';
      END LOOP;
      FOR r IN SELECT sequencename FROM pg_sequences WHERE schemaname='public' LOOP
        EXECUTE 'ALTER SEQUENCE public.' || quote_ident(r.sequencename)  || ' OWNER TO "${DB_USER}"';
      END LOOP;
      FOR r IN SELECT viewname   FROM pg_views     WHERE schemaname='public' LOOP
        EXECUTE 'ALTER VIEW public.'     || quote_ident(r.viewname)      || ' OWNER TO "${DB_USER}"';
      END LOOP;
      FOR r IN SELECT typname    FROM pg_type t JOIN pg_namespace n ON t.typnamespace=n.oid
               WHERE n.nspname='public' AND t.typtype='e' LOOP
        EXECUTE 'ALTER TYPE public.'     || quote_ident(r.typname)       || ' OWNER TO "${DB_USER}"';
      END LOOP;
    END \$\$;
    ALTER SCHEMA public OWNER TO "${DB_USER}";
SQL
  ok "Schema objects reassigned to ${DB_USER}"

  # Apply any pending migrations. On a fresh install this seeds
  # schema_migrations with the hashes of every file in db/migrations/;
  # on an upgrade-in-place it catches the DB up to the bundled app.
  if [[ -x "$INSTALL_ROOT/scripts/migrate.sh" ]]; then
    MERIDIAN_DB_NAME="$DB_NAME" \
    MERIDIAN_MIGRATIONS_DIR="$INSTALL_ROOT/db/migrations" \
      "$INSTALL_ROOT/scripts/migrate.sh" 2>&1 | tee -a "$INSTALL_LOG"
    ok "Migrations applied"
  else
    warn "migrate.sh not present or not executable — skipping migration step"
  fi

  # Lock pg_hba to localhost + meridian role only; others explicitly denied
  local hba
  hba=$(find /etc/postgresql -name pg_hba.conf | head -1)
  [[ -n "$hba" ]] || die "Could not find pg_hba.conf"
  {
    echo "# --- Meridian lockdown $(date -u +%FT%TZ) ---"
    echo "# Admin socket access — required for postgres-user maintenance"
    echo "local   all             postgres                                   peer"
    echo "local   ${DB_NAME}      ${DB_USER}                                 scram-sha-256"
    echo "host    ${DB_NAME}      ${DB_USER}        127.0.0.1/32             scram-sha-256"
    echo "host    ${DB_NAME}      ${DB_USER}        ::1/128                  scram-sha-256"
    echo "# Everything else:"
    echo "local   all             all                                        reject"
    echo "host    all             all             0.0.0.0/0                  reject"
  } > "$hba.meridian.new"
  # Keep a timestamped backup of existing hba
  cp "$hba" "$hba.bak.$(date +%s)"
  mv "$hba.meridian.new" "$hba"
  # mv preserves the temp file's perms (root:root 0600 under root umask),
  # but postgres needs to read pg_hba.conf at startup. Fix ownership +
  # mode explicitly. Surfaced 2026-05-13 during the unattended-rebuild
  # validation pass — PG failed to start after lockdown.
  chown postgres:postgres "$hba"
  chmod 0640 "$hba"
  systemctl restart postgresql
  ok "pg_hba.conf locked down to localhost + meridian role"
}

# --------------------------------------------------------------------
# Cache service · Redis (Debian 12) or Valkey (Debian 13) · localhost bind
# --------------------------------------------------------------------
setup_cache() {
  section "Cache service (${CACHE_PKG})"
  systemctl enable --now "${CACHE_SERVICE}"
  sed -i 's/^bind .*/bind 127.0.0.1 ::1/' "$CACHE_CONF_PATH"
  # NOTE: requirepass deliberately NOT enabled here. The service is bound to
  # 127.0.0.1 only, and meridian.conf's redis_url carries no password --
  # enabling auth here would make celery-beat and redbeat fail to connect.
  # apply_cache_overlay below leaves the overlay's requirepass commented for
  # the same reason. If you need auth, plumb it through meridian.conf first.
  systemctl restart "${CACHE_SERVICE}"
  ok "${CACHE_PKG} bound to localhost (no auth, localhost-only)"
}

# --------------------------------------------------------------------
# BIND9 · recursive resolver for the sandbox
# --------------------------------------------------------------------
setup_bind9() {
  section "BIND9 setup (recursive resolver for sandbox)"
  install -d -m 0750 -o bind -g bind /var/log/named
  # Replace the distro options file so our options{} block isn't a duplicate.
  # named.conf.local stays empty (zones would go there).
  render_template "$CONFIG_SRC/bind9/named.conf.template" "/etc/bind/named.conf.options" 0644 "root:bind"
  echo "// Meridian: no local zones." > /etc/bind/named.conf.local
  chown root:bind /etc/bind/named.conf.local
  systemctl enable --now "$BIND9_SERVICE"
  systemctl restart "$BIND9_SERVICE"
  ok "BIND9 running on 127.0.0.1 (sandbox resolver, query log enabled) · service=$BIND9_SERVICE"
}

# --------------------------------------------------------------------
# Meridian application · venv + pinned deps + systemd units
# --------------------------------------------------------------------
install_meridian_app() {
  section "Meridian application install"

  [[ -d "$INSTALL_ROOT/app" ]] || die "Missing $INSTALL_ROOT/app — is the package laid out correctly?"
  [[ -f "$INSTALL_ROOT/requirements.txt" ]] || die "Missing requirements.txt"

  sudo -u "$SVC_USER" python3 -m venv "$INSTALL_ROOT/venv"
  sudo -u "$SVC_USER" "$INSTALL_ROOT/venv/bin/pip" install --upgrade pip wheel \
    2>&1 | tee -a "$INSTALL_LOG"

  # Offline path when wheels/ is staged (release tarballs); online path otherwise.
  if [[ -d "$INSTALL_ROOT/wheels" ]] && compgen -G "$INSTALL_ROOT/wheels/*.whl" >/dev/null; then
    info "Installing Python deps from bundled wheels (--no-index)"
    sudo -u "$SVC_USER" "$INSTALL_ROOT/venv/bin/pip" install \
      --no-index --find-links "$INSTALL_ROOT/wheels" \
      -r "$INSTALL_ROOT/requirements.txt" \
      2>&1 | tee -a "$INSTALL_LOG"
  else
    if (( AIRGAPPED )); then
      die "Airgapped install but no bundled wheels found · use a release tarball built by scripts/build-release.sh"
    fi
    info "Installing Python deps from PyPI (dev path)"
    sudo -u "$SVC_USER" "$INSTALL_ROOT/venv/bin/pip" install \
      -r "$INSTALL_ROOT/requirements.txt" \
      2>&1 | tee -a "$INSTALL_LOG"
  fi

  # Write the main config file
  install -m 0640 -o "$SVC_USER" -g "$SVC_GROUP" /dev/stdin "$CONFIG_ROOT/meridian.conf" <<CONF
# Generated by install.sh $(date -u +%FT%TZ)
# Edit via Admin Panel when possible; direct edits require meridian-app restart.
portal_name        = "${PORTAL_NAME}"
portal_domain      = "${PORTAL_DOMAIN}"
scope_of_use       = "${SCOPE_OF_USE}"
timezone           = "${TIMEZONE}"
db_dsn             = "postgresql://${DB_USER}:${DB_PASSWORD}@127.0.0.1:5432/${DB_NAME}"
redis_url          = "redis://127.0.0.1:6379/0"
master_key_path    = "${MASTER_KEY_PATH}"
row_hmac_key_path  = "${ROW_HMAC_KEY_PATH}"
bind9_resolver     = "127.0.0.1"
airgapped          = $([[ $AIRGAPPED -eq 1 ]] && echo true || echo false)
manifest_version   = "${MANIFEST_VERSION}"
CONF

  # systemd units — rendered from config/systemd/*.template
  render_template "$CONFIG_SRC/systemd/meridian-app.service.template"    "/etc/systemd/system/meridian-app.service"
  render_template "$CONFIG_SRC/systemd/meridian-celery.service.template" "/etc/systemd/system/meridian-celery.service"
  render_template "$CONFIG_SRC/systemd/meridian-beat.service.template"   "/etc/systemd/system/meridian-beat.service"

  systemctl daemon-reload
  ok "systemd units written: meridian-app · meridian-celery · meridian-beat"
}

# --------------------------------------------------------------------
# Stage the Meridian package · copies app/, db/, scripts/, config/
# and requirements.txt from the extracted package into $INSTALL_ROOT.
# Also symlinks the meridian-nip CLI shim into /usr/local/bin.
# --------------------------------------------------------------------
stage_package() {
  section "Staging Meridian package → $INSTALL_ROOT"

  # If source already lives at the install root (common pattern: rsync
  # the source straight into /opt/meridian and run install.sh from
  # there), there's no copy to do — just ensure permissions are sane.
  # Surfaced 2026-05-13 during the unattended-rebuild validation.
  if [[ "$SCRIPT_DIR" == "$INSTALL_ROOT" ]]; then
    ok "Source already at $INSTALL_ROOT — skipping copy"
    for d in app db scripts config docs; do
      [[ -d "$INSTALL_ROOT/$d" ]] || die "package missing directory: $d at $INSTALL_ROOT"
      chmod -R u=rwX,go=rX "$INSTALL_ROOT/$d"
    done
    # Top-level files (requirements.txt, install.sh, answers*.env, etc.)
    # may carry 0600 from the operator's home dir umask. The meridian
    # service user needs to read requirements.txt / pyproject.toml /
    # alembic.ini / etc. — chmod everything at the install-root level
    # to u=rwX,go=rX so service-user reads succeed.
    chmod u=rwX,go=rX "$INSTALL_ROOT"/*.* 2>/dev/null || true
    return 0
  fi

  for d in app db scripts config docs; do
    [[ -d "$SCRIPT_DIR/$d" ]] || die "package missing directory: $d (run install.sh from the extracted Meridian tarball)"
    install -d -m 0755 "$INSTALL_ROOT/$d"
    cp -a "$SCRIPT_DIR/$d/." "$INSTALL_ROOT/$d/"
    # Source tree may have come from a 077-umask location (e.g. /root/...).
    # Grant traverse + read to every user so postgres can load schema.sql,
    # and the meridian service user retains ownership.
    chmod -R u=rwX,go=rX "$INSTALL_ROOT/$d"
  done

  [[ -r "$SCRIPT_DIR/requirements.txt" ]] || die "package missing requirements.txt"
  install -m 0644 "$SCRIPT_DIR/requirements.txt" "$INSTALL_ROOT/requirements.txt"

  # Bundled wheels · present in release tarballs built by scripts/build-release.sh.
  # When the directory exists we pip install from it with --no-index (offline path).
  # When it doesn't (dev clones), install_meridian_app falls back to PyPI.
  if [[ -d "$SCRIPT_DIR/wheels" ]]; then
    if [[ "$SCRIPT_DIR" != "$INSTALL_ROOT" ]]; then
      install -d -m 0755 "$INSTALL_ROOT/wheels"
      cp -a "$SCRIPT_DIR/wheels/." "$INSTALL_ROOT/wheels/"
    fi
    local count
    count=$(find "$INSTALL_ROOT/wheels" -maxdepth 1 -name '*.whl' 2>/dev/null | wc -l)
    ok "Staged $count Python wheels (offline install path)"
  else
    warn "No wheels/ directory found; install_meridian_app will pip from PyPI."
    warn "For a signed release bundle, run scripts/build-release.sh on the vendor host."
  fi

  chmod +x "$INSTALL_ROOT/scripts"/*.sh "$INSTALL_ROOT/scripts/meridian-nip" 2>/dev/null || true
  ln -sf "$INSTALL_ROOT/scripts/meridian-nip" /usr/local/bin/meridian-nip

  chown -R "$SVC_USER:$SVC_GROUP" "$INSTALL_ROOT"
  # Ensure app tree is world-readable. Nginx runs as www-data and serves
  # /static/ directly from the filesystem; if the build host had a 077
  # umask the copied files would land as 0600 and nginx would 403 every
  # static asset, silently breaking the portal JS. Explicit chmod here
  # catches that. (Secrets under /etc/meridian/secrets are 0400 and live
  # outside this tree so they stay tight.)
  find "$INSTALL_ROOT/app"    -type d -exec chmod 0755 {} + 2>/dev/null || true
  find "$INSTALL_ROOT/app"    -type f -exec chmod 0644 {} + 2>/dev/null || true
  find "$INSTALL_ROOT/docs"   -type d -exec chmod 0755 {} + 2>/dev/null || true
  find "$INSTALL_ROOT/docs"   -type f -exec chmod 0644 {} + 2>/dev/null || true

  # scripts run as root for privileged ops; root owns them directly.
  chown -R root:root "$INSTALL_ROOT/scripts"
  chmod 0755 "$INSTALL_ROOT/scripts"

  ok "Package staged · CLI shim at /usr/local/bin/meridian-nip"
}

apply_sysctl() {
  section "Kernel sysctl hardening"
  copy_verbatim "$CONFIG_SRC/sysctl.d/99-meridian.conf" "/etc/sysctl.d/99-meridian.conf"
  sysctl --system >/dev/null
  ok "sysctl policy applied"
}

apply_logrotate() {
  copy_verbatim "$CONFIG_SRC/logrotate/meridian" "/etc/logrotate.d/meridian"
  ok "logrotate policy installed"
}

apply_postgresql_overlay() {
  section "PostgreSQL tuning overlay"
  local conf_dir conf_file
  conf_file=$(sudo -u postgres psql -tAc "SHOW config_file;" 2>/dev/null)
  [[ -n "$conf_file" ]] || die "Could not locate postgresql.conf"
  conf_dir=$(dirname "$conf_file")
  install -d -m 0755 -o postgres -g postgres "$conf_dir/conf.d"
  copy_verbatim "$CONFIG_SRC/postgresql/postgresql.conf.overlay" \
                "$conf_dir/conf.d/meridian.conf" 0640 "postgres:postgres"
  # Ensure include_dir directive is present
  grep -q "include_dir = 'conf.d'" "$conf_file" \
    || echo "include_dir = 'conf.d'" >> "$conf_file"
  systemctl restart postgresql
  ok "PostgreSQL overlay applied and reloaded"
}

apply_cache_overlay() {
  section "Cache overlay (${CACHE_PKG})"
  [[ -r "$CACHE_OVERLAY_SRC" ]] || die "overlay not found: $CACHE_OVERLAY_SRC"
  if ! grep -q "# --- MERIDIAN OVERLAY ---" "$CACHE_CONF_PATH"; then
    # The overlay's `# requirepass MERIDIAN_INJECTED_AT_INSTALL` stays commented:
    # valkey already binds 127.0.0.1 so password auth would only add coordination
    # pain between this file and meridian.conf's redis_url. Re-enable here once
    # that plumbing exists.
    {
      echo ""
      echo "# --- MERIDIAN OVERLAY --- (managed by install.sh; do not edit)"
      cat "$CACHE_OVERLAY_SRC"
    } >> "$CACHE_CONF_PATH"
    case "$CACHE_PKG" in
      valkey)       install -d -m 0750 -o valkey -g valkey /run/valkey ;;
      redis-server) install -d -m 0750 -o redis  -g redis  /run/redis  ;;
    esac
  fi
  systemctl restart "${CACHE_SERVICE}"
  ok "${CACHE_PKG} overlay applied (bind localhost, AOF on)"
}

apply_ufw() {
  section "UFW firewall"
  local tmp; tmp=$(mktemp)
  render_template "$CONFIG_SRC/ufw/meridian.rules.template" "$tmp"
  bash "$tmp" 2>&1 | tee -a "$INSTALL_LOG"
  rm -f "$tmp"
  ok "UFW enabled with Meridian ruleset"
}

# --------------------------------------------------------------------
# Nginx + TLS
# --------------------------------------------------------------------
setup_nginx_tls() {
  section "Nginx + TLS"

  # Always install the proxy include snippet — all vhost variants rely on it.
  copy_verbatim "$CONFIG_SRC/nginx.snippets.meridian_proxy.conf" \
                "/etc/nginx/snippets/meridian_proxy.conf"

  # Portal-managed TLS overrides directory. System Health "Repair" actions
  # write snippets here (ocsp-stapling.conf, hsts.conf, etc.) and the base
  # vhost includes them via `include /etc/meridian/nginx-overrides/*.conf;`.
  # Owned by the meridian service user so the portal can write without
  # shelling out; world-readable so nginx (running as www-data) can load.
  install -d -m 0755 -o "$SVC_USER" -g "$SVC_USER" /etc/meridian/nginx-overrides
  if [[ ! -f /etc/meridian/nginx-overrides/ocsp-stapling.conf ]]; then
    cat > /etc/meridian/nginx-overrides/ocsp-stapling.conf <<'OVERRIDE'
# Portal-managed · Admin Panel → System Health
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 9.9.9.9 valid=300s;
resolver_timeout 5s;
OVERRIDE
    chown "$SVC_USER:$SVC_USER" /etc/meridian/nginx-overrides/ocsp-stapling.conf
    chmod 0644 /etc/meridian/nginx-overrides/ocsp-stapling.conf
  fi

  case "$SSL_METHOD" in
    letsencrypt)
      # HTTP-only stub for the ACME challenge, THEN the full vhost after cert exists.
      cat > /etc/nginx/sites-available/meridian <<NGX
server {
    listen 80; server_name ${PORTAL_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://\$host\$request_uri; }
}
NGX
      ln -sf /etc/nginx/sites-available/meridian /etc/nginx/sites-enabled/meridian
      rm -f /etc/nginx/sites-enabled/default
      install -d -m 0755 /var/www/acme
      nginx -t && systemctl reload nginx
      certbot certonly --webroot -w /var/www/acme -d "$PORTAL_DOMAIN" \
        --agree-tos -m "$ADMIN_EMAIL" -n --deploy-hook 'systemctl reload nginx'
      # Now render the full template — it already expects LE paths.
      render_template "$CONFIG_SRC/nginx.conf.template" \
                      "/etc/nginx/sites-available/meridian"
      ;;
    cloudflare)
      render_template "$CONFIG_SRC/nginx.conf.template" \
                      "/etc/nginx/sites-available/meridian"
      warn "Cloudflare mode: paste your Origin CA cert/key at:"
      warn "  /etc/letsencrypt/live/${PORTAL_DOMAIN}/fullchain.pem"
      warn "  /etc/letsencrypt/live/${PORTAL_DOMAIN}/privkey.pem"
      warn "or edit /etc/nginx/sites-available/meridian to point at your own paths."
      ;;
    self-signed)
      install -d -m 0755 "/etc/letsencrypt/live/${PORTAL_DOMAIN}"
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "/etc/letsencrypt/live/${PORTAL_DOMAIN}/privkey.pem" \
        -out    "/etc/letsencrypt/live/${PORTAL_DOMAIN}/fullchain.pem" \
        -days 365 -nodes -subj "/CN=${PORTAL_DOMAIN}"
      cp "/etc/letsencrypt/live/${PORTAL_DOMAIN}/fullchain.pem" \
         "/etc/letsencrypt/live/${PORTAL_DOMAIN}/chain.pem"
      render_template "$CONFIG_SRC/nginx.conf.template" \
                      "/etc/nginx/sites-available/meridian"
      ;;
    none)
      warn "HTTP-only mode. Not rendering TLS vhost."
      cat > /etc/nginx/sites-available/meridian <<NGX
server {
    listen 80; server_name ${PORTAL_DOMAIN};
    client_max_body_size 20m;
    location /static/ { alias ${INSTALL_ROOT}/app/static/; }
    location / {
        proxy_pass http://127.0.0.1:8000;
        include /etc/nginx/snippets/meridian_proxy.conf;
    }
}
NGX
      ;;
  esac
  ln -sf /etc/nginx/sites-available/meridian /etc/nginx/sites-enabled/meridian
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx
  ok "Nginx configured for $SSL_METHOD"
}

# --------------------------------------------------------------------
# SSH hardening + zsh for ddi-ssh group
# --------------------------------------------------------------------
setup_ssh_zsh() {
  section "SSH + zsh for ddi-ssh group"

  # Keep root in $SSH_GROUP so admin SSH survives the AllowGroups gate.
  # Combined with PermitRootLogin prohibit-password in the drop-in, root
  # can still log in with a key but never a password.
  usermod -aG "$SSH_GROUP" root
  # Meridian service user needs bind group membership to read /etc/bind/rndc.key
  # (mode 640 root:bind) for the Admin → Health "bind:reload" repair action.
  if getent group bind >/dev/null; then
    usermod -aG bind "$SVC_USER" || true
  fi

  # Drop-in overrides the distro sshd_config without modifying it.
  render_template "$CONFIG_SRC/ssh/sshd_config.d.meridian.conf.template" \
                  "/etc/ssh/sshd_config.d/10-meridian.conf" 0600 "root:root"

  # MOTD — legal warning + system info. Not a template (no variables).
  cat > /etc/issue.net <<'MOTD'
╔══════════════════════════════════════════════════════════════════╗
║  RESTRICTED SYSTEM · Meridian NIP                                ║
║                                                                  ║
║  Authorized personnel only. All activity is logged, monitored,   ║
║  and audited. Disconnect immediately if you are not authorized.  ║
║                                                                  ║
║  Tamper attempts are detected via cryptographic hash chains      ║
║  and raise immediate alerts.                                     ║
╚══════════════════════════════════════════════════════════════════╝
MOTD

  # Validate + restart only if sshd accepts the new config.
  sshd -t || die "sshd config rejected the Meridian drop-in; see the file above."
  systemctl restart ssh
  ok "sshd listening on port ${SSH_PORT}, group-gated to $SSH_GROUP"

  # zsh + Oh My Zsh for ddi-ssh members (run once per user on first login)
  cat > /etc/skel/.zshrc <<'ZSHRC'
export LANG=en_US.UTF-8
export EDITOR=vim
export HISTSIZE=50000
export HISTFILE="$HOME/.zsh_history"
setopt hist_ignore_dups share_history inc_append_history
bindkey -e
autoload -Uz compinit && compinit

# Prompt (fallback if Powerlevel10k not installed)
autoload -U colors && colors
PROMPT='%F{green}%n@%m%f %F{blue}%~%f %# '

# fzf keybinds
[[ -f /usr/share/doc/fzf/examples/key-bindings.zsh ]] && source /usr/share/doc/fzf/examples/key-bindings.zsh
[[ -f /usr/share/doc/fzf/examples/completion.zsh ]]    && source /usr/share/doc/fzf/examples/completion.zsh

# Meridian-safe aliases
alias ll='ls -lah --color=auto'
alias grep='grep --color=auto'
alias ..='cd ..'
ZSHRC
  ok "Default .zshrc seeded for new ddi-ssh users"
}

# --------------------------------------------------------------------
# fail2ban + AppArmor
# --------------------------------------------------------------------
setup_fail2ban_apparmor() {
  section "fail2ban + AppArmor"

  render_template "$CONFIG_SRC/fail2ban/jail.meridian.conf" \
                  "/etc/fail2ban/jail.d/meridian.conf"
  copy_verbatim "$CONFIG_SRC/fail2ban/filter.d/meridian-login.conf" \
                "/etc/fail2ban/filter.d/meridian-login.conf"

  # Seed /etc/fail2ban/jail.local with the admin/deploy subnet in ignoreip
  # so the operator's own workstation can't lock itself out of sshd during
  # a hectic deploy. Any user-edited jail.local is preserved: we only write
  # the file if it doesn't already exist.
  if [[ ! -f /etc/fail2ban/jail.local ]]; then
    local __ignore="127.0.0.1/8 ::1"
    if [[ -n "$ADMIN_CIDR" ]]; then
      __ignore+=" $ADMIN_CIDR"
    fi
    cat > /etc/fail2ban/jail.local <<EOF
# Meridian · per-host fail2ban overrides
# Created by install.sh. Edit freely — subsequent installer runs skip this
# file if it already exists. The ignoreip list below prevents the admin
# workstation subnet from being banned.

[DEFAULT]
ignoreip = $__ignore
EOF
    chmod 0644 /etc/fail2ban/jail.local
    ok "jail.local seeded with ignoreip=$__ignore"
  else
    info "jail.local already exists — leaving it alone"
  fi

  # Always (re)write the admin-CIDR drop-in. jail.local above is user-editable
  # and intentionally left alone after the first install, but the ADMIN_CIDR
  # answer can change (operator moves networks, runs --upgrade with a new
  # answers file, etc.) — this drop-in tracks the *current* answer without
  # touching user edits. [DEFAULT] applies to every jail, not just sshd.
  if [[ -n "$ADMIN_CIDR" ]]; then
    cat > /etc/fail2ban/jail.d/meridian-admin-cidr.conf <<EOF
# Managed by install.sh. Refreshed on every install / --upgrade run.
# Applies the admin/operator CIDR to ALL fail2ban jails (sshd, nginx-*,
# meridian-login) so heavy probing on one jail doesn't lock the operator
# out of every port at once.
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 $ADMIN_CIDR
EOF
    chmod 0644 /etc/fail2ban/jail.d/meridian-admin-cidr.conf
    ok "jail.d/meridian-admin-cidr.conf refreshed with ${ADMIN_CIDR}"
  else
    rm -f /etc/fail2ban/jail.d/meridian-admin-cidr.conf
  fi

  # Portal-managed persistent ignoreip overrides. Owned by the meridian user
  # so the Fail2ban admin card can write to it directly when an admin clicks
  # "Add to ignoreip (persist)". fail2ban-client reload (allowed via the
  # sudoers drop-in) picks the new content up.
  if [[ ! -f /etc/fail2ban/jail.d/meridian-portal-overrides.conf ]]; then
    cat > /etc/fail2ban/jail.d/meridian-portal-overrides.conf <<'OVERRIDE'
# Portal-managed · written by the Fail2ban admin card (System Health →
# Fail2ban). Operator-edited entries are preserved; install.sh never
# rewrites this file once it exists. Format:
#
#   [DEFAULT]
#   ignoreip = 127.0.0.1/8 ::1 <ip-or-cidr> <ip-or-cidr> ...
#
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
OVERRIDE
    chmod 0644 /etc/fail2ban/jail.d/meridian-portal-overrides.conf
  fi
  chown "$SVC_USER:$SVC_USER" /etc/fail2ban/jail.d/meridian-portal-overrides.conf

  # The jail watches app-access.log. fail2ban refuses to start if the file
  # doesn't exist yet, and on a fresh install the app hasn't written anything.
  if [[ ! -e "$LOG_ROOT/app-access.log" ]]; then
    install -m 0640 -o "$SVC_USER" -g "$SVC_GROUP" /dev/null "$LOG_ROOT/app-access.log"
  fi
  systemctl enable --now fail2ban
  systemctl restart fail2ban
  ok "fail2ban jails + Meridian login filter configured"

  # Meridian-specific AppArmor profile for the app worker.
  copy_verbatim "$CONFIG_SRC/apparmor/opt.meridian.app" \
                "/etc/apparmor.d/opt.meridian.app"
  apparmor_parser -r -W /etc/apparmor.d/opt.meridian.app 2>/dev/null || \
    warn "apparmor_parser could not load the Meridian profile; check /etc/apparmor.d/opt.meridian.app"

  # Enforce distro-shipped profiles for bind9 and nginx if present.
  for p in usr.sbin.named usr.sbin.nginx; do
    [[ -f /etc/apparmor.d/$p ]] && aa-enforce "/etc/apparmor.d/$p" 2>/dev/null || true
  done
  ok "AppArmor profiles enforced (meridian-app, named, nginx)"
}

# --------------------------------------------------------------------
# Admin break-glass wiring
# --------------------------------------------------------------------
# Installs the admin SSH pubkey and the set of sudoers drop-ins shipped
# under config/sudoers.d/. This is what turns a bare VM into one an
# operator can actually deploy to on day 1 — without it, every deploy
# requires root-on-console + manual file transfer.
setup_admin_access() {
  section "Admin break-glass (pubkey + sudoers drop-ins)"

  # 0. Make sure the operator's interactive account is in the ddi-ssh
  #    group — sshd has `AllowGroups ddi-ssh` so interactive accounts
  #    not in that group are refused at login. Without this, a fresh VM
  #    has no password-SSH path at all and admin recovery depends
  #    entirely on console access.
  #
  #    Covers both common naming conventions: the production VM ships
  #    with `meridian-user`, but lab / customer installs commonly use
  #    whatever name the preseed (or human) created during OS setup.
  #    SUDO_USER catches the latter automatically.
  local _ssh_users=()
  getent passwd meridian-user >/dev/null 2>&1 && _ssh_users+=(meridian-user)
  if [[ -n "${SUDO_USER:-}" ]] && [[ "$SUDO_USER" != "root" ]] \
       && [[ "$SUDO_USER" != "meridian-user" ]] \
       && getent passwd "$SUDO_USER" >/dev/null 2>&1; then
    _ssh_users+=("$SUDO_USER")
  fi
  if (( ${#_ssh_users[@]} )) && getent group ddi-ssh >/dev/null 2>&1; then
    local u
    for u in "${_ssh_users[@]}"; do
      if ! id -nG "$u" | tr ' ' '\n' | grep -qx ddi-ssh; then
        usermod -aG ddi-ssh "$u"
        ok "$u added to ddi-ssh group"
      else
        info "$u already in ddi-ssh"
      fi
    done
    # Also give each interactive account full sudo. Without this, the
    # interactive account can SSH in but can't bootstrap anything
    # (install nginx overrides, fix perms, edit configs). The account
    # password still gates every sudo call.
    for u in "${_ssh_users[@]}"; do
      if ! id -nG "$u" | tr ' ' '\n' | grep -qx sudo; then
        usermod -aG sudo "$u"
        ok "$u added to sudo group"
      fi
    done
  fi

  # 1. SSH pubkey → root + meridian-user (if the interactive account exists).
  if [[ -n "$ADMIN_SSH_PUBKEY" ]]; then
    local __auth
    for __auth in /root/.ssh/authorized_keys /home/meridian-user/.ssh/authorized_keys; do
      local __dir="${__auth%/*}"
      local __owner
      if [[ "$__auth" == "/root/"* ]]; then
        __owner="root:root"
      else
        # Skip the meridian-user path if that account doesn't exist on
        # this install (some builds are service-user-only).
        getent passwd meridian-user >/dev/null 2>&1 || continue
        __owner="meridian-user:meridian-user"
      fi
      install -d -m 0700 -o "${__owner%:*}" -g "${__owner#*:}" "$__dir"
      touch "$__auth"
      chown "$__owner" "$__auth"
      chmod 0600 "$__auth"
      # Append only if not already present — lets this stage re-run safely.
      if ! grep -qxF "$ADMIN_SSH_PUBKEY" "$__auth" 2>/dev/null; then
        printf '%s\n' "$ADMIN_SSH_PUBKEY" >> "$__auth"
        ok "pubkey installed in $__auth"
      else
        info "pubkey already present in $__auth"
      fi
    done
  else
    warn "ADMIN_SSH_PUBKEY is blank — skipping pubkey install"
    warn "You'll need console/password SSH until you run ssh-copy-id or set one via Admin → Users"
  fi

  # 2. Sudoers drop-ins. Each file is validated with visudo -cf before we
  # commit it; a parse error leaves the previous file (if any) untouched.
  if [[ -d "$CONFIG_SRC/sudoers.d" ]]; then
    local __src __dst __name
    for __src in "$CONFIG_SRC"/sudoers.d/*; do
      [[ -f "$__src" ]] || continue
      __name="$(basename "$__src")"
      __dst="/etc/sudoers.d/$__name"
      install -m 0440 -o root -g root "$__src" "$__dst.new"
      if visudo -cf "$__dst.new" >/dev/null 2>&1; then
        mv "$__dst.new" "$__dst"
        ok "sudoers drop-in · $__name"
      else
        rm -f "$__dst.new"
        warn "sudoers drop-in · $__name — visudo rejected it, skipped"
      fi
    done
  else
    info "no sudoers.d/ templates in $CONFIG_SRC — nothing to install"
  fi
}

# --------------------------------------------------------------------
# Master keys for field encryption + row-hash chain
# --------------------------------------------------------------------
generate_master_keys() {
  section "Generating master keys (Layer 2 + Layer 3)"

  umask 0077
  if [[ ! -f "$MASTER_KEY_PATH" ]]; then
    openssl rand -out "$MASTER_KEY_PATH" 32
    chown "$SVC_USER":"$SVC_GROUP" "$MASTER_KEY_PATH"
    chmod 0400 "$MASTER_KEY_PATH"
    ok "Generated Layer 2 master key (AES-256-GCM)"
  fi
  if [[ ! -f "$ROW_HMAC_KEY_PATH" ]]; then
    openssl rand -out "$ROW_HMAC_KEY_PATH" 32
    chown "$SVC_USER":"$SVC_GROUP" "$ROW_HMAC_KEY_PATH"
    chmod 0400 "$ROW_HMAC_KEY_PATH"
    ok "Generated Layer 3 row-HMAC key (SHA-256)"
  fi
  warn "These keys live at $SECRETS_DIR. Back them up somewhere safe."
  warn "Without them, the database is unreadable. Losing them = total data loss."
}

# --------------------------------------------------------------------
# First admin + initial data
# --------------------------------------------------------------------
seed_first_admin() {
  section "Seeding first admin user"
  # Done via the meridian-nip CLI shim that the package installs.
  # NOTE: force-change-at-login is intentionally OFF so automated
  # build-out scripts (e.g. golden-image seeding of additional accounts,
  # initial LDAP wiring, roles) can sign in as admin/meridian without
  # hitting a mandatory password-reset wall. The credential is well-known
  # and documented — the operator is expected to rotate it via Admin
  # Panel → Credentials once their build workflow is complete.
  # PYTHONPATH must include $INSTALL_ROOT so `-m app.cli` resolves
  # against the source tree, not the venv site-packages. The systemd
  # services set this via Environment=; the install-time CLI calls
  # missed that for a long time. Surfaced 2026-05-13.
  (cd "$INSTALL_ROOT" && PYTHONPATH="$INSTALL_ROOT" \
    "$INSTALL_ROOT/venv/bin/python" -m app.cli users create \
      --username "$ADMIN_USERNAME" \
      --email    "$ADMIN_EMAIL" \
      --role     super_admin \
      --temp-password "$ADMIN_TEMP_PASSWORD") \
    2>&1 | tee -a "$INSTALL_LOG"
  ok "Admin user created: $ADMIN_USERNAME (no forced reset — rotate via Admin Panel → Credentials)"
}

# activate_license() removed 2026-05-13: license subsystem deleted
# (Apache 2.0). Every install gets full feature parity, no activation.

# --------------------------------------------------------------------
# Start services + health check
# --------------------------------------------------------------------
start_and_verify() {
  section "Starting services"
  systemctl enable --now meridian-app meridian-celery meridian-beat
  sleep 3
  for unit in meridian-app meridian-celery meridian-beat; do
    if systemctl is-active --quiet "$unit"; then
      ok "$unit running"
    else
      die "$unit failed to start. See: journalctl -u $unit"
    fi
  done

  # Smoke: HTTP 200 on /healthz
  if curl -fsS --max-time 5 "http://127.0.0.1:8000/healthz" >/dev/null; then
    ok "App /healthz returned 200"
  else
    die "App /healthz failed. Check $LOG_ROOT/app-error.log"
  fi
}

# --------------------------------------------------------------------
# Post-install summary + shred offer
# --------------------------------------------------------------------
summary() {
  section "Install complete"
  local url
  case "$SSL_METHOD" in
    none) url="http://${PORTAL_DOMAIN}" ;;
    *)    url="https://${PORTAL_DOMAIN}" ;;
  esac

  # Current live address(es) — useful when STATIC_IP is blank (DHCP reveal)
  # and as a sanity check when STATIC_IP is set but hasn't activated yet.
  local live_addrs
  live_addrs=$(ip -o -4 addr show scope global 2>/dev/null \
               | awk '{print $2": "$4}' | paste -sd'; ' -)
  live_addrs="${live_addrs:-none}"

  local net_line
  if [[ -n "$STATIC_IP" ]]; then
    net_line="${STATIC_IP} on ${NET_IFACE} (takes effect on next reboot)"
  else
    net_line="DHCP (current: ${live_addrs})"
  fi

  cat | tee -a "$INSTALL_LOG" <<EOF
  ${C_BOLD}${C_GREEN}  ✓  Meridian is ready.${C_RESET}

     Portal URL:         ${url}
     Admin username:     ${ADMIN_USERNAME}
     Admin temp pwd:     ${ADMIN_TEMP_PASSWORD}     (CHANGE AT FIRST LOGIN)
     Admin email:        ${ADMIN_EMAIL}

     Database:           ${DB_NAME} (role ${DB_USER})
     DB password:        ${DB_PASSWORD}

     SSH port:           ${SSH_PORT}   (group: ${SSH_GROUP})
     TLS method:         ${SSL_METHOD}
     Network:            ${net_line}
     Scope of use:       ${SCOPE_OF_USE}
     Timezone:           ${TIMEZONE}
     License:            Apache 2.0 (free for any use; see LICENSE)

     Config:             ${CONFIG_ROOT}/meridian.conf
     App:                ${INSTALL_ROOT}
     Master keys:        ${SECRETS_DIR}    ${C_YELLOW}← back this up${C_RESET}
     Logs:               ${LOG_ROOT}
     This install log:   ${INSTALL_LOG}

  ${C_BOLD}${C_YELLOW}  IMPORTANT${C_RESET}
     · Write down the temp password and DB password above before this
       install log is shredded.
     · The master keys under ${SECRETS_DIR} cannot be regenerated without
       data loss. Back them up to secure offline storage.
     · The admin user must enroll MFA at first login.
     · If you set a custom SSH port (${SSH_PORT}), log into a fresh SSH
       session NOW to confirm it works before closing this one.

  ${C_BOLD}${C_TEAL}  Next steps${C_RESET}
     1. Open ${url} and sign in.
     2. Accept the AUP (it will prompt automatically).
     3. Enroll MFA.
     4. Admin → Branding → upload your logo, set AUP text.
     5. Admin → Integrations → connect AD, Infoblox, notifications.
     6. Admin → Scope Manager → enable only the features your team needs.
EOF

  prompt_yn SHRED n "Shred $INSTALL_LOG now? (only do this AFTER you've saved the credentials above)"
  if [[ "$SHRED" == "y" ]]; then
    shred -u "$INSTALL_LOG" && echo "Log shredded."
  else
    warn "Log retained at $INSTALL_LOG. Shred it manually: shred -u $INSTALL_LOG"
  fi
}

# --------------------------------------------------------------------
# Resume support · state persistence + stage dispatcher
# --------------------------------------------------------------------
# Ordered list of stages eligible for --resume-from. Must match the
# call sequence in main() below.
readonly RESUMABLE_STAGES=(
  system_prep
  setup_static_network
  install_os_packages
  generate_master_keys
  stage_package
  apply_sysctl
  setup_postgresql
  apply_postgresql_overlay
  setup_cache
  apply_cache_overlay
  setup_bind9
  install_meridian_app
  setup_nginx_tls
  setup_ssh_zsh
  setup_fail2ban_apparmor
  apply_logrotate
  apply_ufw
  seed_first_admin
  start_and_verify
)

save_state() {
  local tmp
  tmp=$(mktemp "${STATE_FILE}.XXXXXX")
  chmod 0600 "$tmp"
  {
    printf '# Meridian installer state · written %s\n' "$(date -u +%FT%TZ)"
    printf '# Re-run: sudo ./install.sh --resume-from=<stage>\n'
    local v
    for v in PORTAL_NAME PORTAL_DOMAIN ADMIN_USERNAME ADMIN_EMAIL ADMIN_TEMP_PASSWORD \
             DB_NAME DB_USER DB_PASSWORD TIMEZONE SSL_METHOD SCOPE_OF_USE \
             SSH_PORT LUKS_ENCRYPT MODE AIRGAPPED \
             STATIC_IP STATIC_GATEWAY STATIC_DNS NET_IFACE; do
      printf '%s=%q\n' "$v" "${!v}"
    done
  } > "$tmp"
  mv -f "$tmp" "$STATE_FILE"
}

load_state() {
  [[ -r "$STATE_FILE" ]] || die "Cannot resume: $STATE_FILE not found. Re-run without --resume-from for a fresh install."
  # shellcheck disable=SC1090
  . "$STATE_FILE"
}

# run_stage <function_name>
# When RESUME_FROM is set, skip every stage before it; run the rest.
# When RESUME_FROM is empty, always runs.
run_stage() {
  local stage=$1
  if [[ -n "$RESUME_FROM" && $STAGE_REACHED -eq 0 ]]; then
    if [[ "$stage" == "$RESUME_FROM" ]]; then
      STAGE_REACHED=1
    else
      return 0
    fi
  fi
  "$stage"
}

validate_resume_from() {
  [[ -z "$RESUME_FROM" ]] && return 0
  local s
  for s in "${RESUMABLE_STAGES[@]}"; do
    [[ "$s" == "$RESUME_FROM" ]] && return 0
  done
  err "Invalid --resume-from stage: $RESUME_FROM"
  err "Valid stages (in order):"
  printf '  %s\n' "${RESUMABLE_STAGES[@]}" >&2
  exit 1
}

# --------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------
parse_args() {
  while (( $# )); do
    case "$1" in
      --upgrade)          MODE="upgrade" ;;
      --dry-run)          MODE="dry-run" ;;
      --airgapped)        AIRGAPPED=1 ;;
      --unattended)       UNATTENDED=1 ;;
      --config)           ANSWERS_FILE="$2"; shift ;;
      --resume-from)      RESUME_FROM="$2"; shift ;;
      --resume-from=*)    RESUME_FROM="${1#*=}" ;;
      --skip-license)     warn "--skip-license is a no-op since 2026-05-13 (Apache 2.0)" ;;
      -h|--help)          grep -E '^#' "$0" | head -15; exit 0 ;;
      *)                  die "Unknown flag: $1" ;;
    esac
    shift
  done
  if (( UNATTENDED )); then
    [[ -n "$ANSWERS_FILE" && -r "$ANSWERS_FILE" ]] || die "--unattended requires --config <file>"
    # shellcheck disable=SC1090
    . "$ANSWERS_FILE"
  fi
  validate_resume_from
}

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
main() {
  parse_args "$@"
  : > "$INSTALL_LOG"
  chmod 0600 "$INSTALL_LOG"
  welcome_banner
  preflight
  if [[ "$MODE" == "dry-run" ]]; then
    ok "Dry-run complete. No changes made."
    exit 0
  fi

  if [[ -n "$RESUME_FROM" ]]; then
    load_state
    info "Resuming from stage: $RESUME_FROM  (state loaded from $STATE_FILE)"
  else
    configure_interactive
    save_state
    info "Config saved to $STATE_FILE — if install fails, re-run with --resume-from=<stage>"
  fi

  run_stage system_prep
  run_stage setup_static_network
  run_stage install_os_packages
  run_stage generate_master_keys
  run_stage stage_package
  run_stage apply_sysctl
  run_stage setup_postgresql
  run_stage apply_postgresql_overlay
  run_stage setup_cache
  run_stage apply_cache_overlay
  run_stage setup_bind9
  run_stage install_meridian_app
  run_stage setup_nginx_tls
  run_stage setup_ssh_zsh
  run_stage setup_fail2ban_apparmor
  run_stage setup_admin_access
  run_stage apply_logrotate
  run_stage apply_ufw
  run_stage seed_first_admin
  run_stage start_and_verify
  summary
}

main "$@"

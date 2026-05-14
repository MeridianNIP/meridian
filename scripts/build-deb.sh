#!/usr/bin/env bash
# =====================================================================
# Meridian · build a Debian package (.deb) wrapping install.sh
# =====================================================================
# Produces a thin-wrapper .deb that ships the source tree under
# /opt/meridian and runs install.sh --unattended --config
# /etc/meridian/answers.local.env on postinst.
#
# Usage:
#   ./scripts/build-deb.sh                 # version from pyproject.toml
#   ./scripts/build-deb.sh 1.0.1           # explicit version override
#   ./scripts/build-deb.sh --output dist/  # output dir override
#
# Output:
#   dist/meridian-nip_<version>_amd64.deb
#
# Operator install pattern (apt-side):
#   1. Pre-stage /etc/meridian/answers.local.env on the target host
#      (copy from /opt/meridian/answers.example.env or hand-write it).
#   2. sudo apt install ./meridian-nip_<version>_amd64.deb
#      (or via the apt repo: sudo apt install meridian-nip)
#   3. apt's postinst runs install.sh against the answers file.
#
# If /etc/meridian/answers.local.env is NOT present at install time,
# postinst skips the install.sh run and prints a notice so the
# operator can finish it manually. This avoids prompting from
# debconf — keeps the .deb non-interactive.
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_CYAN=$'\e[36m'; C_RED=$'\e[31m'; C_YELLOW=$'\e[33m'
info(){ printf '%s[INFO]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()  { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn(){ printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die() { printf '%s[ERR ]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

VERSION=""
OUTPUT_DIR="$REPO_ROOT/dist"
while (( $# )); do
  case "$1" in
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,20p' "$0" | sed 's/^# //; s/^#//'
      exit 0 ;;
    -*) die "Unknown flag: $1" ;;
    *)
      [[ -z "$VERSION" ]] && { VERSION="$1"; shift; } || die "Unexpected arg: $1"
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION=$(grep -E '^version *=' "$REPO_ROOT/pyproject.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
fi
[[ -n "$VERSION" ]] || die "Could not determine version (no arg and pyproject.toml has no version line)"

ARCH="amd64"
PKG="meridian-nip"
DEB="${PKG}_${VERSION}_${ARCH}.deb"

command -v dpkg-deb >/dev/null || die "dpkg-deb missing — apt install dpkg-dev"

info "Building $DEB (version=$VERSION arch=$ARCH)"
mkdir -p "$OUTPUT_DIR"

STAGE=$(mktemp -d /tmp/meridian-deb.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT

# ---------------------------------------------------------------------
# Stage the source tree under /opt/meridian
# ---------------------------------------------------------------------
info "Staging source into $STAGE/opt/meridian"
install -d -m 0755 "$STAGE/opt/meridian"

# Copy the working tree, excluding things that don't belong in a release.
rsync -a \
  --exclude='.git/' \
  --exclude='.github/' \
  --exclude='.gitignore' \
  --exclude='.claude/' \
  --exclude='.venv/' \
  --exclude='venv/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='.pytest_cache/' \
  --exclude='.ruff_cache/' \
  --exclude='dist/' \
  --exclude='node_modules/' \
  --exclude='wheels/' \
  --exclude='mockups/' \
  --exclude='answers.local.env' \
  --exclude='answers.test.env' \
  --exclude='.pre-commit-config.yaml' \
  "$REPO_ROOT/" "$STAGE/opt/meridian/"

# Pre-staged answers directory (operator drops their answers.local.env here).
install -d -m 0755 "$STAGE/etc/meridian"

# Normalize permissions — the source tree may inherit 0077-umask perms
# from the build host. .deb needs world-readable for system install.
find "$STAGE/opt/meridian" -type d -exec chmod 0755 {} +
find "$STAGE/opt/meridian" -type f -exec chmod 0644 {} +
# Re-mark known-executable files.
find "$STAGE/opt/meridian" -type f \( -name '*.sh' -o -name 'meridian-nip' \) -exec chmod 0755 {} +
chmod 0755 "$STAGE/opt/meridian/install.sh"

# ---------------------------------------------------------------------
# DEBIAN/control
# ---------------------------------------------------------------------
DEPS="bash, coreutils, util-linux, python3 (>= 3.11), python3-venv, postgresql (>= 15), nginx, bind9, fail2ban, ufw, ca-certificates, openssl, curl, jq, rsync, openssh-server, sudo"
# valkey on Debian 13, redis-server on Debian 12 — depend on either via alternatives
DEPS+=", valkey-server | redis-server"

SIZE_KB=$(du -sk "$STAGE/opt" | cut -f1)

install -d -m 0755 "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: MeridianNIP <ops@meridiannip.com>
Installed-Size: $SIZE_KB
Depends: $DEPS
Homepage: https://meridiannip.com
Description: Self-hosted DDI + network-operations portal
 Meridian NIP is a self-hosted DNS / DHCP / IPAM + network-operations
 portal. Apache 2.0 licensed, free for any use. The package ships the
 application source under /opt/meridian and triggers install.sh on
 postinst — operators must pre-stage /etc/meridian/answers.local.env
 before apt-installing (see meridiannip.com/install.html).
 .
 The package is a thin wrapper around install.sh; subsequent
 upgrades (apt upgrade meridian-nip) re-run install.sh --upgrade.
CONTROL

# ---------------------------------------------------------------------
# DEBIAN/postinst
# ---------------------------------------------------------------------
cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

ANSWERS=/etc/meridian/answers.local.env
INSTALL_SH=/opt/meridian/install.sh

case "$1" in
  configure)
    if [ ! -f "$ANSWERS" ]; then
      cat >&2 <<MSG

================================================================
  Meridian NIP installed under /opt/meridian, but the unattended
  installer was NOT run because $ANSWERS is missing.

  To finish:
    sudo cp /opt/meridian/answers.example.env $ANSWERS
    sudo \$EDITOR $ANSWERS
    sudo $INSTALL_SH --unattended --config $ANSWERS

  Or run install.sh interactively:
    sudo $INSTALL_SH

  See https://meridiannip.com/install.html for the full walkthrough.
================================================================

MSG
      exit 0
    fi

    # Detect fresh-install vs upgrade by looking for an existing service.
    if systemctl list-unit-files meridian-app.service >/dev/null 2>&1 && \
       systemctl is-enabled meridian-app.service >/dev/null 2>&1; then
      echo "[meridian-nip] existing install detected — running install.sh --upgrade"
      "$INSTALL_SH" --upgrade --unattended --config "$ANSWERS"
    else
      echo "[meridian-nip] fresh install — running install.sh --unattended"
      "$INSTALL_SH" --unattended --config "$ANSWERS"
    fi
    ;;
  abort-upgrade|abort-remove|abort-deconfigure)
    ;;
esac

exit 0
POSTINST
chmod 0755 "$STAGE/DEBIAN/postinst"

# ---------------------------------------------------------------------
# DEBIAN/prerm  — stop services on remove (keep them on upgrade)
# ---------------------------------------------------------------------
cat > "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e

case "$1" in
  remove|deconfigure)
    for u in meridian-app meridian-celery meridian-beat; do
      systemctl stop "$u.service" 2>/dev/null || true
    done
    ;;
  upgrade|failed-upgrade)
    # Leave services running across upgrades. install.sh's postinst
    # path will restart them after the new code is staged.
    ;;
esac

exit 0
PRERM
chmod 0755 "$STAGE/DEBIAN/prerm"

# ---------------------------------------------------------------------
# DEBIAN/postrm  — clean up service units on purge; keep data + DB
# ---------------------------------------------------------------------
cat > "$STAGE/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e

case "$1" in
  purge)
    # purge removes the package + config files but explicitly NOT:
    #   /var/lib/meridian       — data, keys, backups
    #   /var/log/meridian       — logs
    #   the meridian Postgres DB and role
    #   /etc/meridian/secrets/  — master keys (irreplaceable; manual delete only)
    #
    # If you really want to wipe everything, remove those by hand
    # AFTER you have a separate offline backup of the master keys.
    for u in meridian-app meridian-celery meridian-beat; do
      systemctl disable "$u.service" 2>/dev/null || true
      rm -f "/etc/systemd/system/$u.service"
    done
    systemctl daemon-reload 2>/dev/null || true
    rm -f /usr/local/bin/meridian-nip
    ;;
  remove|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
    ;;
esac

exit 0
POSTRM
chmod 0755 "$STAGE/DEBIAN/postrm"

# ---------------------------------------------------------------------
# Build the .deb
# ---------------------------------------------------------------------
info "Running dpkg-deb --build"
dpkg-deb --root-owner-group --build "$STAGE" "$OUTPUT_DIR/$DEB"
ok "$OUTPUT_DIR/$DEB ($(stat -c%s "$OUTPUT_DIR/$DEB") bytes)"

# ---------------------------------------------------------------------
# Sanity probe
# ---------------------------------------------------------------------
info "dpkg-deb --info:"
dpkg-deb --info "$OUTPUT_DIR/$DEB" | sed 's/^/    /'
info "dpkg-deb --contents (top 20):"
dpkg-deb --contents "$OUTPUT_DIR/$DEB" | head -20 | sed 's/^/    /'

ok "done — built $DEB"

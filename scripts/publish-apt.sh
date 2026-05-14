#!/usr/bin/env bash
# =====================================================================
# Meridian · publish current build to the meridiannip.com apt repo
# =====================================================================
# Builds a fresh .deb (via build-deb.sh), drops it into the apt-repo
# layout under the site repo (/home/pj/projects/meridiannip.com/apt/),
# regenerates the Packages + Release indexes, and re-signs the
# Release file with the persistent GPG key at
# ~/.meridian-apt-signing/.
#
# Apt-side install for users:
#
#     curl -fsSL https://meridiannip.com/meridiannip.gpg \
#       | sudo gpg --dearmor -o /usr/share/keyrings/meridiannip-archive-keyring.gpg
#     echo "deb [signed-by=/usr/share/keyrings/meridiannip-archive-keyring.gpg] https://meridiannip.com/apt stable main" \
#       | sudo tee /etc/apt/sources.list.d/meridian.list
#     sudo apt update
#     sudo apt install meridian-nip
#
# Usage:
#   ./scripts/publish-apt.sh                  # build current pyproject version
#   ./scripts/publish-apt.sh 1.0.1            # explicit version
#
# After this script: commit + push the site repo to deploy the new
# apt index. The CF Pages GitHub integration picks it up automatically.
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SITE_ROOT="${MERIDIAN_SITE_ROOT:-$HOME/projects/meridiannip.com}"
APT_ROOT="$SITE_ROOT/apt"
GPG_HOME="${MERIDIAN_APT_GPG_HOME:-$HOME/.meridian-apt-signing}"
GPG_UID="ops@meridiannip.com"

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_CYAN=$'\e[36m'; C_RED=$'\e[31m'; C_YELLOW=$'\e[33m'
info(){ printf '%s[INFO]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()  { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn(){ printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die() { printf '%s[ERR ]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

VERSION="${1:-}"
[[ -d "$SITE_ROOT" ]] || die "Site repo not found at $SITE_ROOT (override with MERIDIAN_SITE_ROOT=)"
[[ -d "$GPG_HOME" ]] || die "GPG keyring missing at $GPG_HOME — see project_meridian_apt_repo.md memory note for re-keying"
export GNUPGHOME="$GPG_HOME"
gpg --list-secret-keys "$GPG_UID" >/dev/null 2>&1 || die "GPG key for $GPG_UID not in $GPG_HOME"

# ---------------------------------------------------------------------
# 1. Build the .deb
# ---------------------------------------------------------------------
info "Step 1/4 — building .deb"
if [[ -n "$VERSION" ]]; then
  "$SCRIPT_DIR/build-deb.sh" "$VERSION" >/dev/null
else
  "$SCRIPT_DIR/build-deb.sh" >/dev/null
fi
DEB=$(ls -t "$REPO_ROOT/dist/"meridian-nip_*_amd64.deb | head -1)
[[ -f "$DEB" ]] || die "build-deb.sh did not produce a .deb"
ok "built $(basename "$DEB")"

# ---------------------------------------------------------------------
# 2. Stage .deb into apt repo layout
# ---------------------------------------------------------------------
info "Step 2/4 — staging .deb into apt repo"
install -d -m 0755 "$APT_ROOT/pool/main/m/meridian-nip"
install -d -m 0755 "$APT_ROOT/dists/stable/main/binary-amd64"
install -m 0644 "$DEB" "$APT_ROOT/pool/main/m/meridian-nip/$(basename "$DEB")"
ok "staged $(basename "$DEB") under apt/pool/"

# ---------------------------------------------------------------------
# 3. Regenerate indexes
# ---------------------------------------------------------------------
info "Step 3/4 — regenerating Packages + Release"
cd "$APT_ROOT"
apt-ftparchive packages pool/ > dists/stable/main/binary-amd64/Packages
gzip -kf9 dists/stable/main/binary-amd64/Packages

cat > /tmp/aptftp.conf <<EOF
APT::FTPArchive::Release::Origin   "MeridianNIP";
APT::FTPArchive::Release::Label    "MeridianNIP";
APT::FTPArchive::Release::Suite    "stable";
APT::FTPArchive::Release::Codename "stable";
APT::FTPArchive::Release::Architectures "amd64";
APT::FTPArchive::Release::Components "main";
APT::FTPArchive::Release::Description "Meridian NIP Apache 2.0 apt repository";
EOF
apt-ftparchive -c /tmp/aptftp.conf release dists/stable/ > dists/stable/Release
ok "rebuilt Packages + Release"

# ---------------------------------------------------------------------
# 4. Sign
# ---------------------------------------------------------------------
info "Step 4/4 — signing Release"
rm -f dists/stable/InRelease dists/stable/Release.gpg
gpg --batch --yes --default-key "$GPG_UID" --clearsign -o dists/stable/InRelease dists/stable/Release
gpg --batch --yes --default-key "$GPG_UID" --detach-sign --armor -o dists/stable/Release.gpg dists/stable/Release
ok "signed → InRelease + Release.gpg"

# Refresh public key at site/static/meridiannip.gpg (idempotent)
gpg --armor --export "$GPG_UID" > "$SITE_ROOT/static/meridiannip.gpg"
ok "refreshed $SITE_ROOT/static/meridiannip.gpg"

cat <<DONE

  ✓  apt repo updated at $APT_ROOT
     deb files: $(ls -1 pool/main/m/meridian-nip/ | wc -l)
     latest:    $(basename "$DEB")

  Next: commit + push the site repo. CF Pages picks it up within ~30s.
        cd $SITE_ROOT && git add -A && git commit -m "apt: $(basename "$DEB")" && git push origin main

DONE

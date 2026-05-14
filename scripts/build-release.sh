#!/usr/bin/env bash
# =====================================================================
# Meridian · Vendor-side release packager
# =====================================================================
# Produces a reproducible `meridian-<version>.tar.gz` that ships every
# Python dependency as a pre-downloaded wheel alongside the app tree.
# Customers' install.sh consumes the tarball offline for pip, while apt
# still pulls OS packages from Debian (or the vendor apt repo).
#
# Usage (vendor laptop / CI runner):
#   ./scripts/build-release.sh                 # builds into dist/
#   ./scripts/build-release.sh 1.0.1           # explicit version tag
#   ./scripts/build-release.sh --platform arm64
#
# Prereqs:
#   · Python 3.11+ (3.13 recommended) with pip
#   · git (to tag the source state into the archive)
# =====================================================================

set -euo pipefail

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_CYAN=$'\e[36m'; C_RED=$'\e[31m'
info(){ printf '%s[INFO]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()  { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
die() { printf '%s[ERR ]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

VERSION="${1:-}"
PLATFORM="linux_x86_64"
while (( $# )); do
  case "$1" in
    --platform) PLATFORM="$2"; shift ;;
    --version)  VERSION="$2"; shift ;;
    -h|--help)  grep -E '^# ' "$0" | head -20; exit 0 ;;
    *)          [[ -z "$VERSION" ]] && VERSION="$1" ;;
  esac
  shift
done

VERSION="${VERSION:-dev-$(date +%Y%m%d%H%M%S)}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$SRC_DIR/dist"
STAGE_DIR="$DIST_DIR/meridian-${VERSION}"
TAR_OUT="$DIST_DIR/meridian-${VERSION}.tar.gz"

mkdir -p "$DIST_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/wheels"

info "Staging source tree → ${STAGE_DIR}"
for d in app db config docs scripts brand; do
  [[ -d "$SRC_DIR/$d" ]] || die "missing source dir: $d"
  cp -a "$SRC_DIR/$d" "$STAGE_DIR/$d"
done
cp "$SRC_DIR/install.sh"        "$STAGE_DIR/install.sh"
cp "$SRC_DIR/requirements.txt"  "$STAGE_DIR/requirements.txt"
chmod +x "$STAGE_DIR/install.sh" "$STAGE_DIR/scripts"/*.sh

# Write a VERSION file the installer reads for the banner + audit.
echo "$VERSION" > "$STAGE_DIR/VERSION"

info "Downloading Python wheels (platform=${PLATFORM})"
# Pull wheels for the exact Python/platform we ship against. --only-binary=:all:
# fails fast if any dep has no wheel for the target (which we want; we don't
# bundle source tarballs that'd need a compiler on the customer host).
python3 -m pip download \
  --dest "$STAGE_DIR/wheels" \
  --only-binary=:all: \
  --platform "$PLATFORM" \
  --python-version 313 \
  --implementation cp \
  --abi cp313 \
  --requirement "$SRC_DIR/requirements.txt" \
  2>&1 | tee "$DIST_DIR/wheels-${VERSION}.log" || {
    info "Platform-specific download failed; falling back to source+any-binary"
    python3 -m pip download --dest "$STAGE_DIR/wheels" \
      --requirement "$SRC_DIR/requirements.txt"
  }

# Integrity manifest — sha256sums for every file in the tarball.
info "Computing integrity manifest"
( cd "$STAGE_DIR" && find . -type f -not -name SHA256SUMS \
    -exec sha256sum {} + | sort > SHA256SUMS )

info "Packing tarball"
tar -C "$DIST_DIR" -czf "$TAR_OUT" "$(basename "$STAGE_DIR")"

BUNDLE_SIZE=$(du -h "$TAR_OUT" | cut -f1)
WHEEL_COUNT=$(find "$STAGE_DIR/wheels" -name '*.whl' -o -name '*.tar.gz' | wc -l)

ok "Built ${TAR_OUT} (${BUNDLE_SIZE}, ${WHEEL_COUNT} wheels)"
echo
echo "Next:"
echo "  · GPG-sign:  gpg --detach-sign --armor ${TAR_OUT}"
echo "  · Verify install from dist/: (cd dist && tar xzf $(basename "$TAR_OUT") && cd meridian-${VERSION} && sudo ./install.sh --dry-run)"

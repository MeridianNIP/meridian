#!/usr/bin/env bash
# =====================================================================
# Meridian · repack Debian 13 netinst ISO with preseed for unattended boot
# =====================================================================
# Produces a new hybrid BIOS+UEFI bootable ISO that:
#
#   - Includes /preseed.cfg (this repo's scripts/preseed/meridian.preseed.cfg)
#   - Has isolinux/txt.cfg + boot/grub/grub.cfg patched to autoboot the
#     install entry with `auto=true priority=critical preseed/file=/cdrom/preseed.cfg`
#   - Drops the menu timeout to ~1 second so Hyper-V Gen 2 fires the
#     unattended path without keyboard interaction
#
# Result: drop the ISO in a Hyper-V VM, power on, walk away, come back
# in ~10 minutes to a freshly-installed Debian with SSH key already
# authorized for the `pj` user. Then `install.sh --unattended` finishes
# the Meridian-specific provisioning.
#
# Usage:
#   ./scripts/repack-preseed-iso.sh [source.iso] [output.iso]
#
# Defaults:
#   source = /mnt/c/VMs/ISOs/debian-13.4.0-amd64-netinst.iso
#   output = /mnt/c/VMs/ISOs/debian-13.4.0-amd64-meridian-unattended.iso
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRESEED_SRC="${SCRIPT_DIR}/preseed/meridian.preseed.cfg"
SOURCE_ISO="${1:-/mnt/c/VMs/ISOs/debian-13.4.0-amd64-netinst.iso}"
OUTPUT_ISO="${2:-/mnt/c/VMs/ISOs/debian-13.4.0-amd64-meridian-unattended.iso}"

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_RED=$'\e[31m'; C_CYAN=$'\e[36m'; C_YELLOW=$'\e[33m'
info() { printf '%s[INFO]%s %s\n' "$C_CYAN"   "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[FAIL]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }

[[ -r "$SOURCE_ISO"  ]] || die "source ISO not readable: $SOURCE_ISO"
[[ -r "$PRESEED_SRC" ]] || die "preseed missing: $PRESEED_SRC"
command -v xorriso >/dev/null || die "xorriso not on PATH (sudo apt install xorriso)"

WORK=$(mktemp -d /tmp/meridian-iso-repack.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

info "Source : $SOURCE_ISO ($(stat -c%s "$SOURCE_ISO") bytes)"
info "Preseed: $PRESEED_SRC"
info "Output : $OUTPUT_ISO"
info "Stage  : $WORK"

# ---------------------------------------------------------------------
# Step 1 — extract the source ISO. xorriso's "extract" preserves Rock
# Ridge attributes so the repacked filesystem looks identical from the
# installer's POV (case, ownership, symlinks intact).
# ---------------------------------------------------------------------
info "Step 1/4 — extract"
xorriso -osirrox on -indev "$SOURCE_ISO" \
    -extract / "$WORK/iso" 2>"$WORK/extract.log" \
    || { sed -e 's/^/    /' "$WORK/extract.log" >&2; die "extract failed"; }
# Restore writability — xorriso extracts read-only by default.
chmod -R u+w "$WORK/iso"
ok "extracted to $WORK/iso ($(du -sh "$WORK/iso" | cut -f1))"

# ---------------------------------------------------------------------
# Step 2 — drop preseed.cfg in at the ISO root. The kernel param
# `preseed/file=/cdrom/preseed.cfg` resolves to here because the
# installer mounts the ISO at /cdrom.
# ---------------------------------------------------------------------
info "Step 2/4 — inject preseed"
cp "$PRESEED_SRC" "$WORK/iso/preseed.cfg"
ok "added /preseed.cfg ($(stat -c%s "$WORK/iso/preseed.cfg") bytes)"

# ---------------------------------------------------------------------
# Step 3 — patch boot configs to autoboot with preseed args
# ---------------------------------------------------------------------
info "Step 3/4 — patch boot configs"

# BIOS path: isolinux. txt.cfg defines the menu entries; isolinux.cfg
# defines the timeout. We add preseed args to the "install" entry's
# append line, then crank the timeout down so the menu doesn't wait
# for input.
ISOLINUX_TXT="$WORK/iso/isolinux/txt.cfg"
ISOLINUX_CFG="$WORK/iso/isolinux/isolinux.cfg"
[[ -f "$ISOLINUX_TXT" ]] || die "missing $ISOLINUX_TXT"
[[ -f "$ISOLINUX_CFG" ]] || die "missing $ISOLINUX_CFG"

# Match the 'append vga=788 ...' line and add preseed args BEFORE the
# `---` separator (Debian convention: `---` separates installer args
# from kernel-cmdline args passed to the booted system).
sed -i 's|append vga=788 initrd=/install.amd/initrd.gz ---|append vga=788 initrd=/install.amd/initrd.gz auto=true priority=critical preseed/file=/cdrom/preseed.cfg ---|' "$ISOLINUX_TXT"
grep -q "preseed/file=/cdrom/preseed.cfg" "$ISOLINUX_TXT" \
    || die "isolinux txt.cfg patch did not apply"
ok "patched $ISOLINUX_TXT"

# Set syslinux to autoboot in 0.1s (10 = 1.0s — too patient; 1 = 0.1s)
sed -i 's/^timeout 0$/timeout 1/' "$ISOLINUX_CFG"
grep -q "^timeout 1$" "$ISOLINUX_CFG" \
    || warn "isolinux.cfg timeout not changed (already non-0?)"
# Set the default entry so syslinux knows what to fire after the timeout.
if ! grep -q "^default install$" "$ISOLINUX_CFG"; then
    printf '\ndefault install\n' >> "$ISOLINUX_CFG"
fi
ok "patched $ISOLINUX_CFG"

# UEFI path: grub.cfg. Debian 13 wraps install entries in
# `menuentry --hotkey=... 'Install' { linux ... }` blocks. We:
#  - prepend a 1s default timeout
#  - set default=0 (first entry, typically 'Graphical install')
#  - rewrite every `linux` line in install menuentries to add our args
GRUB_CFG="$WORK/iso/boot/grub/grub.cfg"
[[ -f "$GRUB_CFG" ]] || die "missing $GRUB_CFG"

# Inject preseed args into every `linux ... /install.amd/vmlinuz ...`
# line that doesn't already carry them. The Debian grub.cfg uses
# `--- quiet` as the separator; insert before it.
python3 - "$GRUB_CFG" <<'PY'
import re, sys
path = sys.argv[1]
with open(path) as f:
    body = f.read()
def inject(m):
    line = m.group(0)
    if "preseed/file=" in line:
        return line
    return line.replace(" --- quiet",
                        " auto=true priority=critical preseed/file=/cdrom/preseed.cfg --- quiet")
new = re.sub(r"^[ \t]*linux[ \t]+/install\.amd/vmlinuz[^\n]*",
             inject, body, flags=re.MULTILINE)
# Set a tight default + timeout at the top of the file. Multiple
# `set timeout=` lines are fine; the last one wins.
prefix = "set default=0\nset timeout=1\n"
with open(path, "w") as f:
    f.write(prefix + new)
PY

grep -q "preseed/file=/cdrom/preseed.cfg" "$GRUB_CFG" \
    || die "grub.cfg patch did not apply"
grep -q "set timeout=1" "$GRUB_CFG" \
    || die "grub.cfg timeout patch did not apply"
ok "patched $GRUB_CFG"

# ---------------------------------------------------------------------
# Step 4 — rebuild ISO. Use xorriso's "mkisofs emulation" mode so we
# can pass the same flags Debian's build system uses to produce a
# hybrid (BIOS via isolinux + UEFI via grub) bootable ISO.
#
# Critical flags:
#   -isohybrid-mbr   — embed the isohdpfx MBR so BIOS+USB-stick boots
#   -eltorito-alt-boot ... -e boot/grub/efi.img  — preserve UEFI boot
#   -isohybrid-gpt-basdat — GPT entry pointing at the EFI image so
#                            UEFI firmware (incl. Hyper-V Gen 2) finds it
# ---------------------------------------------------------------------
info "Step 4/4 — rebuild ISO"

ISOHDPFX=/usr/lib/ISOLINUX/isohdpfx.bin
if [[ ! -r "$ISOHDPFX" ]]; then
    warn "isolinux package not present; UEFI-only repack (BIOS may not work from USB)"
    HYBRID_MBR_ARGS=()
else
    HYBRID_MBR_ARGS=(-isohybrid-mbr "$ISOHDPFX")
fi

xorriso -as mkisofs \
    -r -V "Meridian-Debian-13" \
    -J -joliet-long \
    -cache-inodes \
    -b isolinux/isolinux.bin \
    -c isolinux/boot.cat \
    -boot-load-size 4 -boot-info-table -no-emul-boot \
    "${HYBRID_MBR_ARGS[@]}" \
    -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
    -o "$OUTPUT_ISO" \
    "$WORK/iso" 2>"$WORK/build.log" \
    || { tail -40 "$WORK/build.log" >&2; die "ISO build failed"; }

OUT_SIZE=$(stat -c%s "$OUTPUT_ISO")
SRC_SIZE=$(stat -c%s "$SOURCE_ISO")
ok "wrote $OUTPUT_ISO ($OUT_SIZE bytes; source was $SRC_SIZE)"
ok "DONE — boot Hyper-V Gen 2 VM from this ISO for a hands-off install."

# Distribution roadmap

Current state of the distribution channels Meridian can ship over.
Each entry says whether it's live today or planned, and what the
shape of the artifact is.

## Tier 0 — Source clone + install.sh (shipped)

What ships today: the GitHub repo. Tagged releases at
`https://github.com/MeridianNIP/meridian/releases`. Users either
`git clone --branch vX.Y.Z` or download the source-code archive
from the release page, then run `sudo ./install.sh` on a Debian
13 (or 12) host.

Supports unattended mode (`--unattended --config answers.env`) for
CI / fleet rollouts. Online installs pull Python deps from PyPI
against the hash-pinned `requirements.txt`. Offline installs use the
`wheels/` directory (built by `scripts/build-release.sh` on a
connected host) via `pip install --no-index --find-links wheels/`.

Audience: admins comfortable with Debian, staged rollouts, CI pipelines.

## Tier 1 — Preseed-injected ISO (shipped at v1.0.0)

What ships today: the same release page attaches
`debian-13.4.0-amd64-meridian-unattended.iso` (~940 MB, UEFI-bootable
hybrid) plus a `SHA256SUMS` file. Boots hands-off in Hyper-V Gen 2,
VMware Workstation / Fusion / ESXi, VirtualBox (EFI enabled). After
~10 minutes of unattended Debian install, the operator rsyncs the
source tree and runs `install.sh`.

Source: `scripts/repack-preseed-iso.sh` (in this repo) wraps the
upstream Debian netinst with `scripts/preseed/meridian.preseed.cfg`
and the boot-config patches. Anyone can rebuild it locally and bake
their own SSH key in via `MERIDIAN_AUTHORIZED_KEY_FILE=...`.

Audience: evaluators who want to skip the Debian-install step,
admins onboarding fresh hardware or VMs.

## Tier 2 — Prebuilt VM appliance (planned)

One signed VHDX (Hyper-V), one OVA (VMware / VirtualBox), one qcow2
(Proxmox / libvirt) — each containing a Meridian install ready for
first-boot cloud-init to set hostname, static IP, admin email. Portal
reachable in ~5 minutes from import.

Seed source: export the production `meridian-vm` Hyper-V VM once it
is healthy, scrub instance-specific secrets, re-seal with
`cloud-init clean`, and publish the VHDX. Remaining formats derive
from the same VHDX via `qemu-img convert`.

Audience: evaluators, SMB deployments, anyone who wants zero-Debian
exposure.

## Tier 3 — Apt repo (planned)

Custom apt repo at `apt.meridiannip.com` serving a `meridian-nip`
debian package. `sudo apt install meridian-nip` on any Debian 12/13
host pulls the latest release; `sudo apt upgrade` ships subsequent
versions. Signed `Release` files; package files hosted on Cloudflare
R2 (cheap, no egress fees).

Audience: admins who already manage a fleet via apt; pairs with
unattended-upgrades for hands-off security patches.

## Tier 4 — Cloud marketplace images (later)

Same VHDX/qcow2 from Tier 2, uploaded to AWS / Azure / GCP /
DigitalOcean marketplaces. Mostly a paperwork exercise once Tier 2
exists; billing integration is the hard part, and since Meridian is
free under Apache 2.0 there's nothing to bill — the marketplaces
become a *distribution* channel, not a revenue channel.

Audience: cloud-first deployments where the operator never touches a
Debian shell.

## What's NOT planned

- **Docker / OCI image** — Meridian binds to host networking, runs
  several long-lived daemons (PostgreSQL, BIND, valkey, nginx,
  fail2ban), and uses AppArmor profiles tightly. Pretending it's a
  twelve-factor app inside a container doesn't help operators. A
  proper appliance VM is the right shape.
- **Windows-native installer** — Meridian's stack is Linux only.
  WSL2 works in a niche way but isn't supported as a production
  surface.

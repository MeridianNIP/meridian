# Distribution roadmap

Planning note (not yet implemented). Describes the tiered distribution strategy
for Meridian and the caveats specific to each format. Update as formats ship.

## Tier 0 — Source tarball + install.sh (shipped)

What ships today: a `tar.zst` of the project tree, extracted and invoked with
`sudo ./install.sh` on a Debian 12 or 13 host the admin provides. Supports
unattended mode via `--unattended --config answers.env`.

Audience: admins comfortable with Debian, staged rollouts, CI pipelines.

## Tier 1 — Prebuilt VM appliance (planned)

One signed VHDX (Hyper-V), one OVA (VMware / VirtualBox), one qcow2 (Proxmox /
libvirt). First-boot cloud-init pulls hostname, static IP, admin email, license
key from the hypervisor's cloud-init datasource or a cidata ISO. Portal reachable
in ~5 minutes from import.

Seed source: export the `meridian-vm` Hyper-V VM once it is healthy at
`meridiannip.meridian.local`, scrub instance-specific secrets, re-seal with
`cloud-init clean`, and publish the VHDX. Remaining formats derive from the
same VHDX via `qemu-img convert`.

Audience: evaluators, SMB deployments, anyone who wants zero-Debian-exposure.

## Tier 2 — Bootable Debian ISO (later)

Custom ISO built with `xorriso` that combines Debian netinst + a preseed file
+ the Meridian tarball staged for post-install. Admin boots from USB, answers
one wizard, walks away.

Audience: bare-metal installs, airgapped datacentre rollouts.

## Tier 3 — Cloud marketplace images (later)

Same VHDX, uploaded to AWS / Azure / GCP / DigitalOcean marketplaces. Mostly
a paperwork exercise once Tier 1 exists; billing integration is the hard part.

## WSL distro — niche, documented caveats

WSL2 is a real option for **single-instance** deployers who want to evaluate
Meridian on a Windows host without standing up a hypervisor. Ships as a
`.tar.zst` rootfs that the user imports with `wsl --import`.

Do not offer to multi-WSL users as a primary deployment path — the caveats
below apply to every WSL install and are architectural, not fixable.

**Caveats**

- **One IP for the whole Windows host.** All WSL2 distros share a single
  utility VM, a single kernel, and a single eth0 with a single MAC, so they
  also share one LAN DHCP lease. Running Meridian alongside other WSL distros
  on the same machine means sharing port 22 / 80 / 443 on the host's IP,
  which usually breaks at least one service. Single-distro hosts are fine.
- **Static IP support is inert.** The static-IP code in `install.sh` writes a
  `systemd-networkd` profile that WSL ignores — networking is managed by the
  Windows host. Leave `STATIC_IP` blank. Pin the host's address via router
  DHCP reservation instead.
- **LUKS is not available.** WSL2 has no real block devices; the layered
  disk encryption story (`install.sh` LUKS volume) cannot run. Rely on
  Windows BitLocker at the host level if disk encryption matters.
- **AppArmor is kernel-dependent.** The stock WSL kernel may not enforce
  AppArmor profiles. Install attempts to load them and warns on failure;
  Meridian still runs, it just loses one layer of confinement.
- **systemd must be enabled.** Add `[boot]\nsystemd=true` to `/etc/wsl.conf`
  before running `install.sh` so service units actually start.
- **Services die on WSL shutdown.** If the Windows host reboots or the user
  runs `wsl --shutdown`, the portal goes with it until a WSL shell is opened
  again. Set `[boot]\ncommand` in `wsl.conf` to re-enable the units, or start
  a small keep-alive process at login.
- **Port 80 ACME challenge will not work** behind NAT without Windows-side
  port forwarding — use `cloudflare`, `self-signed`, or DNS-01 ACME instead.

Audience: Windows-native evaluators, demo / POC installs, devs who want a
laptop-local instance. Not recommended for production.

## What we will never ship

- **Docker Compose** — Meridian owns nginx, BIND, PostgreSQL, fail2ban, and
  AppArmor at the system level; containerizing fights the design. Admins who
  want containerized DNS/IPAM should look elsewhere.
- **Windows-native binary** — the product is a Debian appliance. A native
  Windows build would triple the maintenance surface for no real gain; WSL
  covers the Windows-host story.

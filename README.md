<p align="center">
  <img src="brand/meridian-wordmark-teal.svg" alt="Meridian NIP" width="420">
</p>

<p align="center">
  <strong>Self-hosted DDI + network-ops portal · Apache 2.0</strong><br>
  Free for any use — personal, commercial, or derivative.<br>
  <a href="LICENSE">LICENSE</a> · <a href="NOTICE">NOTICE</a> ·
  <a href="https://meridiannip.com">meridiannip.com</a>
</p>

---

Copyright © 2026 MeridianNIP. The **"MeridianNIP"** name and logo are
trademarks; per LICENSE Section 6, forks and derivative works must use a
different name and logo.

---

## What it is

Meridian is a portal that consolidates the everyday DNS / DHCP / IPAM
("DDI") and network-operations work an admin does into a single
web UI. It is a **reader and a tooling surface** — it queries external
IPAM / DHCP / Directory sources (Infoblox, NetBox, BlueCat, phpIPAM, ISC
Kea, LDAP, Entra), runs diagnostic tools (DNS propagation, DNSBL, TLS
scan, traceroute, port scan, etc.), and gives you a per-user pinned
dashboard. It does **not** author DNS / DHCP / IPAM data on those
external sources.

### Headline features

- **DNS tools**: dig with multi-resolver propagation, DNSSEC chain,
  zone health, reverse-DNS, WHOIS (single + bulk), Certificate
  Transparency / crt.sh, AXFR check, typosquat generator, DNS flush,
  mail-auth (SPF/DKIM/DMARC) analyzer
- **Network tools**: ping, traceroute / MTR, port scan, packet capture
  (tcpdump file-cap), SNMP walk, ASN lookup, BGP looking glass,
  IP geolocation, IP reputation (8 DNSBLs), HTTP security-header
  audit, **subnet/supernet calculator**
- **Threat intel**: VirusTotal, Censys, Shodan, AbuseIPDB, GreyNoise,
  URLScan, Pulsedive — all rate-limited per the
  [safety caps](app/safety/limits.py) so a misconfigured loop can't
  weaponise your install
- **Monitors**: HTTP, HTTPS, TCP, ICMP ping, cert expiry, DNS records —
  all clamped to a 30-second floor (no DDoSing your own targets)
- **Per-user dashboards** with runbooks, wizards, pinned tools, files,
  links, messages, reports
- **Admin surface**: users + RBAC, scope manager, integrations,
  vulnerabilities, system health (per-component /healthz), queue
  introspection (Celery workers + redbeat schedule), webhook + email +
  SMS notification channels, fail2ban admin card with persistent
  ignoreip, lockout-appeal review, backup + restore, audit log with
  HMAC row-chain integrity, GDPR data export + erasure for users,
  customizable branding
- **Security**: argon2id passwords, TOTP MFA with backup codes,
  single-session enforcement, audit row-hash chain, app-layer CSRF
  (double-submit cookie), PII redaction at audit-insert time, fail2ban
  with configurable ADMIN_CIDR allowlist, AppArmor profiles, AES-256-GCM
  vault with HKDF-lite domain-separated subkeys
- **Operability**: `/metrics` Prometheus endpoint, per-component
  `/healthz`, scheduled jobs visible in the queues UI, automatic
  backups, monitor-result samples retained per policy

---

## Install

Three supported install paths. Pick whichever matches what you have.

### Quick start

Releases ship a prebuilt **preseed-injected Debian 13 ISO** as a GitHub
Release asset. Most users want to grab it directly:

- **Latest release**: https://github.com/MeridianNIP/meridian/releases/latest
- **Direct ISO download**: https://github.com/MeridianNIP/meridian/releases/latest/download/debian-13.4.0-amd64-meridian-unattended.iso
- **Verify**: download `SHA256SUMS` from the same release and run `sha256sum -c SHA256SUMS`

Rebuilding the ISO yourself with `scripts/repack-preseed-iso.sh` is also
supported — see the callouts in each path below. Useful if you want to bake
your own SSH public key into the preseed (`MERIDIAN_AUTHORIZED_KEY_FILE=...`).

### Path 1 — Hyper-V (Windows host, hands-off)

Best for Windows users running Hyper-V Manager. The bootstrap script
builds a Gen 2 VM, attaches the preseed-injected ISO, and walks away.
~10 minutes from `Start-VM` to SSH-able Debian.

**Requirements:** Windows 10/11 Pro/Enterprise with Hyper-V feature
enabled, admin PowerShell, a Hyper-V vSwitch on your LAN (default
`WSL-Bridge`).

```powershell
# 1. Clone or copy the source (you'll need install.sh + answers.example.env)
git clone https://github.com/MeridianNIP/meridian.git
cd meridian

# 2. Get the preseed-injected ISO. Easiest: download the latest release.
Invoke-WebRequest `
  -Uri "https://github.com/MeridianNIP/meridian/releases/latest/download/debian-13.4.0-amd64-meridian-unattended.iso" `
  -OutFile "C:\VMs\ISOs\debian-13.4.0-amd64-meridian-unattended.iso"
#    Alternative: rebuild from source with WSL + xorriso:
#      sudo apt install xorriso
#      MERIDIAN_AUTHORIZED_KEY_FILE=~/.ssh/id_ed25519.pub ./scripts/repack-preseed-iso.sh

# 3. Boot the VM (Windows admin PowerShell)
./scripts/hyperv-bootstrap.ps1 `
    -VMName meridian `
    -Unattended `
    -IsoPath "C:\VMs\ISOs\debian-13.4.0-amd64-meridian-unattended.iso"

# Wait ~10 minutes for Debian to install + reboot.

# 4. From a Linux/WSL shell, prepare your local answers file then push.
#    The repo ships answers.example.env as a template; copy it once
#    and edit to match your environment (PORTAL_DOMAIN, STATIC_IP,
#    ADMIN_CIDR, etc.):
cp answers.example.env answers.local.env
$EDITOR answers.local.env

# Push source + run install.sh:
rsync -az ./ admin@<vm-ip>:~/meridian/
ssh admin@<vm-ip> 'sudo rm -rf /opt/meridian && \
    sudo mv ~/meridian /opt/meridian && \
    sudo chown -R root:root /opt/meridian && \
    sudo chmod 0755 /opt/meridian && \
    sudo /opt/meridian/install.sh --unattended --config /opt/meridian/answers.local.env'
```

Defaults baked into the preseed ISO:

- OS account: `admin` / `meridiannip` (change at first SSH)
- Portal admin: `admin` / `password` (forced change + MFA enroll on
  first browser login)
- Hostname: `meridiannip` (override via `answers.local.env` if you run multiple instances)
- Static IP: configured by `install.sh` based on `STATIC_IP` in answers

### Path 2 — VMware Workstation / Fusion / ESXi (or VirtualBox)

The same preseed-injected ISO also boots in VMware Gen 2-equivalent
(UEFI) VMs and VirtualBox with EFI enabled. One artifact covers all
three hypervisors.

```
1. Download the ISO from the latest release (see Quick start above)
   — OR rebuild it on a Linux/WSL host with scripts/repack-preseed-iso.sh
2. Copy the .iso to the VMware host
3. New VM:
     - Guest OS:     Debian GNU/Linux 13 (64-bit)
     - Firmware:     UEFI (Gen 2)  — Secure Boot OFF
     - Disk:         40 GB dynamic
     - Memory:       4 GB fixed
     - vCPUs:        2
     - Network:      Bridged
     - CD/DVD:       attach the .iso, set boot from CD first
4. Power on. Walk away for ~10 minutes.
5. SSH in as admin / meridiannip
6. rsync source + run install.sh (as in Path 1, step 4)
```

VirtualBox: same flow. Make sure to enable EFI in
Settings → System → Motherboard. Bridged networking is required so the
VM gets a LAN IP.

### Path 3 — Bare Debian 13 (or 12)

For physical hardware, an existing Debian/Ubuntu VM, or any case where
you don't want to use our preseed.

**Requirements:** Debian 13 (primary target) or Debian 12 (fallback).
Minimum 4 GB RAM, 20 GB disk free, internet access for apt.

```
# Fresh Debian 13 install with sshd + standard utilities tasks.
# Create a sudo-capable user (call them whatever; install.sh detects
# the running operator via $SUDO_USER and wires them into ddi-ssh).

# 1. Clone the source onto the box
git clone https://github.com/MeridianNIP/meridian.git /tmp/meridian-src
sudo mkdir -p /opt/meridian
sudo cp -a /tmp/meridian-src/. /opt/meridian/
sudo chown -R root:root /opt/meridian

# 2. Edit the answers file (or use the example)
sudo cp /opt/meridian/answers.local.env /opt/meridian/answers.env
sudo nano /opt/meridian/answers.env
#   - set PORTAL_DOMAIN, STATIC_IP if you want a fixed IP, ADMIN_CIDR
#     to your admin workstation's subnet, etc.

# 3. Run the installer
cd /opt/meridian
sudo ./install.sh --unattended --config /opt/meridian/answers.env

# Or run interactively (will prompt for every meaningful choice with
# an explanation):
sudo ./install.sh

# 4. Browse to https://<portal-domain>/ui/login
#    Default portal admin: admin / password  (change + MFA on first login)
```

### Common post-install

- Change the portal admin password immediately, enroll MFA, generate
  backup codes
- `Admin → Branding` to set logo, colors, organization name, support
  contacts
- `Admin → Integrations` to wire up AD/LDAP, Entra, Infoblox, NetBox,
  notification channels
- `Admin → Scope Manager` to enable only the features your team uses
- `Admin → Queues` to confirm the scheduled jobs are firing
- `/healthz` should return JSON with `"status":"ok"` once every
  component is up

---

## Operations

- **Backups**: `sudo /opt/meridian/scripts/backup.sh` (daily via cron
  by default). Restore: `sudo /opt/meridian/scripts/restore.sh <bundle>`
- **Backup smoke test**: `sudo /opt/meridian/scripts/smoke-backup-restore.sh`
  exercises the full backup → bundle → dry-run-restore loop. Run it after
  any backup-related change.
- **Doctor**: `sudo /opt/meridian/venv/bin/python -m app.cli doctor`
  for pre-flight diagnostics
- **Migrations**: `sudo /opt/meridian/scripts/migrate.sh` applies any
  pending schema changes. install.sh runs this automatically; for
  upgrades use `sudo /opt/meridian/install.sh --upgrade`
- **Fail2ban admin**: live unban / persistent ignoreip via
  `Admin → System Health → Fail2ban Jails`. If you lock yourself out
  via SSH, see `/opt/meridian/docs/admin/lockout-recovery.md`
- **GDPR**: any logged-in user can export their data dossier or erase
  their account via `Settings → Privacy & data`

---

## Architecture (one screen)

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser  ──TLS──>  nginx (port 443)  ──> gunicorn (uvicorn)    │
│                                            │                    │
│                                            ▼                    │
│                                     FastAPI + Jinja2            │
│                                            │                    │
│        ┌──────────────────┬────────────────┼────────────────┐   │
│        ▼                  ▼                ▼                ▼   │
│   PostgreSQL 17     Valkey (broker)     BIND9          AppArmor │
│   (data + audit)    │                  (sandbox        (per-svc │
│                     │                   resolver)      profiles)│
│                     ▼                                           │
│              Celery workers + beat (redbeat schedule)           │
│                                                                 │
│  fail2ban (sshd, nginx, meridian-login)                         │
│  systemd-networkd  ·  HMAC row chain  ·  AES-256-GCM vault      │
└─────────────────────────────────────────────────────────────────┘
```

- **Frontend**: Jinja2 + vanilla JS (no SPA framework) + plain CSS
- **Backend**: Python 3.13 + FastAPI + SQLAlchemy 2.x
- **DB**: PostgreSQL 17 (13) / 15 (12), SCRAM-SHA-256 localhost-only
- **Broker / cache**: Valkey (Debian 13) / Redis (Debian 12)
- **Worker**: Celery + redbeat (schedule reads from `jobs` table)
- **Web**: Nginx (TLS + full security headers)
- **DNS**: BIND9 recursive resolver, isolated on 127.0.0.1
- **Certs**: ACME via certbot (Let's Encrypt) or self-signed

---

## Safety: no networking bombs

Every poll, monitor, scan, and external-API integration has a hard
floor / ceiling baked in. See [`app/safety/limits.py`](app/safety/limits.py)
for the constants. Defaults are conservative; an admin can raise them
intentionally but the out-of-the-box deployment cannot be weaponised
as a DDoS source against your own LAN or against external services.

---

## Distribution under Apache 2.0

You can:

- Run Meridian in production for any purpose, commercial or otherwise
- Modify the source for your needs
- Distribute modified versions, including commercially, provided you:
  - Include this LICENSE in the distribution
  - Note any changes to modified files
  - Preserve copyright + attribution notices (see NOTICE)
  - Use a name and logo that aren't "MeridianNIP" (trademark, not
    license-granted; see LICENSE Section 6)

You cannot:

- Use "MeridianNIP" as the name of your fork or derivative
- Hold the contributors liable for damages (LICENSE Section 8)

---

## Contributing

Contributions accepted under the same Apache 2.0 terms. Open a PR
against the repo; the project standardises on:

- Python style: ruff defaults; line length 100
- Migrations: numbered files in `db/migrations/`, one BEGIN..COMMIT per
  file, idempotent where possible (use `CREATE TABLE IF NOT EXISTS`,
  `ADD COLUMN IF NOT EXISTS`)
- Tests: pytest under `tests/`; aim for coverage on every new route
  handler

---

## License

[Apache License 2.0](LICENSE).

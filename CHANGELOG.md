# Changelog

All notable changes to Meridian are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions adhere to
semantic versioning.

## [Unreleased]

Queued for v1.0.2:

### Fixed (TODO)
- `install.sh` on `--upgrade` regenerates the PostgreSQL `meridian`
  role password instead of reusing the existing one from
  `/etc/meridian/meridian.conf`, then fails the post-stage connection
  test with "password authentication failed for user meridian".
  Surfaced 2026-05-14 on the v1.0.1 apt-upgrade-of-prod validation —
  the previous two upgrade fixes unblocked install.sh enough to
  reach this stage. Fix: when `--upgrade` is in effect and
  `/etc/meridian/meridian.conf` already declares a `db_dsn` with
  embedded password, parse it and reuse the password rather than
  generating a new one (or skip `setup_postgresql`'s role-password
  step entirely on upgrade).

## [1.0.1] — 2026-05-14

Bug-fix release; only `install.sh` changes. No DB migrations, no app
changes — safe to `apt upgrade meridian-nip` on any v1.0.0 install.
Existing v1.0.0 VM appliance and ISO remain valid (the bugs only
fire on the upgrade path, not on fresh installs).

Release page: <https://github.com/MeridianNIP/meridian/releases/tag/v1.0.1>

### Fixed
- `install.sh` `install_os_packages` racing with dpkg lock when invoked
  by the meridian-nip .deb's postinst (i.e. `apt install meridian-nip`).
  The .deb's Depends: line already enumerates every OS package
  install.sh would install, so when running under dpkg the stage is
  now a documented no-op (detect via `DPKG_MAINTSCRIPT_PACKAGE` env).
- `install.sh` `setup_postgresql` re-running `schema.sql` on every
  invocation, which failed `--upgrade` paths with "type already exists"
  because the CREATE TYPE statements in schema.sql aren't IF-NOT-EXISTS
  guarded. Now skipped automatically when the public schema already
  has tables — migrate.sh handles reconciliation in that case.

## [1.0.0] — 2026-05-14

First public release. Tagged + published to GitHub Releases after the
2026-05-14 rc1 validation pass on a fresh Hyper-V VM (30/32 checks
green; the two remaining were quoting bugs in the validation harness,
not product issues).

Release page: <https://github.com/MeridianNIP/meridian/releases/tag/v1.0.0>
— includes the preseed-injected Debian 13.4 ISO (940 MB, UEFI-bootable)
plus `SHA256SUMS`. Source on `main` at this tag matches the asset.

Licensed under **Apache License 2.0** (no commercial tier, no license-key
gating, total feature parity for every install). "MeridianNIP" name + logo
are common-law trademarks — forks must use a different name and logo.

### Added — core platform
- FastAPI application + Jinja2 templates, PostgreSQL 17/15, Valkey/Redis, Celery + redbeat, BIND9, Nginx
- `install.sh` interactive installer with Debian 12 / 13 auto-detection and `--airgapped` flag (skips outbound apt + Let's Encrypt; keeps install local to your machine)
- Two-person approval workflow for `requires_two_person` permissions
- argon2id passwords, TOTP MFA, single-session enforcement
- HMAC-SHA256 row-hash chain on 8 sensitive tables
- AES-256-GCM field vault with HKDF-lite domain-separated subkeys
- CSRF double-submit cookie middleware (`app/auth/csrf.py`)
- Nginx template with full security-header set (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- AppArmor profile, systemd units with `CapabilityBoundingSet`, fail2ban jail, UFW rules, logrotate

### Added — tool surfaces
- **DNS Tools** (5 tabs) — dig, propagation across 16 resolvers, DNSSEC chain walker, AXFR audit, CT log / crt.sh, zone health, reverse PTR
- **Network Tools** (5 tabs) — ping, traceroute, HTTP test, port scan, SNMP walk, packet capture (tcpdump with CAP_NET_RAW file-cap path)
- **16 Wizards** — `dns.resolve_fail`, `mail.delivery`, `ssl.deep_inspect`, `dnssec.chain`, `zone.health`, `registrar.mismatch`, `domain.bringup`, `cloudflare.validator`, `typosquat.sweep`, `dmarc.tuning`, `axfr.audit`, `ip.reputation`, `infoblox.drift`, `network.reachability`, `network.up_for_everyone`, `mail.flow_validator`
- **Runbook engine** — 12-tool registry, per-step permission gating, configurable `continue_on`, full run-history persistence
- **Certificates** — ACME accounts, parsing, CSR, watchlist, scheduled expiry check + auto-renew
- **Monitors** — probes with anti-flap reconcile, scheduled collector, incident dispatch, retention rotation
- **DHCP Intelligence** — Infoblox Grid + CSP + ISC Kea backends with aggregator
- **IPAM Intelligence** — Infoblox + NetBox + phpIPAM + BlueCat + spreadsheet adapters (read-only)
- **Directory Ops** — LDAP / Active Directory / Entra ID search, unlock / disable / reset-password with approval gating
- **Files** — per-user quota, streaming up/download, pcap auto-registration
- **Messages** — direct / group / broadcast with unread tracking

### Added — admin surfaces (10-tab admin panel)
- Overview, Users, Scope Manager (CIDR allow/deny overlays on top of RFC1918 defaults)
- Integrations (DHCP / IPAM / Directory CRUD with vault-stored credentials)
- **Network Devices** — SSH-based config backup via netmiko; Cisco IOS/IOS-XR/NX-OS/ASA, Juniper Junos, Arista EOS, Palo Alto PAN-OS, Fortinet FortiOS, MikroTik RouterOS, generic SSH; SHA-256-gated snapshot storage ("backup on change"), unified-diff per snapshot, inventory + per-device drawer with side-by-side diff viewer
- Vulnerabilities (OSV.dev scanning, severity filters, multi-select bulk suppress, external ref links)
- System Health + Repair (live checks + curated repair actions)
- Updates (apt pending, version drift, manifest, snapshots, history; apply is CLI-only)
- Webhooks (inbound receivers + outbound fan-out, HMAC signed, delivery log)
- Branding (display identity + four image uploads with magic-byte + SVG sanitization)

### Added — background jobs (13 Celery modules)
- `integrity.scan` (HMAC row-hash verify)
- `cert.expiry_check` + `cert.auto_renew` (certbot-backed for ACME, notification for manual)
- `monitors.collector.sample_due` + `monitors.collector.retention`
- `vuln.scan` (OSV + SBOM components)
- `backup.full_db` / `backup.rotate` / `backup.wal_ship`
- `db.vacuum_analyze` / `db.reindex_hot`
- `retention.{audit,query,celery,pcap,file_quota}_cleanup` / `retention.sessions`
- `ad.stale_accounts`, `dhcp.utilization`, `ipam.conflict_scan`
- `health.feature_ping`, `oss.scan`, `upgrade.{apt_check,check_drift,pre_snapshot}`
- `devices.backup_all` + `devices.retention`

### Added — packaging + docs
- `pyproject.toml` with ruff + mypy + pytest config
- `.pre-commit-config.yaml` with ruff + shellcheck + standard hygiene
- `.github/workflows/ci.yml` — lint (ruff + shellcheck + schema), celery-handler-vs-task audit, admin-tab-bar consistency, unit + smoke tests; all green at tag time
- `db/migrations/` scaffold + `scripts/migrate.sh` (SHA-tracked, transactional runner)
- `scripts/backup.sh`, `restore.sh`, `doctor.sh`, `health_check.sh`, `wal_archive.sh`, `setup_luks.sh`, `repack-preseed-iso.sh`, `smoke-backup-restore.sh`
- Third-party attribution in `docs/legal/oss.html`
- AUP template in `docs/legal/aup-template.html`
- Prometheus `/metrics` endpoint (`app/metrics.py`), gated by `admin.system.metrics`
- Fresh-install validation pass: 30 of 32 checks green on a hands-off
  Hyper-V VM rebuild; full feature surface walked

### Added — post-tag updates to the v1.0.0 release page
- **VM appliance images** attached to the release: `meridian-nip-v1.0.0.vhdx.zst` (Hyper-V, 1.1 GB), `meridian-nip-v1.0.0.qcow2` (KVM/Proxmox, 1.4 GB), and `meridian-nip-v1.0.0.ova` (VMware/VirtualBox, 1.4 GB). Plus `SHA256SUMS-appliance` covering all three. Built from a scrubbed `meridian-appliance` VM with per-appliance secrets (master key + row-HMAC key + SSH host keys regenerated, audit/sessions cleared, DHCP networking).
- **`scripts/build-deb.sh`** + **`scripts/publish-apt.sh`** — thin-wrapper Debian packaging + apt-repo publishing (signed via GPG ed25519 ops@meridiannip.com). Repo lives at <https://meridiannip.com/apt>.
- **`scripts/build-ova.sh`** — vmdk → OVA packager (used in the appliance build).

### Known gaps (tracked post-1.0)
- `docs/` portal HTML predates some 1.0 features and needs refresh (this CHANGELOG entry is the start of that)
- No responsive CSS (desktop-only UX — explicitly declined per positioning)
- No i18n (hardcoded English — explicitly declined per positioning)
- WebAuthn / OIDC SSO / SCIM not implemented (TOTP + password + fail2ban is the baseline)

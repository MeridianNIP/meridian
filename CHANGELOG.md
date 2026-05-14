# Changelog

All notable changes to Meridian are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions adhere to
semantic versioning.

## [Unreleased]

Nothing pending — next tagged release to be assigned when the first
field bug forces a 1.0.1.

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

### Known gaps (tracked post-1.0)
- `docs/` portal HTML predates some 1.0 features and needs refresh (this CHANGELOG entry is the start of that)
- No responsive CSS (desktop-only UX — explicitly declined per positioning)
- No i18n (hardcoded English — explicitly declined per positioning)
- WebAuthn / OIDC SSO / SCIM not implemented (TOTP + password + fail2ban is the baseline)
- VM appliance images (`.vhdx` / `.ova` / `.qcow2`) parked — current artifact is the preseed ISO only

# Changelog

All notable changes to Meridian are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions adhere to
semantic versioning.

## [Unreleased]

Nothing pending — next tagged release to be assigned when the first
field-install smoke test passes.

## [1.0.0] — 2026-04-18

First generally-available release. Represents the full scope of the initial
Meridian intake plus expansions landed during the build-out.

### Added — core platform
- FastAPI application + Jinja2 templates, PostgreSQL 17/15, Valkey/Redis, Celery + redbeat, BIND9, Nginx
- `install.sh` interactive installer with Debian 12 / 13 auto-detection and `--airgapped` wheel-bundled path
- Ed25519-signed, hardware-fingerprint-bound license tokens
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

### Added — background jobs (14 Celery modules)
- `license.verify` / `license.expiry_notify` (wired to dispatcher + webhook fanout)
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
- `.github/workflows/ci.yml` with syntax check, handler-vs-task audit, admin-nav-consistency check
- `db/migrations/` scaffold + `scripts/migrate.sh` (SHA-tracked, transactional runner)
- `scripts/backup.sh`, `restore.sh`, `doctor.sh`, `health_check.sh`, `wal_archive.sh`, `setup_luks.sh`, `build-release.sh`
- Third-party attribution in `docs/legal/oss.html`
- AUP template in `docs/legal/aup-template.html`

### Known gaps (tracked post-1.0)
- No automated test suite yet
- `docs/` HTML (14 pages) predates some 1.0 features and needs refresh
- No responsive CSS (desktop-only UX)
- No i18n (hardcoded English)
- No Prometheus `/metrics` endpoint
- First-run end-to-end smoke test on a fresh VM not yet exercised

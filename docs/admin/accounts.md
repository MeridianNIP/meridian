# Default accounts reference

Every account that ships with a Meridian install, where the credentials
come from, and which must be changed before any deployment leaves the
lab. Treat this doc as security-sensitive — it describes the attack
surface of a fresh build.

---

## Portal users (`users` table)

| Username | Role          | Default password | Force change? | MFA |
|----------|---------------|------------------|---------------|-----|
| `admin`  | `super_admin` | `meridian`       | **yes** — flagged `must_change_password=TRUE`, the first login cannot reach any page until the password is changed | Enrollment offered on first login |

- Credentials set by `install.sh`, stored as an Argon2id hash in the
  `users.password_hash` column. You can override the default by setting
  `ADMIN_TEMP_PASSWORD` in the environment before running the installer
  (used by `--unattended` and CI builds).
- No other portal users are seeded. Every additional admin / analyst /
  auditor / viewer is created from Admin Panel → Users after the first
  login.
- Directory-integrated users (LDAP / AD) show up as `primary_auth='ldap'`
  shadow rows; they never have a stored password.

---

## System (Linux) accounts

| User           | UID  | Shell             | Purpose                                                                 | Groups                     |
|----------------|------|-------------------|-------------------------------------------------------------------------|----------------------------|
| `meridian`     | 988  | `/usr/sbin/nologin` | Service account — runs `meridian-app`, `meridian-celery`, `meridian-beat`. No interactive login path. Owns `/opt/meridian`, `/var/lib/meridian`, `/var/log/meridian`, `/etc/meridian`. | `meridian`                  |
| `meridian-user`| 1000 | `/bin/bash`         | Interactive/deploy account used to SSH in and run admin commands. Password `meridian` (same install-time default). | `meridian-user`, `ddi-ssh`, `sudo` |
| `root`         | 0    | `/bin/bash`         | Standard root. SSH login via **key only** (`PermitRootLogin prohibit-password`). Password `meridian` at install. | `root`, `ddi-ssh`            |
| `postgres`     | varies | `/bin/bash`       | PostgreSQL superuser owned by the postgres package. Password unset; authenticated via peer auth over the local socket. Not reachable over the network. | `postgres`                   |

`ddi-ssh` is the group gated by `AllowGroups` in `sshd_config`. Only
members can SSH in — root and `meridian-user` are added at install.

---

## Database roles

| Role        | Purpose                                       | Auth                                   |
|-------------|-----------------------------------------------|----------------------------------------|
| `meridian`  | App connection (FastAPI + Celery + beat).     | Password, stored in `/etc/meridian/meridian.conf`. Localhost-only (`pg_hba.conf` restricts to `127.0.0.1/32 md5`). |
| `postgres`  | Schema migration + admin. Owns every table.   | Peer auth via the Unix socket; no password. |

The `meridian` role password is auto-generated at install and written to
`/etc/meridian/meridian.conf` (mode 0640, owner `meridian:meridian`).
It is embedded in the DSN that the app reads. Rotate with `ALTER ROLE
meridian WITH PASSWORD '…'` and update the conf file.

New migrations that create tables MUST grant the app role access:

```sql
GRANT ALL ON TABLE <new_table>     TO meridian;
GRANT USAGE, SELECT ON SEQUENCE <sequence> TO meridian;
```

Forgetting this emits `permission denied for table <name>` at runtime
because migrations run as `postgres` and new tables inherit that owner.

---

## Service / broker accounts

| Service             | Auth                                                                 |
|---------------------|----------------------------------------------------------------------|
| `redis` / `valkey`  | No password. Bound to `127.0.0.1` only. Used as Celery broker/backend. |
| `bind9` / `named`   | No user-facing auth — local recursive resolver. `rndc` uses a local HMAC key at `/etc/bind/rndc.key`. |
| `snmpd`             | Uses Meridian-issued SNMPv3 users configured via Admin Panel → SNMP. No v1/v2c communities by default. |
| `nginx`             | Runs as `www-data`. No auth boundary of its own — it terminates TLS and proxies to `meridian-app` on 127.0.0.1:8000. |
| `fail2ban`          | Reads/writes bans via `fail2ban-client`. Controlled from the portal via the super_admin Fail2ban jails card, backed by a narrow sudoers drop-in. |

None of the above expose a network login surface on a default install.

---

## What the first login MUST change

Before this VM leaves the build lab, the operator should:

1. **Sign in at `https://<portal>/ui/login` as `admin` / `meridian`** and complete the forced password reset.
2. **Enroll MFA** during that same first login (TOTP by default; WebAuthn also offered).
3. **Change the `meridian-user` Linux password** via console or SSH (`passwd`). Leaving it at `meridian` is a security incident waiting to happen.
4. **Change the `root` password** (`passwd root`) and install your own SSH pubkey into `/root/.ssh/authorized_keys`. Install.sh can do the pubkey step during setup if you paste one at the `Admin SSH pubkey` prompt.
5. **Rotate the database role password** if the install was cloned from a golden image — every clone shares the same credential otherwise.
6. **Set the admin CIDR / whitelist** at Admin Panel → System Health → Fail2ban jails so your workstation subnet can't be accidentally banned.

---

## Build-image checklist (what survives cloning)

A golden image snapshot preserves everything above, so treat every clone
as an untrusted base until these are rotated:

- [ ] Portal `admin` user still has `must_change_password=TRUE` (first login on each clone forces a fresh password)
- [ ] `meridian-user` + `root` Linux passwords have been reset per-clone
- [ ] Database `meridian` role password has been rotated and `/etc/meridian/meridian.conf` updated
- [ ] Row-HMAC key at `/etc/meridian/secrets/row_hmac.key` has been regenerated (otherwise clones share the same tamper-evident chain key and can impersonate each other)
- [ ] Master encryption key at `/etc/meridian/secrets/master.key` has been regenerated
- [ ] SSH host keys have been regenerated (`ssh-keygen -A` + remove old `/etc/ssh/ssh_host_*` first)

# Lockout recovery — operator playbook

Every Meridian access vector can lock somebody out. This page is the
single reference for who is locked out, why, and how the admin (or the
user) recovers. Print this and put it next to the console.

> **Console fallback** — if every remote path is blocked, an
> administrator with the **OS root password** can always reach the VM via
> Hyper-V Manager → Connect → log in as `root` (or via a Debian rescue
> ISO if the VM is hosted elsewhere). Without that password you fall
> back to the GRUB single-user trick (see [recovery.md](recovery.md)).

---

## Scenario matrix

| Lockout cause | User can self-serve? | Admin path | Notes |
|---|---|---|---|
| Forgot password | ✓ `/ui/forgot-password` | `/ui/admin/users` → row → "Reset password" | Email channel must be configured |
| Lost MFA device, has backup code | ✓ Use a backup code at login | n/a | Backup codes are one-shot; user must regenerate after use |
| Lost MFA device, no backup code | ✗ | `/ui/admin/users` → row → **"Reset MFA"** (**gap** — see below) | User must re-enroll TOTP after admin reset |
| Account locked (failed-login lockout) | ✗ | `/ui/admin/users` → row → "Unlock" | Audit row recorded |
| Disabled account | ✗ | `/ui/admin/users` → row → "Enable" | User edited their own profile or admin disabled |
| Session expired / idle timeout | ✓ Re-login | n/a | Default idle 30 min; per-user override at `/ui/settings#sessions` |
| Fail2ban IP ban (sshd, nginx, login jails) | ✗ | OS console: `fail2ban-client unban <ip>` (**gap** — no portal action) | All four jails use `nftables[type=allports]`; one trip blocks all ports |
| Lost recovery email (e.g. dead mailbox) | ✗ | Admin sets a temp password via reset, hands it to user out-of-band | Force-change-at-login flag flips on |
| Admin themselves locked out | ✗ | Console fallback above; reset their own row in `users` table | Avoid by always keeping at least 2 super_admin accounts |

---

## 1. Forgot password (the easy one)

**User flow** (works without any admin intervention if email is wired):

1. Click "Forgot password?" on the login page.
2. Enter username or email.
3. Portal sends a single-use reset link to the address of record.
4. Link drops user on `/ui/reset-password?token=…` — pick a new
   password, log in.

**If email isn't configured**, the user must contact the admin (out of
band). Admin path:

1. `/ui/admin/users` → find the user → **Reset password**.
2. Modal returns a temp password. Hand it to the user via Signal,
   phone, paper — anything except email if email is the broken channel.
3. `force_change_password` is auto-set; user is forced through a new
   password on next login.

**Audit trail**: `admin.user.reset_password` row in `audit_events`.

---

## 2. Lost MFA device — with backup codes

When a user enrolls TOTP, the portal generates a configurable count
(default 10, policy `mfa_backup_codes_count`) of **one-shot backup
codes**. They're shown ONCE at enrollment. Tell users to save them in a
password manager.

**User flow**:

1. At the login MFA prompt, click "Use a backup code instead".
2. Paste one code. Login succeeds. That code is now spent.
3. Once in, go to `/ui/settings#mfa` and **regenerate codes** — the old
   set is invalidated.

> Backup codes are an *escape hatch*, not a replacement for the
> authenticator. After one use, encourage the user to re-enroll TOTP on
> a fresh device.

---

## 3. Lost MFA device — no backup codes (admin reset)

> **GAP — not yet implemented.** A `/admin/users/{id}/reset-mfa`
> endpoint that clears `mfa_enrolled`, erases the encrypted TOTP secret,
> and audits as `admin.user.mfa_reset` is on the backlog. Until it
> ships, fall back to the SQL recipe at the bottom of this section.

Once shipped, admin flow will be:

1. `/ui/admin/users` → row → **"Reset MFA"** (super_admin only).
2. Confirm dialog ("the user will need to re-enroll TOTP and lose all
   backup codes — proceed?").
3. Portal flips `mfa_enrolled=false` and erases the TOTP secret +
   backup-code table. User is force-logged-out.
4. On next login the user is bounced through TOTP enrollment again.

**Fallback SQL recipe** (run as `meridian` DB user; replaces the not-yet-
implemented admin button):

```sql
BEGIN;
UPDATE users
   SET mfa_enrolled = false,
       totp_secret_encrypted = NULL,
       totp_last_used_at = NULL
 WHERE username = '<them>';
DELETE FROM mfa_backup_codes WHERE user_id =
  (SELECT id FROM users WHERE username = '<them>');
INSERT INTO audit_events (ts, user_id, action, target_type, target_key,
                          payload, outcome)
  VALUES (now(),
          (SELECT id FROM users WHERE username = '<acting-admin>'),
          'admin.user.mfa_reset.sql_fallback',
          'user',
          (SELECT id::text FROM users WHERE username = '<them>'),
          '{"note":"recovery.md SQL fallback"}'::jsonb,
          'ok');
COMMIT;
```

Then have the user log in and re-enroll under `/ui/settings#mfa`.

---

## 4. Account locked (failed-login lockout)

Failed-login threshold + duration come from `policy_routes.py` (defaults:
N failures in M minutes triggers lockout, sticky until admin clears).

**Admin flow**:

1. `/ui/admin/users` → filter by `locked = true` (Locked column shows a
   red badge).
2. Row → **Unlock**.
3. Audit row recorded as `admin.user.unlock`.

Consider also calling `Reset password` if you suspect compromise — a
fresh password invalidates any sessions an attacker might have minted.

---

## 5. Fail2ban IP ban (this is the SSH / portal one)

Fail2ban runs four jails by default on a Meridian box:

| Jail | What it watches | Default maxretry / findtime / bantime |
|---|---|---|
| `sshd` | `/var/log/auth.log` for failed SSH | 4 / 10m / 1h |
| `nginx-bad-request` | nginx 400 storms | 6 / 5m / 30m |
| `nginx-req-limit` | nginx rate-limit 429s | 8 / 5m / 1h |
| `meridian-login` | portal login 401s (filter at `/etc/fail2ban/filter.d/meridian-login.conf`) | 5 / 15m / 2h |

All four use `nftables[type=allports]` for the ban action, so **one
trip blocks the IP on every port**, including 22 and 443 — which means
the user can't even reach the login page to argue, and an admin whose
own workstation tripped a jail can lose SSH at the same time.

**`bantime.increment = true` + `factor=2` + `maxtime=7d`** means each
repeat ban DOUBLES in length. Trip 3× in a single afternoon and you
won't be able to reach the box again until tomorrow.

### Self-service path — none (today)

There's no portal "I'm locked out" page that an end user could hit from
a phone tether. Because the all-ports ban also drops 443, they can't
reach the portal at all.

### Portal admin path (preferred when you're NOT the one banned)

`/ui/admin/health` → **Fail2ban jails** card (super_admin only,
permission `admin.system.fail2ban`).

The card lists every jail with current ban count, total bans since
restart, current `ignoreip` list, and per-row actions:

- **Unban** any listed banned IP
- **Add IP to ignoreip** — temporary (lost on fail2ban restart)
- **Remove IP from ignoreip**

Backend wraps `fail2ban-client` via `sudo -n` through
`/etc/sudoers.d/meridian-fail2ban`. All actions audited as
`admin.fail2ban.{unban,addignoreip,delignoreip}`.

**Caveat — temporary vs permanent**: the card's "Add to ignoreip"
operates on the running jail only. The change does NOT survive a
fail2ban restart, reboot, or `fail2ban-client reload`. For permanent
whitelisting, edit `/etc/fail2ban/jail.local` or
`/etc/fail2ban/jail.d/meridian-admin-cidr.conf` directly (the latter
is install.sh-managed and refreshed on every install / --upgrade).

### Admin path — OS console

If you can SSH from a non-banned IP, you're golden:

```
fail2ban-client status                # list jails
fail2ban-client status sshd           # what's banned in sshd jail
fail2ban-client unban <ip>            # one-shot
fail2ban-client set sshd addignoreip <ip>   # session-only; doesn't survive reload
```

To **persist** an ignoreip across reloads and reboots, put it under
`[DEFAULT]` so it applies to every jail:

```
cat > /etc/fail2ban/jail.d/00-ignoreip-admins.conf <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 <your-admin-cidr>
EOF
fail2ban-client reload
```

`install.sh` already does this in `setup_fail2ban_apparmor()` via
`/etc/fail2ban/jail.local`, gated on the `ADMIN_CIDR` install prompt.
If you skipped that prompt, you're flying without a net.

### Admin path — Hyper-V / console fallback

If every IP is banned (including yours):

1. Hyper-V Manager → Connect to `meridian-vm`.
2. Log in as `root` (OS password from the Debian install — NOT the
   portal admin temp password).
3. Run the `unban` + persistent-ignoreip block above.

### Reset the bantime escalation

The escalation counter persists across reloads in
`/var/lib/fail2ban/fail2ban.sqlite3`. If you've been banned several
times today, your "next" ban will already be doubled. To reset:

```
fail2ban-client unban --all
systemctl stop fail2ban
rm /var/lib/fail2ban/fail2ban.sqlite3
systemctl start fail2ban
```

---

## 6. Session expired / idle timeout

Default: 30 minutes of no activity → session revoked → next request
returns 401, which the SPA redirects to `/ui/login?next=…`. Per-user
override on `/ui/settings#sessions`. Admin can bump the global default
at `/ui/admin/settings`.

Nothing for the user to do beyond re-login.

---

## 7. Admin locks themselves out

The biggest single risk in a small deployment with one admin.

**Prevent**: always keep **at least two super_admin** accounts on a
production install. The second exists solely to recover the first.

**Recover (last resort)** — direct SQL via console, identical to the
MFA-reset SQL fallback above but flipped to the admin row:

```sql
UPDATE users
   SET enabled = true,
       locked = false,
       failed_login_count = 0,
       mfa_enrolled = false,       -- only if MFA is the blocker
       totp_secret_encrypted = NULL
 WHERE username = '<admin-username>';
```

Then trigger a password reset via the admin CLI:

```
meridian-nip users reset-password --username <admin> --temp-password '<new>' --force-change-at-login
```

---

## Implementation status (2026-05-13)

| # | Item | Status |
|---|---|---|
| 1 | Portal Fail2ban admin card at `/ui/admin/health` | **Already shipped.** Routes in `app/admin/fail2ban_routes.py`, wrapper in `app/admin/fail2ban.py`, sudoers drop-in at `/etc/sudoers.d/meridian-fail2ban`, permission `admin.system.fail2ban` seeded in migration 0003. End-to-end verified live. |
| 2 | Admin "Reset MFA" endpoint | **Shipped.** `POST /admin/users/{id}/reset-mfa` clears `mfa_enrolled`, wipes `mfa_secret_enc`, deletes `mfa_backup_codes` rows, revokes active sessions. UI button on `/ui/admin/users` row (super_admin or admin.users.manage). Audited as `admin.user.mfa_reset`. |
| 3 | "I'm locked out" appeal page | **Shipped.** Public page at `/ui/locked-out` (link from `/ui/login`); POST `/api/v1/auth/lockout-appeal` rate-limited to 1 submission per source IP per hour. Rows persist in `lockout_appeals` (migration 0011). Caveat: an all-ports fail2ban ban still blocks the page itself — operators who want the appeal page reachable from a banned IP must run the relevant jails on per-port `banaction = nftables` (the default for most). |
| 4 | `ADMIN_CIDR` re-prompt on `--upgrade` | **Shipped.** `install.sh` now writes `/etc/fail2ban/jail.d/meridian-admin-cidr.conf` on every install or `--upgrade`, applying ADMIN_CIDR at the `[DEFAULT]` level so all four jails honor it. |
| 5 | Backup-code low-water banner | **Shipped.** `/ui/dashboard` shows a warning when an MFA-enrolled user has fewer than 3 unused backup codes. Links to `/ui/settings#mfa` to regenerate. |
| 6 | Secondary recovery contact | **Shipped.** Columns `users.recovery_email`, `users.recovery_phone` added via migration 0010; editable on `/ui/settings#profile`. Password-reset dispatcher fallback to recovery channels is on the backlog. |

## All backlog items shipped (2026-05-13)

1. **Recovery-email fallback in the notifications dispatcher** —
   `app/notifications/dispatcher.py` now synthesizes an ephemeral email
   channel from `users.email` and (when set) `users.recovery_email`
   whenever a user-targeted dispatch finds no configured email channel.
   No DB changes; recovery_email is opt-in via `/ui/settings#profile`.
2. **SMS provider (Twilio)** — `app/notifications/channels/sms.py`
   handles `kind = sms_twilio` channels using REST API + basic auth.
   Credentials come from the channel config OR env vars
   (`TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_FROM`).
   Dispatcher synthesizes an SMS channel from `users.recovery_phone`
   when no SMS channel is configured. Bodies are clamped to 480 chars
   (3 segments) so a runaway message can't burn the bill.
3. **Persistent ignoreip via the Fail2ban admin card** — the System
   Health page now has a "Persistent ignoreip" panel that writes to
   `/etc/fail2ban/jail.d/meridian-portal-overrides.conf` (meridian-owned)
   and reloads fail2ban via `sudo fail2ban-client reload` (allowed by
   the updated sudoers drop-in). Survives reload + reboot.
4. **Admin appeals review surface** — `/ui/admin/appeals` lists open /
   resolved / spam lockout appeals with per-row Resolve + Spam buttons.
   Endpoint at `/api/v1/admin/lockout-appeals` (permission
   `admin.users.manage`).

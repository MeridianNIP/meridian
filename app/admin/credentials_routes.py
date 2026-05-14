"""Admin Panel → Credentials.

Rotate the well-known default accounts that ship with a fresh install:
portal `admin`, Linux `meridian-user`, Linux `root`, DB role `meridian`,
plus the two cryptographic keys (row_hmac and master). Everything goes
through narrow wrapper scripts with specific sudoers entries — the
portal never writes to /etc/shadow or /etc/passwd directly.

Forensics: every rotation writes an audit row with outcome + actor,
and the in-memory history is returned by GET /history for the UI's
"last rotated" display.
"""
from __future__ import annotations

import subprocess
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.auth.password import hash_password
from app.db import fastapi_dep_db
from app.models.audit import AuditEvent
from app.models.user import User


router = APIRouter(prefix="/admin/credentials", tags=["admin-credentials"])

APPLY_SCRIPT = "/opt/meridian/scripts/rotate-credential.sh"


def _defer_app_restart(delay_s: int = 4) -> tuple[bool, str]:
    """Schedule a `systemctl restart meridian-app.service` to fire after
    `delay_s` seconds. Detaches from the current process so the HTTP
    response can flush before sshd / gunicorn dies.

    Implementation notes:
    - `start_new_session=True` is enough to detach — DON'T also pass
      `preexec_fn=os.setsid`, which causes a double-setsid in the child
      and silently kills it before exec (the second setsid fails with
      EPERM since the proc is already a session leader).
    - Output is captured to /var/log/meridian/restart.log so a botched
      sudo / failed unit restart leaves a forensic trail. /dev/null
      worked but hid every diagnostic.
    """
    log = "/var/log/meridian/restart.log"
    cmd = (
        f"date -u --iso-8601=seconds >> {log}; "
        f"sleep {int(delay_s)}; "
        f"sudo -n /usr/bin/systemctl restart meridian-app.service "
        f">> {log} 2>&1"
    )
    try:
        subprocess.Popen(
            ["/bin/sh", "-c", cmd],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        return True, f"restart scheduled in {delay_s}s"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"could not schedule restart: {e}"


class LinuxPasswordIn(BaseModel):
    account: str = Field(..., pattern=r"^(meridian-user|root)$")
    new_password: str = Field(..., min_length=12, max_length=256)


class PortalPasswordIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    new_password: str = Field(..., min_length=12, max_length=256)


class DbPasswordIn(BaseModel):
    new_password: str = Field(..., min_length=16, max_length=256)


def _rotate_wrapper(arg: str, secret: str | None = None) -> tuple[bool, str]:
    """Invoke /opt/meridian/scripts/rotate-credential.sh <arg> [-]. The
    wrapper reads the secret from stdin when needed so it never appears
    in process argv or journald."""
    try:
        r = subprocess.run(
            ["sudo", "-n", APPLY_SCRIPT, arg],
            input=(secret or "") + "\n",
            capture_output=True, text=True, timeout=30,
        )
        return (r.returncode == 0), ((r.stdout or "") + (r.stderr or ""))[:1200]
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"{type(e).__name__}: {e}"


@router.get("/status")
async def get_status(
    user: User = Depends(require_permission("admin.system.credentials")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Return a snapshot of when each credential was last rotated. Driven
    by the audit log (action=admin.credential.rotate.*)."""
    rows = db.execute(text("""
        SELECT a.action, a.ts, u.username AS actor_username, a.outcome
          FROM audit_events a
          LEFT JOIN users u ON u.id = a.user_id
         WHERE a.action LIKE 'admin.credential.rotate.%'
         ORDER BY a.ts DESC
         LIMIT 200
    """)).fetchall()
    # Keep the latest successful rotate per target.
    latest: dict[str, dict[str, Any]] = {}
    for action, ts, actor, outcome in rows:
        # action is 'admin.credential.rotate.<target>'
        target = action.rsplit(".", 1)[-1]
        if target in latest:
            continue
        latest[target] = {
            "last_rotated": ts.isoformat() if ts else None,
            "last_actor": actor,
            "last_outcome": outcome,
        }
    # Targets the UI knows about — ensure every card has an entry.
    targets = ["portal_admin", "linux_meridian_user", "linux_root",
               "db_meridian", "row_hmac_key", "master_key", "ssh_host_keys"]
    return {t: latest.get(t, {"last_rotated": None,
                              "last_actor": None,
                              "last_outcome": None}) for t in targets}


@router.post("/portal-password")
async def rotate_portal_password(
    request: Request, body: PortalPasswordIn,
    user: User = Depends(require_permission("admin.system.credentials")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    target = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"user {body.username!r} not found")
    target.password_hash = hash_password(body.new_password)
    # Clear any must-change flag so the user can actually log in after this.
    prefs = dict(target.preferences or {})
    prefs["force_change_password"] = False
    target.preferences = prefs
    db.flush()
    audit(db, user_id=user.id, action="admin.credential.rotate.portal_admin",
          target_type="user", target_key=body.username,
          payload={}, ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True, "detail": f"portal password for {body.username!r} reset"}


@router.post("/linux-password")
async def rotate_linux_password(
    request: Request, body: LinuxPasswordIn,
    user: User = Depends(require_permission("admin.system.credentials")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    ok, detail = _rotate_wrapper(f"linux:{body.account}", secret=body.new_password)
    target = "linux_root" if body.account == "root" else "linux_meridian_user"
    audit(db, user_id=user.id, action=f"admin.credential.rotate.{target}",
          target_type="linux_account", target_key=body.account,
          payload={"ok": ok, "detail": detail[:400]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail)
    return {"ok": True, "detail": f"password for {body.account} changed"}


@router.post("/db-password")
async def rotate_db_password(
    request: Request, body: DbPasswordIn,
    user: User = Depends(require_permission("admin.system.credentials")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Rotates the `meridian` PG role password AND updates
    /etc/meridian/meridian.conf so the app picks up the new DSN at
    next service restart. Does NOT restart the app automatically —
    that would kick the caller off the page; the UI shows a prompt."""
    ok, detail = _rotate_wrapper("db:meridian", secret=body.new_password)
    audit(db, user_id=user.id, action="admin.credential.rotate.db_meridian",
          target_type="db_role", target_key="meridian",
          payload={"ok": ok, "detail": detail[:400]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail)
    # Auto-restart so the worker pool reconnects with the new DSN.
    # The 4s delay lets this HTTP response reach the browser first.
    sched_ok, sched_detail = _defer_app_restart(delay_s=4)
    return {
        "ok": True,
        "detail": ("DB password rotated. The portal will restart in ~4 seconds "
                   "to reconnect with the new credentials — your page will "
                   "reload automatically."),
        "restart_scheduled": sched_ok,
        "restart_in_seconds": 4,
        "schedule_detail": sched_detail,
    }


class RotateKeyIn(BaseModel):
    confirm: str = Field(..., pattern=r"^ROTATE$")


@router.post("/row-hmac-key")
async def rotate_row_hmac_key(
    request: Request, body: RotateKeyIn,
    user: User = Depends(require_permission("admin.system.credentials")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Regenerate /etc/meridian/secrets/row_hmac.key. DESTRUCTIVE:
    invalidates the entire tamper-evident chain. The caller MUST
    immediately run the integrity:rebaseline repair afterwards,
    otherwise every scan will report thousands of mismatches."""
    ok, detail = _rotate_wrapper("key:row_hmac")
    audit(db, user_id=user.id, action="admin.credential.rotate.row_hmac_key",
          target_type="key", target_key="row_hmac",
          payload={"ok": ok, "detail": detail[:400]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail)
    # The row-HMAC key is loaded once per process via lru_cache AND
    # bound per-connection to PG via set_config('meridian.row_hmac_key').
    # Both layers need a fresh process to pick up the new key. Auto-
    # restart is mandatory here — without it, a follow-up rebaseline
    # would write hashes using the OLD key (still cached in memory),
    # which is the opposite of what the operator just asked for.
    sched_ok, sched_detail = _defer_app_restart(delay_s=4)
    return {
        "ok": True,
        "detail": ("row_hmac key rotated and archived. Portal restarts in ~4 seconds. "
                   "Once it's back, click Admin → Health → "
                   "Rebaseline integrity chain so every existing row is rehashed "
                   "with the new key (otherwise scans will alarm)."),
        "restart_scheduled": sched_ok,
        "restart_in_seconds": 4,
        "followup": "integrity:rebaseline",
    }


@router.post("/master-key")
async def rotate_master_key(
    request: Request, body: RotateKeyIn,
    user: User = Depends(require_permission("admin.system.credentials")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Regenerate /etc/meridian/secrets/master.key. DESTRUCTIVE:
    every secret in the vault (SMTP password, directory bind, SNMPv3
    auth, etc.) was encrypted with the old key and will be unreadable
    after this — you must re-enter every one via Admin → Integrations."""
    ok, detail = _rotate_wrapper("key:master")
    audit(db, user_id=user.id, action="admin.credential.rotate.master_key",
          target_type="key", target_key="master",
          payload={"ok": ok, "detail": detail[:400]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail)
    # Master key is also lru_cached. Restart so the new key is in force
    # before the operator starts re-entering integration secrets.
    sched_ok, sched_detail = _defer_app_restart(delay_s=4)
    return {
        "ok": True,
        "detail": ("master key rotated. Portal restarts in ~4 seconds. "
                   "Every encrypted secret (SMTP creds, LDAP bind, SNMPv3 users, "
                   "webhook signing) is now UNREADABLE — re-enter each via "
                   "Admin → Integrations once the portal is back."),
        "restart_scheduled": sched_ok,
        "restart_in_seconds": 4,
    }


@router.post("/ssh-host-keys")
async def rotate_ssh_host_keys(
    request: Request, body: RotateKeyIn,
    user: User = Depends(require_permission("admin.system.credentials")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Regenerate /etc/ssh/ssh_host_* and restart sshd. Every existing
    SSH client will see a "host key changed" warning until they clear
    the old fingerprint from their known_hosts."""
    ok, detail = _rotate_wrapper("ssh:host_keys")
    audit(db, user_id=user.id, action="admin.credential.rotate.ssh_host_keys",
          target_type="ssh", target_key="host_keys",
          payload={"ok": ok, "detail": detail[:400]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail)
    return {
        "ok": True,
        "detail": "SSH host keys regenerated + sshd reloaded. Clients will need to re-trust the new fingerprints (ssh-keygen -R <host>).",
    }

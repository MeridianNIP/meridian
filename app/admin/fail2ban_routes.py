"""Admin surface for fail2ban — list jails + banned IPs, unban an IP,
add/remove an IP from a jail's ignoreip list. Super-admin gate so the
regular admin role can't accidentally whitelist an attacker."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.admin import fail2ban as f2b
from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.user import User
from sqlalchemy.orm import Session as OrmSession


router = APIRouter(prefix="/admin/fail2ban", tags=["admin-fail2ban"])


@router.get("")
async def get_snapshot(
    user: User = Depends(require_permission("admin.system.fail2ban")),
) -> dict:
    return f2b.snapshot()


class IpIn(BaseModel):
    jail: str = Field(..., min_length=1, max_length=64)
    ip: str = Field(..., min_length=2, max_length=64)


@router.post("/unban")
async def post_unban(
    request: Request, body: IpIn,
    user: User = Depends(require_permission("admin.system.fail2ban")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        ok, detail = f2b.unban(body.jail, body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit(db, user_id=user.id, action="admin.fail2ban.unban",
          target_type="fail2ban", target_key=f"{body.jail}:{body.ip}",
          payload={"ok": ok, "detail": detail[:200]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail or "unban failed")
    return {"ok": True, "detail": detail}


@router.post("/ignore/add")
async def post_ignore_add(
    request: Request, body: IpIn,
    user: User = Depends(require_permission("admin.system.fail2ban")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        ok, detail = f2b.add_ignore(body.jail, body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit(db, user_id=user.id, action="admin.fail2ban.ignore.add",
          target_type="fail2ban", target_key=f"{body.jail}:{body.ip}",
          payload={"ok": ok, "detail": detail[:200]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail or "add failed")
    return {"ok": True, "detail": detail}


@router.post("/ignore/remove")
async def post_ignore_remove(
    request: Request, body: IpIn,
    user: User = Depends(require_permission("admin.system.fail2ban")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        ok, detail = f2b.del_ignore(body.jail, body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit(db, user_id=user.id, action="admin.fail2ban.ignore.remove",
          target_type="fail2ban", target_key=f"{body.jail}:{body.ip}",
          payload={"ok": ok, "detail": detail[:200]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail or "remove failed")
    return {"ok": True, "detail": detail}


class PersistIpIn(BaseModel):
    ip: str = Field(..., min_length=2, max_length=64)


@router.post("/ignore/persist/add")
async def post_persist_add(
    request: Request, body: PersistIpIn,
    user: User = Depends(require_permission("admin.system.fail2ban")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Write an IP/CIDR to the portal-managed ignoreip drop-in and reload
    fail2ban. Unlike `/ignore/add` (per-jail, runtime-only), this survives
    reload + reboot because it applies to the `[DEFAULT]` section of a
    persistent file."""
    try:
        ok, detail = f2b.persist_ignore_add(body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit(db, user_id=user.id, action="admin.fail2ban.persist.add",
          target_type="fail2ban", target_key=body.ip,
          payload={"ok": ok, "detail": detail[:200]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail or "persist failed")
    return {"ok": True, "detail": detail}


@router.post("/ignore/persist/remove")
async def post_persist_remove(
    request: Request, body: PersistIpIn,
    user: User = Depends(require_permission("admin.system.fail2ban")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        ok, detail = f2b.persist_ignore_remove(body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit(db, user_id=user.id, action="admin.fail2ban.persist.remove",
          target_type="fail2ban", target_key=body.ip,
          payload={"ok": ok, "detail": detail[:200]},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    if not ok:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail or "persist remove failed")
    return {"ok": True, "detail": detail}

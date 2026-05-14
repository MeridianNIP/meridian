from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user
from app.auth.password import hash_password, verify_password
from app.auth.session_manager import revoke_session
from app.db import fastapi_dep_db
from app.models.session import Session as SessionModel
from app.models.user import User


router = APIRouter(prefix="/settings", tags=["settings"])


class ProfileUpdate(BaseModel):
    display_name: str | None = Field(None, max_length=128)
    timezone: str | None = Field(None, max_length=64)
    phone_e164: str | None = Field(None, max_length=32)
    sms_carrier_gateway: str | None = Field(None, max_length=64)
    idle_timeout_override_min: int | None = Field(None, ge=0, le=1440)
    recovery_email: str | None = Field(None, max_length=256)
    recovery_phone: str | None = Field(None, max_length=32)


@router.post("/profile")
async def update_profile(
    request: Request,
    body: ProfileUpdate,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    changes: dict[str, object] = {}
    if body.display_name is not None and body.display_name != user.display_name:
        changes["display_name"] = body.display_name
    if body.timezone is not None and body.timezone != user.timezone:
        changes["timezone"] = body.timezone
    if body.phone_e164 is not None and body.phone_e164 != user.phone_e164:
        changes["phone_e164"] = body.phone_e164
    if body.sms_carrier_gateway is not None and body.sms_carrier_gateway != user.sms_carrier_gateway:
        changes["sms_carrier_gateway"] = body.sms_carrier_gateway
    if body.idle_timeout_override_min is not None and body.idle_timeout_override_min != user.idle_timeout_override_min:
        changes["idle_timeout_override_min"] = body.idle_timeout_override_min
    if body.recovery_email is not None and body.recovery_email != user.recovery_email:
        changes["recovery_email"] = body.recovery_email or None
    if body.recovery_phone is not None and body.recovery_phone != user.recovery_phone:
        changes["recovery_phone"] = body.recovery_phone or None
    for k, v in changes.items():
        setattr(user, k, v)
    if changes:
        audit(db, user_id=user.id, action="settings.profile.update",
              payload={"fields": list(changes.keys())},
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))
    return {"updated": list(changes.keys())}


class PasswordChange(BaseModel):
    current: str
    new: str = Field(..., min_length=12, max_length=256)


class PreferenceUpsert(BaseModel):
    key: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    value: Any = None


@router.get("/preferences")
async def get_preference(
    key: str,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Read one key from the caller's JSONB preferences blob. Used by
    the dashboard pinned-tools editor, the important-links reorder,
    and any future per-user personalization that doesn't warrant its
    own schema."""
    if not key.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "key must be alphanumeric")
    prefs = user.preferences or {}
    return {"key": key, "value": prefs.get(key)}


@router.put("/preferences")
async def set_preference(
    request: Request,
    body: PreferenceUpsert,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    u = db.get(User, user.id)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user row missing")
    prefs = dict(u.preferences or {})
    if body.value is None:
        prefs.pop(body.key, None)
    else:
        prefs[body.key] = body.value
    u.preferences = prefs
    audit(db, user_id=u.id, action="settings.preference.set",
          target_type="user_preference", target_key=body.key,
          payload={"cleared": body.value is None},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True, "key": body.key, "value": body.value}


@router.post("/password")
async def change_password(
    request: Request,
    body: PasswordChange,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if not user.password_hash or not verify_password(body.current, user.password_hash):
        audit(db, user_id=user.id, action="settings.password.change_failed",
              payload={"reason": "bad_current"}, outcome="denied",
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current password incorrect")
    user.password_hash = hash_password(body.new)
    # Clear the force-change flag if it was set.
    prefs = dict(user.preferences or {})
    prefs.pop("force_change_password", None)
    user.preferences = prefs
    audit(db, user_id=user.id, action="settings.password.change",
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}


@router.post("/sessions/{session_id}/revoke")
async def revoke_my_session(
    request: Request,
    session_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    sess = db.get(SessionModel, session_id)
    if sess is None or sess.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    if sess.revoked_at is not None:
        return {"ok": True, "already_revoked": True}
    revoke_session(db, sess.id, reason="user_revoked", by=user.id)
    audit(db, user_id=user.id, action="settings.session.revoke",
          target_type="session", target_key=str(sess.id),
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}


@router.post("/sessions/revoke-others")
async def revoke_others(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    current_sid = getattr(request.state, "session_id", None)
    result = db.execute(text("""
        UPDATE sessions SET revoked_at = now(), revoked_reason = 'user_revoke_others',
                            revoked_by = :u
         WHERE user_id = :u AND revoked_at IS NULL AND id <> :keep
    """), {"u": user.id, "keep": current_sid})
    n = result.rowcount or 0
    audit(db, user_id=user.id, action="settings.sessions.revoke_others",
          payload={"revoked": n},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"revoked": n}

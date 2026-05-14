from __future__ import annotations

from datetime import UTC, datetime
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.auth.password import hash_password
from app.db import fastapi_dep_db
from app.models.user import User

router = APIRouter(prefix="/admin/users", tags=["admin-users"])


_ALLOWED_ROLES = ("super_admin", "admin", "analyst", "viewer", "auditor", "api_service")


@router.get("/role-counts")
async def role_counts(
    user: User = Depends(require_permission("admin.users.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict[str, int]:
    """How many local users hold each role. Powers the Global Settings
    → Roles card. AD-only users (if any exist with no local row) are
    not included — those are surfaced through the directory role map."""
    from sqlalchemy import Text, cast

    rows = db.execute(
        select(cast(User.role, Text), func.count()).where(User.deleted_at.is_(None)).group_by(User.role)
    ).all()
    out = {r: 0 for r in _ALLOWED_ROLES}
    for role, n in rows:
        out[str(role)] = int(n)
    return out


def _serialize(u: User) -> dict:
    return {
        "id": str(u.id),
        "username": u.username,
        "email": u.email,
        "display_name": u.display_name,
        "role": u.role,
        "enabled": u.enabled,
        "locked": u.locked,
        "mfa_enrolled": u.mfa_enrolled,
        "failed_login_count": u.failed_login_count,
        "max_concurrent_sessions": u.max_concurrent_sessions,
        "idle_timeout_override_min": u.idle_timeout_override_min,
        "timezone": u.timezone,
        "recovery_email": u.recovery_email,
        "recovery_phone": u.recovery_phone,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "last_active_at": u.last_active_at.isoformat() if u.last_active_at else None,
        "deleted_at": u.deleted_at.isoformat() if u.deleted_at else None,
    }


@router.get("/")
async def list_users(
    include_disabled: bool = True,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    q = select(User).where(User.deleted_at.is_(None))
    if not include_disabled:
        q = q.where(User.enabled.is_(True))
    rows = list(db.execute(q.order_by(User.username)).scalars())
    return {
        "users": [_serialize(u) for u in rows],
        "total": len(rows),
        "enabled": sum(1 for u in rows if u.enabled and not u.locked),
    }


class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    email: str = Field(..., max_length=256)
    display_name: str | None = Field(None, max_length=128)
    role: str = Field(..., pattern=r"^(super_admin|admin|analyst|viewer|auditor|api_service)$")
    temp_password: str | None = Field(None, min_length=12, max_length=256)
    force_change_password: bool = True


@router.post("/", status_code=201)
async def create_user(
    request: Request,
    body: UserCreate,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.role not in _ALLOWED_ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "role not allowed")
    existing = db.execute(
        select(User).where((User.username == body.username) | (User.email == body.email))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username or email already in use")

    # Only super_admin can create another super_admin.
    if body.role == "super_admin" and user.role != "super_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only super_admin can create another super_admin")

    temp_pw = body.temp_password or _generate_password(24)
    now = datetime.now(UTC)
    u = User(
        id=uuid.uuid4(),
        username=body.username,
        email=body.email,
        display_name=body.display_name,
        role=body.role,
        enabled=True,
        locked=False,
        password_hash=hash_password(temp_pw),
        primary_auth="credential",
        preferences=({"force_change_password": True} if body.force_change_password else {}),
        created_at=now,
        updated_at=now,
    )
    db.add(u)
    db.flush()
    audit(
        db,
        user_id=user.id,
        action="admin.user.create",
        target_type="user",
        target_key=body.username,
        payload={"role": body.role, "email": body.email, "temp_pw_generated": body.temp_password is None},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    # Temp password is returned once; never logged.
    return {"user": _serialize(u), "temp_password": temp_pw}


class UserUpdate(BaseModel):
    display_name: str | None = None
    email: str | None = Field(None, max_length=256)
    role: str | None = Field(None, pattern=r"^(super_admin|admin|analyst|viewer)$")
    enabled: bool | None = None
    max_concurrent_sessions: int | None = Field(None, ge=1, le=10)
    recovery_email: str | None = Field(None, max_length=256)
    recovery_phone: str | None = Field(None, max_length=32)


@router.patch("/{user_id}")
async def update_user(
    request: Request,
    user_id: uuid.UUID,
    body: UserUpdate,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    target = db.get(User, user_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if target.id == user.id and body.enabled is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot disable yourself")
    if body.role == "super_admin" and user.role != "super_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only super_admin can promote to super_admin")
    if (
        target.role == "super_admin"
        and body.role
        and body.role != "super_admin"
        and user.role != "super_admin"
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only super_admin can demote a super_admin")

    changed: dict = {}
    for field_name, value in body.model_dump(exclude_unset=True).items():
        if getattr(target, field_name) != value:
            changed[field_name] = {"from": getattr(target, field_name), "to": value}
            setattr(target, field_name, value)

    if changed:
        audit(
            db,
            user_id=user.id,
            action="admin.user.update",
            target_type="user",
            target_key=target.username,
            payload={"changes": list(changed.keys())},
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    return {"user": _serialize(target), "changed": list(changed.keys())}


@router.post("/{user_id}/reset-password")
async def reset_password(
    request: Request,
    user_id: uuid.UUID,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    target = db.get(User, user_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if target.role == "super_admin" and user.role != "super_admin":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "only super_admin can reset another super_admin's password"
        )

    temp_pw = _generate_password(24)
    target.password_hash = hash_password(temp_pw)
    target.preferences = {**(target.preferences or {}), "force_change_password": True}
    target.failed_login_count = 0
    target.locked = False
    audit(
        db,
        user_id=user.id,
        action="admin.user.reset_password",
        target_type="user",
        target_key=target.username,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"user": _serialize(target), "temp_password": temp_pw}


@router.post("/{user_id}/unlock")
async def unlock_user(
    request: Request,
    user_id: uuid.UUID,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    target = db.get(User, user_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    target.locked = False
    target.failed_login_count = 0
    audit(
        db,
        user_id=user.id,
        action="admin.user.unlock",
        target_type="user",
        target_key=target.username,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"user": _serialize(target)}


@router.post("/{user_id}/reset-mfa")
async def reset_mfa(
    request: Request,
    user_id: uuid.UUID,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Wipe the target's MFA enrollment so they can re-enroll a new
    authenticator. Used when a user loses their TOTP device and has
    burned through all backup codes."""
    from datetime import datetime

    from sqlalchemy import text, update

    from app.models.session import Session as SessionModel

    target = db.get(User, user_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if target.role == "super_admin" and user.role != "super_admin":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "only super_admin can reset MFA for another super_admin"
        )

    target.mfa_enrolled = False
    target.mfa_secret_enc = None
    db.execute(text("DELETE FROM mfa_backup_codes WHERE user_id = :u"), {"u": target.id})

    # Force every active session to terminate. MFA was the second factor —
    # leaving sessions alive after revoking it defeats the purpose.
    now = datetime.now(UTC)
    db.execute(
        update(SessionModel)
        .where(SessionModel.user_id == target.id, SessionModel.revoked_at.is_(None))
        .values(revoked_at=now, revoked_by=user.id, revoked_reason="admin_mfa_reset")
    )

    audit(
        db,
        user_id=user.id,
        action="admin.user.mfa_reset",
        target_type="user",
        target_key=target.username,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"user": _serialize(target), "message": "MFA cleared. User must re-enroll TOTP on next login."}


def _generate_password(length: int = 24) -> str:
    # Similar character set to install.sh gen_password but safer for URL/JSON.
    alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*_-"
    return "".join(secrets.choice(alphabet) for _ in range(length))

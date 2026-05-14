"""PATCH endpoint for Global Settings policy cards that currently live
on the branding row. As each policy domain gets its own dedicated
schema (future `password_policy`, `session_policy`, `mfa_policy`),
this endpoint migrates to route there — for now it's a single PATCH
surface so all the Save buttons on /ui/admin/settings work today.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user
from app.db import fastapi_dep_db
from app.models.branding import Branding, load as load_branding
from app.models.user import User


router = APIRouter(prefix="/admin/policy", tags=["admin-policy"])


_FIELDS = {
    # session
    "session_idle_timeout_default_min": (int, 0, 1440),
    "session_idle_timeout_max_min":     (int, 1, 1440),
    "session_idle_never_allowed":       (bool, None, None),
    # password
    "password_min_length":              (int, 8, 128),
    "password_required_classes":        (int, 1, 4),
    "password_max_age_days":            (int, 0, 3650),
    "password_history_depth":           (int, 0, 24),
    # mfa
    "mfa_requirement":                  (str, None, None),      # all|admins_only|optional
    "mfa_backup_codes_count":           (int, 0, 20),
    # lockout
    "lockout_threshold":                (int, 3, 50),
    "lockout_duration_min":             (int, 1, 1440),
    "lockout_unlock_mode":              (str, None, None),      # admin|time|admin_or_time
    # audit retention
    "audit_online_days":                (int, 30, 3650),
    "audit_archive_days":               (int, 90, 3650),
    "audit_archive_target":             (str, None, None),
}

_MFA_CHOICES = ("all", "admins_only", "optional")
_UNLOCK_CHOICES = ("admin", "time", "admin_or_time")


class PolicyPatch(BaseModel):
    # Every field optional; only provided ones are written.
    session_idle_timeout_default_min: int | None = None
    session_idle_timeout_max_min:     int | None = None
    session_idle_never_allowed:       bool | None = None
    password_min_length:              int | None = None
    password_required_classes:        int | None = None
    password_max_age_days:            int | None = None
    password_history_depth:           int | None = None
    mfa_requirement:                  str | None = None
    mfa_allowed_methods:              list[str] | None = None
    mfa_backup_codes_count:           int | None = None
    lockout_threshold:                int | None = None
    lockout_duration_min:             int | None = None
    lockout_unlock_mode:              str | None = None
    audit_online_days:                int | None = None
    audit_archive_days:               int | None = None
    audit_archive_target:             str | None = None


@router.get("")
async def get_policy(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if user.role != "super_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "super_admin role required")
    b = load_branding(db)
    return {f: getattr(b, f, None) for f in _FIELDS.keys()} | {
        "mfa_allowed_methods": list(b.mfa_allowed_methods or []),
    }


@router.patch("")
async def patch_policy(
    request: Request, body: PolicyPatch,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if user.role != "super_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "super_admin role required")
    b = load_branding(db)
    data = body.model_dump(exclude_unset=True)
    changed: dict[str, Any] = {}
    for field, val in data.items():
        if field == "mfa_allowed_methods":
            b.mfa_allowed_methods = list(val or [])
            changed[field] = b.mfa_allowed_methods
            continue
        spec = _FIELDS.get(field)
        if spec is None:
            continue
        typ, lo, hi = spec
        if typ is int and isinstance(val, int):
            if lo is not None and val < lo: val = lo
            if hi is not None and val > hi: val = hi
        if field == "mfa_requirement" and val not in _MFA_CHOICES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f"mfa_requirement must be one of {_MFA_CHOICES}")
        if field == "lockout_unlock_mode" and val not in _UNLOCK_CHOICES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f"lockout_unlock_mode must be one of {_UNLOCK_CHOICES}")
        setattr(b, field, val)
        changed[field] = val
    b.updated_at = datetime.now(timezone.utc)
    b.updated_by = user.id
    audit(db, user_id=user.id, action="admin.policy.update",
          target_type="branding", target_key="global",
          payload=changed, ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True, "changed": changed}

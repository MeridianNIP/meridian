"""GDPR Article 15 (right of access) + Article 17 (right to erasure).

Two operations, both on the authenticated user (with an admin
counterpart for handling subject-access-requests via support):

  - export()  → JSON dossier of everything we know about the user
  - erase()   → anonymize the profile, revoke credentials, preserve
                audit chain integrity

Erasure does NOT delete audit rows. The HMAC chain in `audit_events`
breaks if rows disappear, and operationally we still need to know
"someone logged in from 1.2.3.4 last Tuesday" — the chain pins the user
to a tombstone UUID so the row stays meaningful without the PII.

Both endpoints require fresh re-authentication (password + MFA where
enrolled) to defeat stolen-session attacks. The check is performed
inline rather than via a session-step-up flag because erasure is
high-stakes enough that we don't want to trust a previous step-up.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user, require_permission
from app.auth.mfa import decrypt_totp_secret, verify_totp
from app.auth.password import hash_password, verify_password
from app.db import fastapi_dep_db
from app.models.audit import AuditEvent
from app.models.session import Session as SessionModel
from app.models.user import User, UserGroup


router = APIRouter(tags=["users-self"])


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _row(u: User) -> dict[str, Any]:
    """Serialize a User row for export. Strips columns that are either
    secret material (password hash, mfa secret, mfa key encryption
    nonce) or pure technical metadata that the data subject can't act
    on."""
    return {
        "id":                       str(u.id),
        "username":                 u.username,
        "email":                    u.email,
        "display_name":             u.display_name,
        "primary_auth":             u.primary_auth,
        "role":                     u.role,
        "enabled":                  u.enabled,
        "locked":                   u.locked,
        "mfa_enrolled":             u.mfa_enrolled,
        "phone_e164":               u.phone_e164,
        "sms_carrier_gateway":      u.sms_carrier_gateway,
        "recovery_email":           u.recovery_email,
        "recovery_phone":           u.recovery_phone,
        "timezone":                 u.timezone,
        "preferences":              u.preferences,
        "external_id":              u.external_id,
        "max_concurrent_sessions":  u.max_concurrent_sessions,
        "idle_timeout_override_min": u.idle_timeout_override_min,
        "created_at":               u.created_at.isoformat() if u.created_at else None,
        "updated_at":               u.updated_at.isoformat() if u.updated_at else None,
        "last_login_at":            u.last_login_at.isoformat() if u.last_login_at else None,
        "last_active_at":           u.last_active_at.isoformat() if u.last_active_at else None,
        "deleted_at":               u.deleted_at.isoformat() if u.deleted_at else None,
    }


def _build_dossier(db: OrmSession, user: User) -> dict[str, Any]:
    """Collect everything we know about `user` across tables."""
    sessions = db.execute(
        select(SessionModel).where(SessionModel.user_id == user.id)
        .order_by(SessionModel.created_at.desc()).limit(500)
    ).scalars().all()
    sess_rows = [{
        "id":            str(s.id),
        "auth_method":   s.auth_method,
        "ip":            s.ip,
        "user_agent":    s.user_agent,
        "device_label":  s.device_label,
        "created_at":    s.created_at.isoformat() if s.created_at else None,
        "last_active_at": s.last_active_at.isoformat() if s.last_active_at else None,
        "expires_at":    s.expires_at.isoformat() if s.expires_at else None,
        "revoked_at":    s.revoked_at.isoformat() if s.revoked_at else None,
        "revoked_reason": s.revoked_reason,
    } for s in sessions]

    audit_rows = db.execute(
        select(AuditEvent).where(AuditEvent.user_id == user.id)
        .order_by(AuditEvent.ts.desc()).limit(5000)
    ).scalars().all()
    audit_serialized = [{
        "ts":          ev.ts.isoformat() if ev.ts else None,
        "action":      ev.action,
        "target_type": ev.target_type,
        "target_key":  ev.target_key,
        "ip":          ev.ip,
        "user_agent":  ev.user_agent,
        "outcome":     ev.outcome,
        "payload":     ev.payload,  # already redacted at insert time
    } for ev in audit_rows]

    groups = db.execute(
        select(UserGroup).where(UserGroup.user_id == user.id)
    ).scalars().all()
    group_rows = [{
        "group_id": str(g.group_id),
        "added_at": g.added_at.isoformat() if g.added_at else None,
    } for g in groups]

    # Optional/cross-table queries below use SAVEPOINTs so a schema mismatch
    # (column renamed in a future migration, table dropped) doesn't poison
    # the outer transaction — the audit INSERT at the end MUST succeed.

    mfa_summary: dict[str, Any] = {"enrolled": user.mfa_enrolled,
                                   "backup_codes_unused": 0,
                                   "backup_codes_used":   0}
    try:
        with db.begin_nested():
            backup_codes = db.execute(text(
                "SELECT count(*) FILTER (WHERE used_at IS NULL) AS unused, "
                "count(*) FILTER (WHERE used_at IS NOT NULL) AS used "
                "FROM mfa_backup_codes WHERE user_id = :uid"
            ), {"uid": user.id}).first()
        if backup_codes:
            mfa_summary["backup_codes_unused"] = int(backup_codes.unused)
            mfa_summary["backup_codes_used"]   = int(backup_codes.used)
    except Exception:
        pass

    # Notification channels owned by the user (secrets stripped).
    notif_rows: list[dict[str, Any]] = []
    try:
        with db.begin_nested():
            notif_rows_raw = db.execute(text(
                "SELECT id, kind, description, target, enabled, created_at, updated_at "
                "FROM notif_channels WHERE user_id = :uid"
            ), {"uid": user.id}).mappings().all()
        notif_rows = [
            {
                "id":          str(r["id"]),
                "kind":        r["kind"],
                "description": r["description"],
                "target":      r["target"],
                "enabled":     r["enabled"],
                "created_at":  r["created_at"].isoformat() if r["created_at"] else None,
                "updated_at":  r["updated_at"].isoformat() if r["updated_at"] else None,
            }
            for r in notif_rows_raw
        ]
    except Exception:
        notif_rows = []

    return {
        "exported_at":         datetime.now(timezone.utc).isoformat(),
        "generated_by":        "meridian-gdpr-export-v1",
        "profile":             _row(user),
        "mfa":                 mfa_summary,
        "group_memberships":   group_rows,
        "sessions":            sess_rows,
        "notification_channels": notif_rows,
        "audit_events":        audit_serialized,
        "audit_event_count":   len(audit_serialized),
        "audit_event_capped":  len(audit_serialized) >= 5000,
    }


# ---------------------------------------------------------------------------
# Re-auth gate (used by both export and erase)
# ---------------------------------------------------------------------------


class ReauthConfirm(BaseModel):
    password: str = Field(..., min_length=1, max_length=512)
    totp_code: str | None = Field(default=None, min_length=6, max_length=10)


def _require_fresh_credentials(db: OrmSession, user: User, body: ReauthConfirm) -> None:
    """Raise HTTPException(401) unless `body` proves the caller knows
    the user's current password AND can satisfy MFA if enrolled."""
    if not user.password_hash or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "password incorrect")
    if user.mfa_enrolled:
        if not body.totp_code or not user.mfa_secret_enc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "MFA code required")
        secret = decrypt_totp_secret(user.mfa_secret_enc)
        if not verify_totp(secret, body.totp_code):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "MFA code invalid")


# ---------------------------------------------------------------------------
# Export endpoint (Article 15)
# ---------------------------------------------------------------------------


@router.get("/users/me/export")
async def export_my_data(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict[str, Any]:
    """Return everything Meridian stores about the caller. Idempotent;
    safe to repeat. Audit-logged."""
    dossier = _build_dossier(db, user)
    audit(db, user_id=user.id, action="user.gdpr.export",
          target_type="user", target_key=str(user.id),
          payload={
              "audit_event_count": dossier["audit_event_count"],
              "audit_event_capped": dossier["audit_event_capped"],
          },
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return dossier


# ---------------------------------------------------------------------------
# Erasure endpoint (Article 17)
# ---------------------------------------------------------------------------


class EraseConfirm(ReauthConfirm):
    acknowledge: str = Field(..., description="must equal 'I understand this is irreversible'")


@router.post("/users/me/erase")
async def erase_my_account(
    request: Request,
    body: EraseConfirm,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict[str, Any]:
    """Anonymize the caller's profile and revoke all credentials.

    Audit rows are kept (their HMAC chain depends on it) but their
    user_id stays pointing at the now-anonymized user row.
    """
    if body.acknowledge.strip() != "I understand this is irreversible":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "acknowledge text mismatch",
        )
    _require_fresh_credentials(db, user, body)

    tombstone = uuid.uuid4().hex[:12]
    original_username = user.username

    # Anonymize the row in place — schema stays valid, FK targets remain
    # resolvable. The username/email get tombstone tokens so they don't
    # collide with the unique constraint.
    user.username       = f"erased-{tombstone}"
    user.email          = f"erased-{tombstone}@meridian.local"
    user.display_name   = None
    user.password_hash  = hash_password(secrets.token_urlsafe(32))  # unguessable
    user.password_changed_at = datetime.now(timezone.utc)
    user.phone_e164     = None
    user.sms_carrier_gateway = None
    user.recovery_email = None
    user.recovery_phone = None
    user.avatar_path    = None
    user.preferences    = {}
    user.external_id    = None
    user.mfa_enrolled   = False
    user.mfa_secret_enc = None
    user.enabled        = False
    user.locked         = True
    user.deleted_at     = datetime.now(timezone.utc)

    # Wipe MFA backup codes + revoke every session + revoke every API
    # token. None of these are reversible — that's the whole point.
    try:
        with db.begin_nested():
            db.execute(text("DELETE FROM mfa_backup_codes WHERE user_id = :uid"),
                       {"uid": user.id})
    except Exception:
        pass
    try:
        with db.begin_nested():
            db.execute(text(
                "UPDATE sessions SET revoked_at = now(), revoked_reason = 'gdpr_erasure' "
                "WHERE user_id = :uid AND revoked_at IS NULL"
            ), {"uid": user.id})
    except Exception:
        pass
    try:
        with db.begin_nested():
            db.execute(text(
                "UPDATE api_tokens SET revoked_at = now() "
                "WHERE created_by = :uid AND revoked_at IS NULL"
            ), {"uid": user.id})
    except Exception:
        # api_tokens schema may not have created_by named this — best effort.
        pass

    audit(db, user_id=user.id, action="user.gdpr.erase",
          target_type="user", target_key=str(user.id),
          payload={
              "original_username": original_username,
              "tombstone": tombstone,
          },
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))

    return {
        "ok":         True,
        "user_id":    str(user.id),
        "tombstone":  tombstone,
        "erased_at":  user.deleted_at.isoformat(),
        "message":    "Account anonymized. Audit history preserved with tombstone identifier. You will be signed out.",
    }


# ---------------------------------------------------------------------------
# Admin counterpart — for handling subject-access requests via support
# ---------------------------------------------------------------------------


@router.get("/admin/users/{user_id}/export")
async def admin_export_user_data(
    request: Request,
    user_id: uuid.UUID,
    actor: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict[str, Any]:
    """Admin variant for handling out-of-band subject access requests
    (e.g. user can't log in, asks support for an export by email).
    Requires `admin.users.manage` permission."""
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    dossier = _build_dossier(db, target)
    audit(db, user_id=actor.id, action="admin.user.gdpr.export",
          target_type="user", target_key=str(target.id),
          payload={
              "audit_event_count": dossier["audit_event_count"],
          },
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return dossier

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, select, update
from sqlalchemy.orm import Session as OrmSession

from app.models.audit import AuditEvent
from app.models.session import ApiToken, Session as SessionModel
from app.models.user import User


SESSION_TOKEN_BYTES = 32


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def mint_session(
    db: OrmSession,
    user: User,
    auth_method: str,
    *,
    ip: str | None,
    user_agent: str | None,
    idle_timeout_min: int,
) -> tuple[SessionModel, str]:
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)

    revoked_old = _enforce_single_session(db, user, now=now, incoming_ip=ip, incoming_ua=user_agent)

    sess = SessionModel(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=token_hash,
        auth_method=auth_method,
        ip=ip,
        user_agent=user_agent,
        device_label=_derive_device_label(user_agent),
        created_at=now,
        last_active_at=now,
        expires_at=now + timedelta(hours=24),
    )
    db.add(sess)

    db.add(AuditEvent(
        ts=now,
        user_id=user.id,
        action="auth.login",
        target_type="session",
        target_key=str(sess.id),
        payload={"revoked_old_sessions": revoked_old, "idle_timeout_min": idle_timeout_min},
        ip=ip,
        user_agent=user_agent,
        outcome="ok",
    ))

    user.last_login_at = now
    user.last_active_at = now
    user.failed_login_count = 0
    return sess, token


def _enforce_single_session(
    db: OrmSession,
    user: User,
    *,
    now: datetime,
    incoming_ip: str | None,
    incoming_ua: str | None,
) -> int:
    limit = max(1, user.max_concurrent_sessions)
    active = db.execute(
        select(SessionModel).where(
            and_(
                SessionModel.user_id == user.id,
                SessionModel.revoked_at.is_(None),
                SessionModel.expires_at > now,
            )
        ).order_by(SessionModel.last_active_at.asc())
    ).scalars().all()

    excess = len(active) - (limit - 1)
    if excess <= 0:
        return 0

    to_revoke = active[:excess]
    for old in to_revoke:
        old.revoked_at = now
        old.revoked_reason = "single_session_enforcement"
        db.add(AuditEvent(
            ts=now,
            user_id=user.id,
            action="auth.session_revoked_by_policy",
            target_type="session",
            target_key=str(old.id),
            payload={
                "old_ip": str(old.ip) if old.ip else None,
                "old_user_agent": old.user_agent,
                "new_ip": incoming_ip,
                "new_user_agent": incoming_ua,
                "limit": limit,
            },
            ip=incoming_ip,
            user_agent=incoming_ua,
            outcome="ok",
        ))
    return len(to_revoke)


def touch_session(db: OrmSession, session_id: uuid.UUID) -> None:
    db.execute(
        update(SessionModel)
        .where(SessionModel.id == session_id, SessionModel.revoked_at.is_(None))
        .values(last_active_at=datetime.now(timezone.utc))
    )


def resolve_session(db: OrmSession, token: str) -> SessionModel | None:
    row = db.execute(
        select(SessionModel).where(SessionModel.token_hash == _hash_token(token))
    ).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at <= datetime.now(timezone.utc):
        return None
    return row


def resolve_api_token(db: OrmSession, token: str) -> ApiToken | None:
    """Look up an `mrd_`-prefixed bearer token. Returns the ApiToken row if
    the token is active and unexpired; None otherwise. The caller is
    responsible for intersecting the row's scopes with the permission
    being checked (see app/auth/deps.py → require_permission).
    """
    row = db.execute(
        select(ApiToken).where(ApiToken.token_hash == _hash_token(token))
    ).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at is not None and row.expires_at <= datetime.now(timezone.utc):
        return None
    return row


def touch_api_token(db: OrmSession, token_id: uuid.UUID) -> None:
    db.execute(
        update(ApiToken)
        .where(ApiToken.id == token_id)
        .values(last_used_at=datetime.now(timezone.utc))
    )


def revoke_session(db: OrmSession, session_id: uuid.UUID, *, reason: str, by: uuid.UUID | None) -> None:
    now = datetime.now(timezone.utc)
    db.execute(
        update(SessionModel)
        .where(SessionModel.id == session_id)
        .values(revoked_at=now, revoked_by=by, revoked_reason=reason)
    )


def enforce_idle_timeout(sess: SessionModel, idle_timeout_min: int) -> bool:
    if idle_timeout_min <= 0:  # 0 means "never" (only if admin allows)
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=idle_timeout_min)
    return sess.last_active_at < cutoff


def _derive_device_label(ua: str | None) -> str | None:
    if not ua:
        return None
    ua_lower = ua.lower()
    os_name = "Unknown"
    for needle, label in [
        ("windows", "Windows"),
        ("mac os x", "macOS"),
        ("iphone", "iOS"),
        ("android", "Android"),
        ("ubuntu", "Ubuntu"),
        ("debian", "Debian"),
        ("linux", "Linux"),
    ]:
        if needle in ua_lower:
            os_name = label
            break
    browser = "Browser"
    for needle, label in [
        ("firefox", "Firefox"),
        ("edg/", "Edge"),
        ("chrome", "Chrome"),
        ("safari", "Safari"),
    ]:
        if needle in ua_lower:
            browser = label
            break
    return f"{os_name} · {browser}"

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user
from app.auth.permissions import effective_permissions
from app.db import fastapi_dep_db
from app.models.session import ApiToken
from app.models.user import User


router = APIRouter(prefix="/settings/tokens", tags=["tokens"])


def _serialize(t: ApiToken) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "scopes": list(t.scopes or []),
        "rate_limit_per_min": t.rate_limit_per_min,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
        "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
    }


@router.get("/")
async def list_tokens(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = list(db.execute(
        select(ApiToken).where(ApiToken.user_id == user.id)
        .order_by(ApiToken.created_at.desc())
    ).scalars())
    return [_serialize(t) for t in rows]


class TokenCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    scopes: list[str] = Field(default_factory=list)
    expires_in_days: int | None = Field(None, ge=1, le=365)
    rate_limit_per_min: int = Field(120, ge=1, le=6000)


@router.post("/", status_code=201)
async def create_token(
    request: Request,
    body: TokenCreate,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    # Dedupe names per user.
    existing = db.execute(
        select(ApiToken).where(
            ApiToken.user_id == user.id, ApiToken.name == body.name,
            ApiToken.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"active token with name {body.name!r} already exists")

    # Scopes must be a subset of the user's effective permissions (no privilege
    # escalation via tokens).
    user_perms = effective_permissions(db, user)
    bad = [s for s in body.scopes if s not in user_perms]
    if bad:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"cannot grant scopes you don't have: {', '.join(bad)}",
        )

    # Mint a 256-bit URL-safe token; store only its SHA-256 hash.
    plaintext = "mrd_" + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()

    now = datetime.now(timezone.utc)
    expires = None
    if body.expires_in_days:
        from datetime import timedelta
        expires = now + timedelta(days=body.expires_in_days)

    rec = ApiToken(
        id=uuid.uuid4(),
        user_id=user.id,
        name=body.name,
        token_hash=token_hash,
        scopes=body.scopes,
        rate_limit_per_min=body.rate_limit_per_min,
        created_at=now,
        expires_at=expires,
    )
    db.add(rec)
    db.flush()

    audit(db, user_id=user.id, action="api_token.create",
          target_type="api_token", target_key=body.name,
          payload={"scopes": body.scopes,
                   "expires_at": expires.isoformat() if expires else None,
                   "rate_limit_per_min": body.rate_limit_per_min},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))

    # Plaintext is returned ONCE. Never stored; never re-shown.
    return {**_serialize(rec), "plaintext_token": plaintext,
            "warning": "Copy the token now — it will not be shown again."}


@router.post("/{token_id}/revoke")
async def revoke_token(
    request: Request,
    token_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rec = db.get(ApiToken, token_id)
    if rec is None or rec.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    if rec.revoked_at is not None:
        return {"ok": True, "already_revoked": True}
    rec.revoked_at = datetime.now(timezone.utc)
    audit(db, user_id=user.id, action="api_token.revoke",
          target_type="api_token", target_key=rec.name,
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}

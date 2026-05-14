"""Admin surface for lockout_appeals submitted via /ui/locked-out."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.user import User

router = APIRouter(prefix="/admin/lockout-appeals", tags=["admin-lockout-appeals"])


_VALID_STATUSES = ("open", "resolved", "spam")


@router.get("")
async def list_appeals(
    status_filter: str = "open",
    limit: int = 100,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if status_filter not in (*_VALID_STATUSES, "all"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"status_filter must be one of {_VALID_STATUSES} or 'all'"
        )
    limit = max(1, min(limit, 500))
    if status_filter == "all":
        rows = (
            db.execute(
                text(
                    "SELECT id, submitted_at, source_ip::text AS source_ip, user_agent, "
                    "       claimed_username, contact_email, context, status, "
                    "       resolved_at, resolved_by, resolved_note "
                    "  FROM lockout_appeals "
                    " ORDER BY submitted_at DESC LIMIT :n"
                ),
                {"n": limit},
            )
            .mappings()
            .all()
        )
    else:
        rows = (
            db.execute(
                text(
                    "SELECT id, submitted_at, source_ip::text AS source_ip, user_agent, "
                    "       claimed_username, contact_email, context, status, "
                    "       resolved_at, resolved_by, resolved_note "
                    "  FROM lockout_appeals WHERE status = :s "
                    " ORDER BY submitted_at DESC LIMIT :n"
                ),
                {"s": status_filter, "n": limit},
            )
            .mappings()
            .all()
        )
    return {"appeals": [dict(r) for r in rows]}


class AppealResolve(BaseModel):
    note: str | None = Field(None, max_length=1000)


@router.post("/{appeal_id}/resolve")
async def resolve_appeal(
    request: Request,
    appeal_id: uuid.UUID,
    body: AppealResolve,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    return _set_status(db, appeal_id, "resolved", body.note, user, request)


@router.post("/{appeal_id}/spam")
async def mark_spam(
    request: Request,
    appeal_id: uuid.UUID,
    body: AppealResolve,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    return _set_status(db, appeal_id, "spam", body.note, user, request)


def _set_status(db, appeal_id, new_status, note, user, request) -> dict:
    n = db.execute(
        text(
            "UPDATE lockout_appeals "
            "   SET status = :s, resolved_at = now(), resolved_by = :u, resolved_note = :n "
            " WHERE id = :id AND status = 'open'"
        ),
        {"s": new_status, "u": user.id, "n": note, "id": appeal_id},
    ).rowcount
    if n == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "appeal not found or already resolved")
    audit(
        db,
        user_id=user.id,
        action=f"admin.lockout_appeal.{new_status}",
        target_type="lockout_appeal",
        target_key=str(appeal_id),
        payload={"note": note},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"ok": True, "appeal_id": str(appeal_id), "status": new_status}

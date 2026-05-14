"""Admin CRUD for the `retention_rules` table — per-scope keep_days for
audit, monitor samples, device snapshots, etc. Surfaced on Global
Settings so super-admins can change retention without DB access.
"""
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


router = APIRouter(prefix="/admin/retention", tags=["admin-retention"])


@router.get("/rules")
async def list_rules(
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = db.execute(text("""
        SELECT id, scope, description, keep_days, keep_count, max_bytes,
               enabled, updated_at, updated_by
          FROM retention_rules
         ORDER BY scope
    """)).fetchall()
    return [{
        "id": str(r.id), "scope": r.scope, "description": r.description,
        "keep_days": r.keep_days, "keep_count": r.keep_count,
        "max_bytes": r.max_bytes, "enabled": r.enabled,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        "updated_by": str(r.updated_by) if r.updated_by else None,
    } for r in rows]


class RetentionPatch(BaseModel):
    keep_days: int | None = Field(None, ge=1, le=3650)
    keep_count: int | None = Field(None, ge=1, le=1_000_000)
    max_bytes: int | None = Field(None, ge=1024)
    enabled: bool | None = None


@router.patch("/rules/{rule_id}")
async def update_rule(
    request: Request, rule_id: uuid.UUID, body: RetentionPatch,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    row = db.execute(text("""
        SELECT scope, keep_days, keep_count, max_bytes, enabled
          FROM retention_rules WHERE id = :id
    """), {"id": rule_id}).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "retention rule not found")

    changed: dict = {}
    updates = {"id": rule_id, "by": user.id}
    sets = ["updated_by = :by"]
    for field, new_val in (
        ("keep_days", body.keep_days), ("keep_count", body.keep_count),
        ("max_bytes", body.max_bytes), ("enabled", body.enabled),
    ):
        if new_val is not None:
            sets.append(f"{field} = :{field}")
            updates[field] = new_val
            changed[field] = new_val
    if not changed:
        return {"ok": True, "changed": {}}

    db.execute(text(
        f"UPDATE retention_rules SET {', '.join(sets)} WHERE id = :id"
    ), updates)
    audit(db, user_id=user.id, action="admin.retention.update",
          target_type="retention_rule", target_key=row.scope,
          payload=changed, ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True, "changed": changed}

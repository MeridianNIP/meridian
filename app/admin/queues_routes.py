"""Admin surface for the queue / scheduler page."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from app.admin import queues as q
from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.user import User


router = APIRouter(prefix="/admin/queues", tags=["admin-queues"])


@router.get("")
async def get_snapshot(
    user: User = Depends(require_permission("admin.system.health.read")),
) -> dict:
    return q.snapshot()


class KickIn(BaseModel):
    handler: str = Field(..., min_length=1, max_length=256)


@router.post("/kick")
async def kick(
    request: Request,
    body: KickIn,
    user: User = Depends(require_permission("admin.system.repair")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Trigger a scheduled job on demand. Gated on the stronger
    `admin.system.repair` permission because firing a job out of cycle
    can have side effects (e.g. running the threat-feed refresh
    mid-business-hours when an admin meant to wait for the off-hours
    window)."""
    try:
        result = q.kick_now(body.handler)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    audit(db, user_id=user.id, action="admin.queues.kick",
          target_type="job", target_key=body.handler,
          payload={"task_id": result.get("task_id"), "task": result.get("task")},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return result

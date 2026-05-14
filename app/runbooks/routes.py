from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.runbook import Runbook, RunbookRun
from app.models.user import User
from app.runbooks.engine import run_runbook
from app.runbooks.tools import catalog as tool_catalog


router = APIRouter(prefix="/runbooks", tags=["runbooks"])


def _visible_to(user: User, rb: Runbook) -> bool:
    if user.role in ("admin", "super_admin"):
        return True
    if rb.owner_id == user.id:
        return True
    if rb.shared:
        return True
    return False


# ============================================================================
# Tools catalog (what the builder UI offers)
# ============================================================================
@router.get("/tools")
async def list_tools(
    user: User = Depends(require_permission("runbook.create")),
) -> list[dict]:
    return [
        {
            "key": t.key, "label": t.label, "category": t.category,
            "description": t.description,
            "required_permission": t.required_permission,
            "params": [
                {"name": p.name, "label": p.label, "type": p.type,
                 "default": p.default, "required": p.required,
                 "options": p.options, "hint": p.hint}
                for p in t.params
            ],
        }
        for t in tool_catalog()
    ]


# ============================================================================
# Runbook CRUD
# ============================================================================
class StepIn(BaseModel):
    tool: str = Field(..., min_length=1, max_length=64)
    params: dict = Field(default_factory=dict)
    label: str | None = Field(None, max_length=120)
    continue_on: list[str] | None = None


class RunbookIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str | None = Field(None, max_length=1024)
    steps: list[StepIn] = Field(default_factory=list)
    shared: bool = False
    enabled: bool = True


@router.get("")
async def list_runbooks(
    mine_only: bool = Query(False),
    user: User = Depends(require_permission("runbook.run")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    stmt = select(Runbook)
    if mine_only:
        stmt = stmt.where(Runbook.owner_id == user.id)
    elif user.role not in ("admin", "super_admin"):
        stmt = stmt.where(or_(Runbook.owner_id == user.id,
                              Runbook.shared.is_(True)))
    stmt = stmt.order_by(Runbook.name)
    rows = db.execute(stmt).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "owner_id": str(r.owner_id) if r.owner_id else None,
            "shared": r.shared,
            "enabled": r.enabled,
            "step_count": len(r.steps or []),
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rows
    ]


@router.get("/{runbook_id}")
async def get_runbook(
    runbook_id: uuid.UUID,
    user: User = Depends(require_permission("runbook.run")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rb = db.get(Runbook, runbook_id)
    if rb is None or not _visible_to(user, rb):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "runbook not found")
    return {
        "id": str(rb.id), "name": rb.name, "description": rb.description,
        "owner_id": str(rb.owner_id) if rb.owner_id else None,
        "shared": rb.shared, "enabled": rb.enabled,
        "steps": rb.steps or [],
        "created_at": rb.created_at.isoformat() if rb.created_at else None,
        "updated_at": rb.updated_at.isoformat() if rb.updated_at else None,
    }


@router.post("", status_code=201)
async def create_runbook(
    request: Request,
    body: RunbookIn,
    user: User = Depends(require_permission("runbook.create")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    now = datetime.now(timezone.utc)
    rb = Runbook(
        name=body.name, description=body.description,
        owner_id=user.id, shared=body.shared, enabled=body.enabled,
        steps=[s.model_dump() for s in body.steps],
        created_at=now, updated_at=now,
    )
    db.add(rb)
    db.commit()
    db.refresh(rb)
    audit(db, user_id=user.id, action="runbook.create",
          target_type="runbook", target_key=str(rb.id),
          payload={"name": rb.name, "step_count": len(rb.steps or []),
                   "shared": rb.shared},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"id": str(rb.id)}


class RunbookPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=120)
    description: str | None = Field(None, max_length=1024)
    steps: list[StepIn] | None = None
    shared: bool | None = None
    enabled: bool | None = None


@router.patch("/{runbook_id}")
async def update_runbook(
    request: Request,
    runbook_id: uuid.UUID,
    body: RunbookPatch,
    user: User = Depends(require_permission("runbook.create")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rb = db.get(Runbook, runbook_id)
    if rb is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "runbook not found")
    if rb.owner_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "only the owner or an admin may edit this runbook")
    changed: dict = {}
    if body.name is not None:
        rb.name = body.name; changed["name"] = body.name
    if body.description is not None:
        rb.description = body.description
    if body.shared is not None:
        if body.shared and "runbook.share" not in {p.key for p in user.permissions} and user.role not in ("admin", "super_admin"):  # type: ignore[attr-defined]
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "sharing requires runbook.share permission")
        rb.shared = body.shared; changed["shared"] = body.shared
    if body.enabled is not None:
        rb.enabled = body.enabled; changed["enabled"] = body.enabled
    if body.steps is not None:
        rb.steps = [s.model_dump() for s in body.steps]
        changed["step_count"] = len(rb.steps)
    rb.updated_at = datetime.now(timezone.utc)
    db.commit()
    audit(db, user_id=user.id, action="runbook.update",
          target_type="runbook", target_key=str(rb.id),
          payload=changed, ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}


@router.delete("/{runbook_id}", status_code=204, response_model=None)
async def delete_runbook(
    request: Request,
    runbook_id: uuid.UUID,
    user: User = Depends(require_permission("runbook.create")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    rb = db.get(Runbook, runbook_id)
    if rb is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "runbook not found")
    if rb.owner_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "only the owner or an admin may delete this runbook")
    name = rb.name
    db.delete(rb)
    db.commit()
    audit(db, user_id=user.id, action="runbook.delete",
          target_type="runbook", target_key=str(runbook_id),
          payload={"name": name},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))


# ============================================================================
# Execute + history
# ============================================================================
@router.post("/{runbook_id}/run")
async def run(
    request: Request,
    runbook_id: uuid.UUID,
    user: User = Depends(require_permission("runbook.run")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rb = db.get(Runbook, runbook_id)
    if rb is None or not _visible_to(user, rb):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "runbook not found")
    if not rb.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "runbook is disabled")

    result = await run_runbook(runbook=rb, user=user, db=db)
    db.commit()
    return result


@router.get("/{runbook_id}/runs")
async def list_runs(
    runbook_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(require_permission("runbook.run")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rb = db.get(Runbook, runbook_id)
    if rb is None or not _visible_to(user, rb):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "runbook not found")
    rows = db.execute(
        select(RunbookRun)
        .where(RunbookRun.runbook_id == runbook_id)
        .order_by(RunbookRun.started_at.desc())
        .limit(limit)
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "user_id": str(r.user_id),
            "started_at": r.started_at.isoformat(),
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "status": r.status,
            "step_count": len(r.step_results or []),
        }
        for r in rows
    ]


@router.get("/{runbook_id}/runs/{run_id}")
async def get_run(
    runbook_id: uuid.UUID,
    run_id: uuid.UUID,
    user: User = Depends(require_permission("runbook.run")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rb = db.get(Runbook, runbook_id)
    if rb is None or not _visible_to(user, rb):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "runbook not found")
    run = db.get(RunbookRun, run_id)
    if run is None or run.runbook_id != runbook_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    return {
        "id": str(run.id), "runbook_id": str(run.runbook_id),
        "user_id": str(run.user_id),
        "started_at": run.started_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "status": run.status,
        "step_results": run.step_results or [],
    }

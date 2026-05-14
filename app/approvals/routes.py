from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from app.approvals.engine import (
    ApprovalError,
    decide,
    list_mine,
    list_pending,
)
from app.approvals.engine import (
    cancel as eng_cancel,
)
from app.approvals.engine import (
    request as eng_request,
)
from app.auth.deps import current_user, require_permission
from app.db import fastapi_dep_db
from app.models.user import User

router = APIRouter(prefix="/approvals", tags=["approvals"])


class ApprovalOut(BaseModel):
    id: uuid.UUID
    requested_by: uuid.UUID
    approver_id: uuid.UUID | None
    action: str
    target_type: str | None
    target_key: str | None
    payload: dict
    justification: str
    state: str
    requested_at: str
    decided_at: str | None
    expires_at: str
    decision_note: str | None

    @classmethod
    def from_row(cls, a) -> ApprovalOut:
        return cls(
            id=a.id,
            requested_by=a.requested_by,
            approver_id=a.approver_id,
            action=a.action,
            target_type=a.target_type,
            target_key=a.target_key,
            payload=a.payload or {},
            justification=a.justification,
            state=a.state,
            requested_at=a.requested_at.isoformat(),
            decided_at=a.decided_at.isoformat() if a.decided_at else None,
            expires_at=a.expires_at.isoformat(),
            decision_note=a.decision_note,
        )


class RequestBody(BaseModel):
    action: str = Field(..., max_length=128)
    target_type: str | None = Field(None, max_length=64)
    target_key: str | None = Field(None, max_length=256)
    payload: dict = Field(default_factory=dict)
    justification: str = Field(..., min_length=10, max_length=2000)
    expires_hours: int = Field(24, ge=1, le=168)


@router.post("/request", response_model=ApprovalOut, status_code=201)
async def request_approval(
    body: RequestBody,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> ApprovalOut:
    try:
        a = eng_request(
            db,
            requester=user,
            action=body.action,
            target_type=body.target_type,
            target_key=body.target_key,
            payload=body.payload,
            justification=body.justification,
            expires_hours=body.expires_hours,
        )
    except ApprovalError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    db.flush()
    return ApprovalOut.from_row(a)


class DecisionBody(BaseModel):
    decision_note: str | None = Field(None, max_length=2000)


@router.post("/{approval_id}/approve", response_model=ApprovalOut)
async def approve(
    approval_id: uuid.UUID,
    body: DecisionBody,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> ApprovalOut:
    try:
        a = decide(
            db, approval_id=approval_id, approver=user, decision="approved", decision_note=body.decision_note
        )
    except ApprovalError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return ApprovalOut.from_row(a)


@router.post("/{approval_id}/deny", response_model=ApprovalOut)
async def deny(
    approval_id: uuid.UUID,
    body: DecisionBody,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> ApprovalOut:
    try:
        a = decide(
            db, approval_id=approval_id, approver=user, decision="denied", decision_note=body.decision_note
        )
    except ApprovalError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return ApprovalOut.from_row(a)


@router.post("/{approval_id}/cancel", response_model=ApprovalOut)
async def cancel(
    approval_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> ApprovalOut:
    try:
        a = eng_cancel(db, approval_id=approval_id, by=user)
    except ApprovalError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return ApprovalOut.from_row(a)


@router.get("/pending", response_model=list[ApprovalOut])
async def pending(
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[ApprovalOut]:
    return [ApprovalOut.from_row(a) for a in list_pending(db)]


@router.get("/mine", response_model=list[ApprovalOut])
async def mine(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[ApprovalOut]:
    return [ApprovalOut.from_row(a) for a in list_mine(db, user=user)]

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.orm import Session as OrmSession

from app.auth.deps import current_user
from app.db import fastapi_dep_db
from app.models.notification import NotifChannel, NotifDelivery
from app.models.user import User

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("/channels")
async def list_channels(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(
            select(NotifChannel)
            .where((NotifChannel.user_id == user.id) | (NotifChannel.user_id.is_(None)))
            .order_by(NotifChannel.kind, NotifChannel.description)
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": str(c.id),
            "kind": c.kind,
            "target": c.target,
            "description": c.description,
            "enabled": c.enabled,
            "user_scope": "global" if c.user_id is None else "personal",
        }
        for c in rows
    ]


@router.get("/inbox")
async def inbox(
    hours: int = 72,
    limit: int = 100,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    # Personal in-app deliveries: channels owned by the user OR global, of kind 'inapp'.
    cutoff = datetime.now(UTC) - timedelta(hours=max(1, min(hours, 720)))
    rows = db.execute(
        select(NotifDelivery, NotifChannel)
        .join(NotifChannel, NotifDelivery.channel_id == NotifChannel.id)
        .where(
            and_(
                NotifChannel.kind == "inapp",
                (NotifChannel.user_id == user.id) | (NotifChannel.user_id.is_(None)),
                NotifDelivery.sent_at >= cutoff,
            )
        )
        .order_by(NotifDelivery.sent_at.desc())
        .limit(max(1, min(limit, 500)))
    ).all()
    return [
        {
            "id": d.id,
            "channel_description": c.description,
            "subject": d.subject,
            "body": d.body,
            "payload": d.payload,
            "sent_at": d.sent_at.isoformat(),
            "status": d.status,
        }
        for (d, c) in rows
    ]


_ALLOWED_KINDS = {"email", "sms_twilio", "sms_gateway", "slack", "teams", "webhook", "inapp", "pagerduty"}


class ChannelIn(BaseModel):
    kind: str = Field(..., min_length=1, max_length=32)
    target: str = Field(..., min_length=1, max_length=512)
    description: str = Field(..., min_length=1, max_length=200)
    enabled: bool = True
    config: dict = Field(default_factory=dict)
    global_scope: bool = Field(
        False, description="If true, the channel is shared across all users; requires admin"
    )


@router.post("/channels", status_code=201)
async def create_channel(
    body: ChannelIn,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.kind not in _ALLOWED_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {sorted(_ALLOWED_KINDS)}")
    if body.global_scope and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only admins can create global channels")
    ch = NotifChannel(
        id=uuid.uuid4(),
        user_id=None if body.global_scope else user.id,
        kind=body.kind,
        target=body.target,
        description=body.description,
        enabled=body.enabled,
        config=body.config or {},
    )
    db.add(ch)
    db.flush()
    return {
        "id": str(ch.id),
        "kind": ch.kind,
        "target": ch.target,
        "description": ch.description,
        "enabled": ch.enabled,
        "user_scope": "global" if ch.user_id is None else "personal",
    }


class ChannelPatch(BaseModel):
    target: str | None = None
    description: str | None = None
    enabled: bool | None = None
    config: dict | None = None


@router.patch("/channels/{channel_id}")
async def update_channel(
    channel_id: uuid.UUID,
    body: ChannelPatch,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    ch = db.get(NotifChannel, channel_id)
    if ch is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    if ch.user_id is not None and ch.user_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your channel")
    if ch.user_id is None and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only admins can edit global channels")
    for field in ("target", "description", "enabled", "config"):
        val = getattr(body, field)
        if val is not None:
            setattr(ch, field, val)
    db.flush()
    return {"id": str(ch.id), "ok": True}


@router.delete("/channels/{channel_id}", status_code=204, response_model=None)
async def delete_channel(
    channel_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    ch = db.get(NotifChannel, channel_id)
    if ch is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    if ch.user_id is not None and ch.user_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your channel")
    if ch.user_id is None and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only admins can delete global channels")
    db.delete(ch)


@router.post("/channels/{channel_id}/test")
async def test_channel(
    channel_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    ch = db.get(NotifChannel, channel_id)
    if ch is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    if ch.user_id is not None and ch.user_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your channel")
    from app.notifications.dispatcher import dispatch

    results = dispatch(
        db,
        event_kind="test.ping",
        subject=f"Meridian test · {ch.kind}",
        body="This is a test notification from Meridian.",
        channel_ids=[ch.id],
    )
    return {"channel": ch.description, "results": results}

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, exists, func, or_, select, text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user
from app.db import fastapi_dep_db
from app.models.message import Message, MessageRead
from app.models.user import User, UserGroup


router = APIRouter(prefix="/messages", tags=["messages"])


def _serialize(db: OrmSession, m: Message, reader_id: uuid.UUID) -> dict:
    sender = db.get(User, m.from_user) if m.from_user else None
    read_at = db.execute(
        select(MessageRead.read_at).where(and_(
            MessageRead.message_id == m.id, MessageRead.user_id == reader_id,
        ))
    ).scalar_one_or_none()
    return {
        "id": str(m.id),
        "channel": m.channel,
        "from_user": str(m.from_user) if m.from_user else None,
        "from_username": sender.username if sender else None,
        "to_user": str(m.to_user) if m.to_user else None,
        "to_group": str(m.to_group) if m.to_group else None,
        "subject": m.subject,
        "body": m.body,
        "priority": m.priority,
        "created_at": m.created_at.isoformat(),
        "read_at": read_at.isoformat() if read_at else None,
        "attachments": [str(a) for a in (m.attachments or [])],
    }


@router.get("/inbox")
async def inbox(
    unread_only: bool = False,
    limit: int = 100,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    group_ids = db.execute(
        select(UserGroup.group_id).where(UserGroup.user_id == user.id)
    ).scalars().all()

    # Inbox = direct-to-me OR to any of my groups OR broadcasts.
    stmt = select(Message).where(or_(
        Message.to_user == user.id,
        Message.to_group.in_(list(group_ids)) if group_ids else Message.to_group.is_(None),
        Message.channel == "broadcast",
    )).order_by(Message.created_at.desc()).limit(max(1, min(limit, 500)))

    if unread_only:
        stmt = stmt.where(
            ~exists().where(and_(
                MessageRead.message_id == Message.id,
                MessageRead.user_id == user.id,
            ))
        )

    rows = list(db.execute(stmt).scalars())
    unread_count = db.execute(select(func.count()).select_from(Message).where(and_(
        or_(
            Message.to_user == user.id,
            Message.to_group.in_(list(group_ids)) if group_ids else Message.to_group.is_(None),
            Message.channel == "broadcast",
        ),
        ~exists().where(and_(
            MessageRead.message_id == Message.id,
            MessageRead.user_id == user.id,
        )),
    ))).scalar_one()
    return {
        "unread_count": int(unread_count),
        "messages": [_serialize(db, m, user.id) for m in rows],
    }


@router.get("/sent")
async def sent(
    limit: int = 50,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rows = list(db.execute(
        select(Message).where(Message.from_user == user.id)
        .order_by(Message.created_at.desc()).limit(max(1, min(limit, 500)))
    ).scalars())
    return {"messages": [_serialize(db, m, user.id) for m in rows]}


class SendBody(BaseModel):
    to_username: str | None = Field(None, max_length=128)
    to_group_id: uuid.UUID | None = None
    broadcast: bool = False
    subject: str | None = Field(None, max_length=256)
    body: str = Field(..., min_length=1, max_length=10000)
    priority: str = Field("normal", pattern="^(low|normal|high|urgent)$")


@router.post("/send", status_code=201)
async def send(
    request: Request,
    body: SendBody,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    # Exactly one recipient mode per message.
    modes = sum([bool(body.to_username), bool(body.to_group_id), bool(body.broadcast)])
    if modes != 1:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "provide exactly one of to_username, to_group_id, or broadcast=true",
        )
    if body.broadcast and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "broadcast requires admin role")

    to_user_id = None
    if body.to_username:
        target = db.execute(
            select(User).where(User.username == body.to_username)
        ).scalar_one_or_none()
        if target is None or not target.enabled or target.deleted_at is not None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "recipient not found")
        to_user_id = target.id

    channel = "broadcast" if body.broadcast else ("group" if body.to_group_id else "direct")
    m = Message(
        id=uuid.uuid4(),
        channel=channel,
        from_user=user.id,
        to_user=to_user_id,
        to_group=body.to_group_id,
        subject=body.subject,
        body=body.body,
        priority=body.priority,
        created_at=datetime.now(timezone.utc),
    )
    db.add(m)

    audit(db, user_id=user.id, action="message.send",
          target_type="message", target_key=str(m.id),
          payload={"channel": channel,
                   "to_user": body.to_username,
                   "to_group": str(body.to_group_id) if body.to_group_id else None,
                   "priority": body.priority,
                   "subject": body.subject,
                   "body_chars": len(body.body)},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    db.flush()
    return _serialize(db, m, user.id)


@router.post("/{message_id}/read")
async def mark_read(
    request: Request,
    message_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    m = db.get(Message, message_id)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message not found")
    # Sender always "sees" their sent; we only mark reads for recipients.
    db.execute(text("""
        INSERT INTO message_reads (message_id, user_id, read_at)
        VALUES (:m, :u, now())
        ON CONFLICT (message_id, user_id) DO NOTHING
    """), {"m": message_id, "u": user.id})
    return {"ok": True, "id": str(message_id)}


@router.delete("/{message_id}", status_code=204, response_model=None)
async def delete_message(
    request: Request,
    message_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    """Delete a message. Allowed only for the original sender or an admin."""
    m = db.get(Message, message_id)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message not found")
    if m.from_user != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only the sender or an admin can delete")
    db.execute(text("DELETE FROM message_reads WHERE message_id = :m"), {"m": message_id})
    db.delete(m)
    audit(db, user_id=user.id, action="message.delete",
          target_type="message", target_key=str(message_id),
          payload={"channel": m.channel, "subject": m.subject},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))


@router.post("/read-all")
async def mark_all_read(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    group_ids = db.execute(
        select(UserGroup.group_id).where(UserGroup.user_id == user.id)
    ).scalars().all()
    result = db.execute(text("""
        INSERT INTO message_reads (message_id, user_id, read_at)
        SELECT m.id, :u, now() FROM messages m
         WHERE (m.to_user = :u
                OR (m.to_group = ANY(:gids))
                OR m.channel = 'broadcast')
           AND NOT EXISTS (
             SELECT 1 FROM message_reads r
              WHERE r.message_id = m.id AND r.user_id = :u
           )
    """), {"u": user.id, "gids": list(group_ids)})
    return {"marked": result.rowcount or 0}

"""User-editable bookmark links. Two scopes:

- `global` — admin-managed, visible to everyone. Only admin / super_admin
  can create/edit/delete.
- `user` — personal, owned by the current user, visible only to them.

Each user can reorder their personal view (including global links) via
the `preferences.link_order` key on their own user row — an array of
link UUIDs in the order they want displayed.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import or_, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user
from app.db import fastapi_dep_db
from app.models.important_link import ImportantLink
from app.models.user import User


router = APIRouter(prefix="/links", tags=["links"])


def _ser(link: ImportantLink) -> dict:
    return {
        "id": str(link.id), "scope": link.scope,
        "user_id": str(link.user_id) if link.user_id else None,
        "name": link.name, "url": link.url,
        "description": link.description, "category": link.category,
        "sort_order": link.sort_order,
        "created_by": str(link.created_by) if link.created_by else None,
        "created_at": link.created_at.isoformat() if link.created_at else None,
    }


class LinkIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    url: str = Field(..., min_length=3, max_length=2048)
    description: str | None = Field(None, max_length=512)
    category: str | None = Field(None, max_length=64)
    scope: str = Field("user", pattern=r"^(user|global)$")
    sort_order: int = Field(100, ge=0, le=10_000)


class LinkPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=120)
    url: str | None = Field(None, min_length=3, max_length=2048)
    description: str | None = Field(None, max_length=512)
    category: str | None = Field(None, max_length=64)
    sort_order: int | None = Field(None, ge=0, le=10_000)


class ReorderIn(BaseModel):
    ordered_ids: list[uuid.UUID]


def _is_admin(user: User) -> bool:
    return user.role in ("admin", "super_admin")


@router.get("")
async def list_links(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Return all links visible to the caller: everyone's globals + this
    user's personals. Also returns the user's saved ordering so the
    client can render them in the preferred order."""
    rows = db.execute(
        select(ImportantLink).where(or_(
            ImportantLink.scope == "global",
            (ImportantLink.scope == "user") & (ImportantLink.user_id == user.id),
        )).order_by(ImportantLink.sort_order, ImportantLink.name)
    ).scalars().all()
    prefs = (user.preferences or {})
    return {
        "links": [_ser(l) for l in rows],
        "user_ordering": prefs.get("link_order") or [],
        "can_manage_global": _is_admin(user),
    }


@router.post("", status_code=201)
async def create_link(
    request: Request, body: LinkIn,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.scope == "global" and not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "only admin / super_admin can create global links")
    link = ImportantLink(
        scope=body.scope,
        user_id=None if body.scope == "global" else user.id,
        name=body.name, url=body.url,
        description=body.description, category=body.category,
        sort_order=body.sort_order,
        created_by=user.id,
    )
    db.add(link)
    db.flush()
    audit(db, user_id=user.id, action="link.create",
          target_type="important_link", target_key=link.name,
          payload={"scope": link.scope, "url": link.url},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"id": str(link.id)}


@router.patch("/{link_id}")
async def update_link(
    request: Request, link_id: uuid.UUID, body: LinkPatch,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    link = db.get(ImportantLink, link_id)
    if link is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "link not found")
    # Authorization: personal links only editable by their owner;
    # global links only editable by admin / super_admin.
    if link.scope == "global":
        if not _is_admin(user):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "admin role required to edit global link")
    else:
        if link.user_id != user.id:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "this personal link belongs to a different user")
    changed: dict[str, Any] = {}
    for field in ("name", "url", "description", "category", "sort_order"):
        v = getattr(body, field)
        if v is not None:
            setattr(link, field, v)
            changed[field] = v
    audit(db, user_id=user.id, action="link.update",
          target_type="important_link", target_key=link.name,
          payload=changed,
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True, "changed": changed}


@router.delete("/{link_id}", status_code=204, response_model=None)
async def delete_link(
    request: Request, link_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    link = db.get(ImportantLink, link_id)
    if link is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "link not found")
    if link.scope == "global":
        if not _is_admin(user):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "admin role required to delete global link")
    else:
        if link.user_id != user.id:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "this personal link belongs to a different user")
    name = link.name
    db.delete(link)
    audit(db, user_id=user.id, action="link.delete",
          target_type="important_link", target_key=name,
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))


@router.post("/reorder")
async def reorder(
    body: ReorderIn,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Persist the caller's preferred ordering of links (both global +
    personal). Stored as a JSONB list of UUIDs on `user.preferences.link_order`."""
    prefs = dict(user.preferences or {})
    prefs["link_order"] = [str(u) for u in body.ordered_ids]
    u = db.get(User, user.id)
    if u is not None:
        u.preferences = prefs
    return {"ok": True, "count": len(body.ordered_ids)}

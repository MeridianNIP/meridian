"""CRUD endpoints for DNS resolvers.

Ownership model:
- owner_user_id IS NULL   ->  house resolver. Visible to every user.
                              Editable only by admin/super_admin.
- owner_user_id = <uid>   ->  private resolver. Visible only to that user.
                              Editable only by that user (or admins).

Canonical public list stays inside the house list -- the seed is run by
schema.sql / the installer. Admins can delete or re-tag those rows same
as any other house entry; the in-code fallback in propagation.py only
kicks in if the table is completely empty.
"""

from __future__ import annotations

import ipaddress
from typing import Literal
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user
from app.db import fastapi_dep_db
from app.models.resolver import Resolver
from app.models.user import User

router = APIRouter(prefix="/dns/resolvers", tags=["dns"])

Scope = Literal["house", "mine"]


def _is_admin(user: User) -> bool:
    return user.role in ("admin", "super_admin")


class ResolverIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    ip: str = Field(..., min_length=1, max_length=64)
    region: str | None = Field(None, max_length=32)
    notes: str | None = Field(None, max_length=500)
    is_propagation_default: bool = False
    group_tag: str | None = Field(None, max_length=60)
    # Scope: "mine" = creates as personal (owner = caller); "house" = admin
    # only, creates as house (owner = NULL). Default "mine" to fail closed.
    scope: Scope = "mine"

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"not a valid IP address: {v}") from e
        return v


class ResolverOut(BaseModel):
    id: uuid.UUID
    name: str
    ip: str
    region: str | None
    notes: str | None
    is_propagation_default: bool
    group_tag: str | None
    scope: Scope  # derived from owner_user_id for the caller

    @classmethod
    def from_row(cls, r: Resolver, caller_id: uuid.UUID) -> ResolverOut:
        return cls(
            id=r.id,
            name=r.name,
            ip=str(r.ip),
            region=r.region,
            notes=r.notes,
            is_propagation_default=r.is_propagation_default,
            group_tag=r.group_tag,
            scope="house" if r.owner_user_id is None else "mine",
        )


@router.get("/groups", response_model=list[str])
def list_groups(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[str]:
    """All distinct group_tag values visible to the caller. Used by the
    Dig / Propagation / Hop Trace "Limit to group" selectors."""
    from sqlalchemy import distinct, func

    if _is_admin(user):
        q = select(distinct(Resolver.group_tag)).where(Resolver.group_tag.is_not(None))
    else:
        q = (
            select(distinct(Resolver.group_tag))
            .where(Resolver.group_tag.is_not(None))
            .where((Resolver.owner_user_id.is_(None)) | (Resolver.owner_user_id == user.id))
        )
    rows = db.execute(q.order_by(func.lower(Resolver.group_tag))).scalars().all()
    return [r for r in rows if r]


@router.get("", response_model=list[ResolverOut])
def list_resolvers(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[ResolverOut]:
    """House resolvers + the caller's own. Admins see everyone's as well, so
    they can debug user-reported issues."""
    from sqlalchemy import func

    if _is_admin(user):
        rows = db.execute(select(Resolver).order_by(func.lower(Resolver.name))).scalars().all()
    else:
        rows = (
            db.execute(
                select(Resolver)
                .where((Resolver.owner_user_id.is_(None)) | (Resolver.owner_user_id == user.id))
                .order_by(func.lower(Resolver.name))
            )
            .scalars()
            .all()
        )
    return [ResolverOut.from_row(r, user.id) for r in rows]


@router.post("", response_model=ResolverOut, status_code=201)
def create_resolver(
    request: Request,
    body: ResolverIn,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> ResolverOut:
    if body.scope == "house" and not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admins can create house resolvers.")
    if body.is_propagation_default and not _is_admin(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only admins can flag resolvers as propagation defaults."
        )
    owner = None if body.scope == "house" else user.id
    # Normalize group_tag -- trim, collapse whitespace, and snap the
    # casing to any existing group whose lowercased form matches. This
    # keeps "Corp DNS" and "corp dns" from living as two separate groups
    # due to typo casing.
    from sqlalchemy import func as _func

    group_raw = " ".join((body.group_tag or "").split()) or None
    if group_raw:
        existing_casing = db.execute(
            select(Resolver.group_tag).where(_func.lower(Resolver.group_tag) == group_raw.lower()).limit(1)
        ).scalar_one_or_none()
        if existing_casing:
            group_raw = existing_casing  # use canonical casing
    # Pre-check the uniqueness constraint so we surface a precise error
    # WITHOUT relying on a post-rollback query (after a failed flush the
    # session can be in an aborted state, making the second query
    # flakey). The uniqueness key is (owner, ip, group_tag).
    owner_cond = Resolver.owner_user_id.is_(None) if owner is None else Resolver.owner_user_id == owner
    existing = db.execute(
        select(Resolver).where(
            owner_cond,
            Resolver.ip == body.ip,
            Resolver.group_tag == group_raw if group_raw is not None else Resolver.group_tag.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        where = f" in group '{group_raw}'" if group_raw else " (ungrouped)"
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Error 409 (record already exists): a {body.scope} resolver with "
            f"IP {body.ip}{where} already exists as '{existing.name}'. "
            "Delete the existing entry, pick a different IP, or put this one "
            "in a different group.",
        )
    row = Resolver(
        owner_user_id=owner,
        name=body.name.strip(),
        ip=body.ip,
        region=(body.region or None),
        notes=(body.notes or None),
        is_propagation_default=body.is_propagation_default,
        group_tag=group_raw,
    )
    db.add(row)
    try:
        db.flush()
    except Exception as e:
        db.rollback()
        # Fallback for any other DB constraint that slipped past the
        # pre-check (e.g. two requests racing).
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Error 409 (conflict): could not create resolver. "
            "Another request may have created a duplicate simultaneously.",
        ) from e
    audit(
        db,
        user_id=user.id,
        action="dns.resolver.create",
        target_type="resolver",
        target_key=str(row.id),
        payload={"name": row.name, "ip": str(row.ip), "scope": body.scope},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return ResolverOut.from_row(row, user.id)


@router.put("/{rid}", response_model=ResolverOut)
def update_resolver(
    request: Request,
    rid: uuid.UUID,
    body: ResolverIn,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> ResolverOut:
    row = db.get(Resolver, rid)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resolver not found.")
    # Permission: owners edit their own; admins edit house + anyone's private.
    if row.owner_user_id is None:
        if not _is_admin(user):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admins can edit house resolvers.")
    elif row.owner_user_id != user.id and not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only edit your own resolvers.")
    if body.is_propagation_default and not _is_admin(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only admins can flag resolvers as propagation defaults."
        )
    # Scope changes are not supported via PUT (would require moving ownership).
    # Clients should delete + recreate if they want to change scope.
    row.name = body.name.strip()
    row.ip = body.ip
    row.region = body.region or None
    row.notes = body.notes or None
    row.is_propagation_default = body.is_propagation_default
    # Same canonical-casing snap as create: "Corp DNS" and "corp dns"
    # should not produce two separate groups.
    from sqlalchemy import func as _func

    g = " ".join((body.group_tag or "").split()) or None
    if g:
        existing_casing = db.execute(
            select(Resolver.group_tag)
            .where(_func.lower(Resolver.group_tag) == g.lower())
            .where(Resolver.id != rid)
            .limit(1)
        ).scalar_one_or_none()
        if existing_casing:
            g = existing_casing
    row.group_tag = g
    try:
        db.flush()
    except Exception as e:
        db.rollback()
        where = f" in group '{body.group_tag}'" if body.group_tag else " (ungrouped)"
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"A resolver with IP {body.ip}{where} already exists in this scope. "
            "Change the group, rename, or use a different IP.",
        ) from e
    audit(
        db,
        user_id=user.id,
        action="dns.resolver.update",
        target_type="resolver",
        target_key=str(row.id),
        payload={"name": row.name, "ip": str(row.ip)},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return ResolverOut.from_row(row, user.id)


@router.delete("/{rid}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_resolver(
    request: Request,
    rid: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> Response:
    row = db.get(Resolver, rid)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resolver not found.")
    if row.owner_user_id is None:
        if not _is_admin(user):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admins can delete house resolvers.")
    elif row.owner_user_id != user.id and not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only delete your own resolvers.")
    audit(
        db,
        user_id=user.id,
        action="dns.resolver.delete",
        target_type="resolver",
        target_key=str(rid),
        payload={"name": row.name, "ip": str(row.ip)},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.delete(row)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

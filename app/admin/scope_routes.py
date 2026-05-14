from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.config import get_settings
from app.db import fastapi_dep_db
from app.models.scope import ScopeRule
from app.models.user import User
from app.network.scope import classify, invalidate_cache


router = APIRouter(prefix="/admin/scope", tags=["admin-scope"])


_ALLOWED_KINDS = ("internal_extra", "external_extra", "deny")


def _validate_cidr(cidr: str) -> str:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid CIDR: {e}")
    return str(net)


@router.get("")
async def get_scope(
    user: User = Depends(require_permission("admin.scope.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rows = db.execute(
        select(ScopeRule).order_by(ScopeRule.kind, ScopeRule.cidr)
    ).scalars().all()
    return {
        "scope_of_use": get_settings().scope_of_use,
        "rules": [
            {
                "id": str(r.id),
                "kind": r.kind,
                "cidr": str(r.cidr),
                "note": r.note,
                "enabled": r.enabled,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in rows
        ],
    }


class RuleIn(BaseModel):
    kind: str = Field(..., pattern=r"^(internal_extra|external_extra|deny)$")
    cidr: str = Field(..., min_length=1, max_length=64)
    note: str | None = Field(None, max_length=512)
    enabled: bool = True


@router.post("", status_code=201)
async def create_rule(
    request: Request,
    body: RuleIn,
    user: User = Depends(require_permission("admin.scope.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    cidr = _validate_cidr(body.cidr)

    existing = db.execute(
        select(ScopeRule).where(ScopeRule.kind == body.kind, ScopeRule.cidr == cidr)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "rule already exists for this kind+cidr")

    now = datetime.now(timezone.utc)
    rule = ScopeRule(
        kind=body.kind, cidr=cidr, note=body.note,
        enabled=body.enabled, created_by=user.id,
        created_at=now, updated_at=now,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    invalidate_cache()

    audit(db, user_id=user.id, action="admin.scope.create",
          target_type="scope_rule", target_key=str(rule.id),
          payload={"kind": rule.kind, "cidr": cidr, "enabled": rule.enabled},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"id": str(rule.id)}


class RulePatch(BaseModel):
    note: str | None = Field(None, max_length=512)
    enabled: bool | None = None


@router.patch("/{rule_id}")
async def update_rule(
    request: Request,
    rule_id: uuid.UUID,
    body: RulePatch,
    user: User = Depends(require_permission("admin.scope.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rule = db.get(ScopeRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    changed: dict = {}
    if body.note is not None:
        rule.note = body.note
        changed["note"] = body.note
    if body.enabled is not None:
        rule.enabled = body.enabled
        changed["enabled"] = body.enabled
    db.commit()
    invalidate_cache()

    audit(db, user_id=user.id, action="admin.scope.update",
          target_type="scope_rule", target_key=str(rule.id),
          payload=changed,
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}


@router.delete("/{rule_id}", status_code=204, response_model=None)
async def delete_rule(
    request: Request,
    rule_id: uuid.UUID,
    user: User = Depends(require_permission("admin.scope.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    rule = db.get(ScopeRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    kind, cidr = rule.kind, str(rule.cidr)
    db.delete(rule)
    db.commit()
    invalidate_cache()

    audit(db, user_id=user.id, action="admin.scope.delete",
          target_type="scope_rule", target_key=str(rule_id),
          payload={"kind": kind, "cidr": cidr},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))


class TestIn(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)


@router.post("/test")
async def test_host(
    body: TestIn,
    user: User = Depends(require_permission("admin.scope.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    decision = classify(db, body.host)
    return {
        "host": body.host,
        "allowed": decision.allowed,
        "classification": decision.classification,
        "reason": decision.reason,
    }

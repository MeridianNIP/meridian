from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.directory.ldap_client import LDAPClient, client_for
from app.models.directory import DirectoryIntegration
from app.models.user import User


router = APIRouter(prefix="/directory", tags=["directory"])


def _integration_or_404(db: OrmSession, integration_id: uuid.UUID | None = None) -> DirectoryIntegration:
    if integration_id is not None:
        integ = db.get(DirectoryIntegration, integration_id)
    else:
        integ = db.execute(
            select(DirectoryIntegration).where(DirectoryIntegration.enabled.is_(True))
            .order_by(DirectoryIntegration.created_at.asc())
        ).scalars().first()
    if integ is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no enabled directory integration configured")
    return integ


@router.get("/integrations")
async def list_integrations(
    user: User = Depends(require_permission("ad.user.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = db.execute(select(DirectoryIntegration).order_by(DirectoryIntegration.name)).scalars().all()
    return [
        {
            "id": str(i.id),
            "kind": i.kind,
            "name": i.name,
            "enabled": i.enabled,
            "fqdn": i.fqdn,
            "primary_uri": i.primary_uri,
            "fallback_uri": i.fallback_uri,
            "base_dn": i.base_dn,
            "bind_account": i.bind_account,
            "auth_method": i.auth_method,
            "last_tested_at": i.last_tested_at.isoformat() if i.last_tested_at else None,
            "last_test_ok": i.last_test_ok,
            "last_test_error": i.last_test_error,
        }
        for i in rows
    ]


@router.post("/integrations/{integ_id}/test")
async def test_integration(
    request: Request,
    integ_id: uuid.UUID,
    user: User = Depends(require_permission("admin.feature_gates.edit")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = _integration_or_404(db, integ_id)
    client = client_for(db, integ)
    result = client.test()

    integ.last_tested_at = datetime.now(timezone.utc)
    integ.last_test_ok = result.ok
    integ.last_test_error = result.error

    audit(db, user_id=user.id, action="directory.test",
          target_type="directory", target_key=integ.name,
          payload={"ok": result.ok, "latency_ms": result.latency_ms, "error": result.error},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"),
          outcome="ok" if result.ok else "error")
    return {
        "ok": result.ok,
        "latency_ms": result.latency_ms,
        "server": result.server,
        "error": result.error,
    }


class UserSearchBody(BaseModel):
    query: str = Field(..., min_length=1, max_length=128)
    integration_id: uuid.UUID | None = None
    limit: int = Field(25, ge=1, le=100)


@router.post("/user/search")
async def search_user(
    request: Request,
    body: UserSearchBody,
    user: User = Depends(require_permission("ad.user.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = _integration_or_404(db, body.integration_id)
    client = client_for(db, integ)
    try:
        results = client.search_user(body.query, limit=body.limit)
    except Exception as e:  # noqa: BLE001
        audit(db, user_id=user.id, action="directory.user.search",
              target_type="directory", target_key=integ.name,
              payload={"query": body.query, "error": f"{type(e).__name__}: {e}"},
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"),
              outcome="error")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"LDAP error: {e}")

    audit(db, user_id=user.id, action="directory.user.search",
          target_type="directory", target_key=integ.name,
          payload={"query": body.query, "results": len(results)},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"integration": integ.name, "query": body.query, "count": len(results), "results": results}


class GetBody(BaseModel):
    dn: str = Field(..., min_length=1, max_length=1024)
    integration_id: uuid.UUID | None = None


@router.post("/user/get")
async def get_user(
    request: Request,
    body: GetBody,
    user: User = Depends(require_permission("ad.user.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = _integration_or_404(db, body.integration_id)
    client = client_for(db, integ)
    try:
        entry = client.get_user_by_dn(body.dn)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"LDAP error: {e}")
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "DN not found")

    audit(db, user_id=user.id, action="directory.user.get",
          target_type="directory_user", target_key=body.dn,
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"integration": integ.name, "entry": entry}


class GroupSearchBody(BaseModel):
    query: str = Field(..., min_length=1, max_length=128)
    integration_id: uuid.UUID | None = None
    limit: int = Field(25, ge=1, le=100)


@router.post("/group/search")
async def search_group(
    request: Request,
    body: GroupSearchBody,
    user: User = Depends(require_permission("ad.user.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = _integration_or_404(db, body.integration_id)
    client = client_for(db, integ)
    try:
        results = client.search_group(body.query, limit=body.limit)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"LDAP error: {e}")

    audit(db, user_id=user.id, action="directory.group.search",
          target_type="directory", target_key=integ.name,
          payload={"query": body.query, "results": len(results)},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"integration": integ.name, "query": body.query, "count": len(results), "results": results}


# --- AD write operations · each gated by a matching approved approval. ------
# The client first files an approval via /api/v1/approvals/request with
# `action` = the AD verb and `target_key` = the user's DN. A second admin
# approves it. Then the client calls the endpoint below with the DN, and the
# require_approval dependency verifies the signed-off approval exists.
from app.approvals.engine import ApprovalError
from app.auth.deps import require_approval
from app.directory.writes import (
    DirectoryWriteError, disable_account, reset_password, unlock_account,
)


class DnBody(BaseModel):
    dn: str = Field(..., min_length=1, max_length=1024)
    integration_id: uuid.UUID | None = None


@router.post("/user/unlock")
async def unlock_user(
    request: Request,
    body: DnBody,
    user: User = Depends(require_permission("ad.user.unlock")),
    approval=Depends(require_approval("ad.user.unlock")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = _integration_or_404(db, body.integration_id)
    client = client_for(db, integ)
    try:
        result = unlock_account(client, body.dn)
    except DirectoryWriteError as e:
        audit(db, user_id=user.id, action="ad.user.unlock",
              target_type="directory_user", target_key=body.dn,
              approval_id=approval.id,
              payload={"error": str(e)},
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"),
              outcome="error")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e))
    audit(db, user_id=user.id, action="ad.user.unlock",
          target_type="directory_user", target_key=body.dn,
          approval_id=approval.id, payload=result,
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    return result


class ResetBody(DnBody):
    new_password: str = Field(..., min_length=12, max_length=256)
    force_change_at_next_logon: bool = True


@router.post("/user/reset-password")
async def reset_user_password(
    request: Request,
    body: ResetBody,
    user: User = Depends(require_permission("ad.user.reset_password")),
    approval=Depends(require_approval("ad.user.reset_password")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = _integration_or_404(db, body.integration_id)
    client = client_for(db, integ)
    try:
        result = reset_password(client, body.dn, body.new_password,
                                force_change=body.force_change_at_next_logon)
    except DirectoryWriteError as e:
        audit(db, user_id=user.id, action="ad.user.reset_password",
              target_type="directory_user", target_key=body.dn,
              approval_id=approval.id,
              payload={"error": str(e), "force_change": body.force_change_at_next_logon},
              ip=client_ip(request), user_agent=request.headers.get("user-agent"),
              outcome="error")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e))
    # DO NOT log the plaintext password — `result` already excludes it.
    audit(db, user_id=user.id, action="ad.user.reset_password",
          target_type="directory_user", target_key=body.dn,
          approval_id=approval.id, payload=result,
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    return result


@router.post("/user/disable")
async def disable_user(
    request: Request,
    body: DnBody,
    user: User = Depends(require_permission("ad.user.disable")),
    approval=Depends(require_approval("ad.user.disable")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = _integration_or_404(db, body.integration_id)
    client = client_for(db, integ)
    try:
        result = disable_account(client, body.dn)
    except DirectoryWriteError as e:
        audit(db, user_id=user.id, action="ad.user.disable",
              target_type="directory_user", target_key=body.dn,
              approval_id=approval.id,
              payload={"error": str(e)},
              ip=client_ip(request), user_agent=request.headers.get("user-agent"),
              outcome="error")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e))
    audit(db, user_id=user.id, action="ad.user.disable",
          target_type="directory_user", target_key=body.dn,
          approval_id=approval.id, payload=result,
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    return result

"""Admin CRUD for external log-collector destinations.

Enforces the 3-destination cap at the service layer — keeps the schema
unconstrained so rotating a collector during a cutover doesn't require
deleting the old row first.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.log_shipping import LogShippingDestination
from app.models.user import User
from app.secrets_vault.vault import encrypt_field

router = APIRouter(prefix="/admin/log-shipping", tags=["admin-log-shipping"])


_ALLOWED_KINDS = (
    "syslog",
    "splunk_hec",
    "elastic",
    "cef",
    "graylog_gelf",
    "datadog",
    "sumo_logic",
    "aws_cloudwatch",
    "gcp_logging",
    "azure_sentinel",
)
_ALLOWED_TRANSPORTS = ("tcp", "udp", "tls", "https")
_MAX_DESTINATIONS = 3


def _store_secret(
    db: OrmSession,
    *,
    name: str,
    plaintext: str,
    created_by: uuid.UUID,
) -> uuid.UUID:
    blob = encrypt_field(plaintext.encode("utf-8"), domain=b"vault")
    nonce, body = blob[:12], blob[12:]
    now = datetime.now(UTC)
    row_id = uuid.uuid4()
    db.execute(
        text("""
        INSERT INTO secrets (id, name, category, ciphertext, nonce,
                             owner_scope, created_by, created_at, updated_at)
        VALUES (:id, :name, :category, :ct, :nonce, :scope, :by, :now, :now)
    """),
        {
            "id": row_id,
            "name": name,
            "category": "api_token",
            "ct": body,
            "nonce": nonce,
            "scope": "system",
            "by": created_by,
            "now": now,
        },
    )
    return row_id


def _delete_secret(db: OrmSession, secret_id: uuid.UUID | None) -> None:
    if secret_id is not None:
        db.execute(text("DELETE FROM secrets WHERE id = :id"), {"id": secret_id})


def _serialise(d: LogShippingDestination) -> dict:
    return {
        "id": str(d.id),
        "name": d.name,
        "kind": d.kind,
        "enabled": d.enabled,
        "endpoint": d.endpoint,
        "transport": d.transport,
        "facility": d.facility,
        "index_or_sourcetype": d.index_or_sourcetype,
        "has_secret": d.auth_secret_id is not None,
        "ca_cert_path": d.ca_cert_path,
        "event_filter": list(d.event_filter or []),
        "batch_size": d.batch_size,
        "flush_interval_s": d.flush_interval_s,
        "last_shipped_at": d.last_shipped_at.isoformat() if d.last_shipped_at else None,
        "last_cursor_ts": d.last_cursor_ts.isoformat() if d.last_cursor_ts else None,
        "last_error": d.last_error,
        "events_shipped_total": d.events_shipped_total,
    }


class DestIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    kind: str = Field(..., min_length=1, max_length=32)
    endpoint: str = Field(..., min_length=1, max_length=512)
    transport: str = Field("tcp", max_length=16)
    facility: str | None = Field(None, max_length=32)
    index_or_sourcetype: str | None = Field(None, max_length=64)
    auth_secret: str | None = Field(None, max_length=4096)
    ca_cert_path: str | None = Field(None, max_length=512)
    event_filter: list[str] = Field(default_factory=list)
    batch_size: int = Field(100, ge=1, le=5000)
    flush_interval_s: int = Field(10, ge=1, le=3600)
    enabled: bool = True


class DestPatch(BaseModel):
    enabled: bool | None = None
    endpoint: str | None = Field(None, max_length=512)
    transport: str | None = Field(None, max_length=16)
    facility: str | None = Field(None, max_length=32)
    index_or_sourcetype: str | None = Field(None, max_length=64)
    auth_secret: str | None = Field(None, max_length=4096)
    clear_auth_secret: bool = False
    ca_cert_path: str | None = Field(None, max_length=512)
    event_filter: list[str] | None = None
    batch_size: int | None = Field(None, ge=1, le=5000)
    flush_interval_s: int | None = Field(None, ge=1, le=3600)


@router.get("")
async def list_destinations(
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(select(LogShippingDestination).order_by(LogShippingDestination.created_at)).scalars().all()
    )
    return [_serialise(d) for d in rows]


@router.post("", status_code=201)
async def create_destination(
    request: Request,
    body: DestIn,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.kind not in _ALLOWED_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {_ALLOWED_KINDS}")
    if body.transport not in _ALLOWED_TRANSPORTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"transport must be one of {_ALLOWED_TRANSPORTS}")
    current = db.execute(select(LogShippingDestination)).scalars().all()
    if len(current) >= _MAX_DESTINATIONS:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"maximum of {_MAX_DESTINATIONS} destinations configured — " f"delete an existing one first.",
        )
    secret_id = None
    if body.auth_secret:
        secret_id = _store_secret(
            db, name=f"log-shipping:{body.name}", plaintext=body.auth_secret, created_by=user.id
        )
    dest = LogShippingDestination(
        name=body.name,
        kind=body.kind,
        enabled=body.enabled,
        endpoint=body.endpoint,
        transport=body.transport,
        facility=body.facility,
        index_or_sourcetype=body.index_or_sourcetype,
        auth_secret_id=secret_id,
        ca_cert_path=body.ca_cert_path,
        event_filter=list(body.event_filter or []),
        batch_size=body.batch_size,
        flush_interval_s=body.flush_interval_s,
    )
    db.add(dest)
    db.flush()
    audit(
        db,
        user_id=user.id,
        action="admin.log_shipping.create",
        target_type="log_shipping",
        target_key=dest.name,
        payload={"kind": dest.kind, "endpoint": dest.endpoint, "has_secret": secret_id is not None},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"id": str(dest.id)}


@router.patch("/{dest_id}")
async def update_destination(
    request: Request,
    dest_id: uuid.UUID,
    body: DestPatch,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    d = db.get(LogShippingDestination, dest_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "destination not found")
    changed: dict[str, Any] = {}
    for field in (
        "enabled",
        "endpoint",
        "transport",
        "facility",
        "index_or_sourcetype",
        "ca_cert_path",
        "batch_size",
        "flush_interval_s",
    ):
        v = getattr(body, field)
        if v is not None:
            if field == "transport" and v not in _ALLOWED_TRANSPORTS:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, f"transport must be one of {_ALLOWED_TRANSPORTS}"
                )
            setattr(d, field, v)
            changed[field] = v
    if body.event_filter is not None:
        d.event_filter = list(body.event_filter)
        changed["event_filter"] = list(body.event_filter)
    if body.clear_auth_secret:
        _delete_secret(db, d.auth_secret_id)
        d.auth_secret_id = None
        changed["auth_secret"] = "cleared"
    elif body.auth_secret:
        _delete_secret(db, d.auth_secret_id)
        d.auth_secret_id = _store_secret(
            db,
            name=f"log-shipping:{d.name}",
            plaintext=body.auth_secret,
            created_by=user.id,
        )
        changed["auth_secret"] = "rotated"
    audit(
        db,
        user_id=user.id,
        action="admin.log_shipping.update",
        target_type="log_shipping",
        target_key=d.name,
        payload=changed,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"ok": True, "changed": changed}


@router.delete("/{dest_id}", status_code=204, response_model=None)
async def delete_destination(
    request: Request,
    dest_id: uuid.UUID,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    d = db.get(LogShippingDestination, dest_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "destination not found")
    name = d.name
    _delete_secret(db, d.auth_secret_id)
    db.delete(d)
    audit(
        db,
        user_id=user.id,
        action="admin.log_shipping.delete",
        target_type="log_shipping",
        target_key=name,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/{dest_id}/test")
async def test_destination(
    dest_id: uuid.UUID,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Dispatch a single test event through the destination. Returns the
    transport adapter's result — ok + latency_ms, or error message."""
    d = db.get(LogShippingDestination, dest_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "destination not found")
    try:
        from app.logging.shipper import test_send

        result = test_send(db, d)
        return result
    except NotImplementedError as e:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(e))
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

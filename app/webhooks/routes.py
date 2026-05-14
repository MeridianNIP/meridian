from __future__ import annotations

from datetime import UTC, datetime
import json
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from app.admin.integrations_routes import _delete_secret, _store_secret
from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.user import User
from app.models.webhook import Webhook, WebhookDelivery
from app.webhooks.dispatcher import (
    EVENTS,
    record_inbound,
    verify_signature,
)

# Two separate routers: /admin/webhooks is admin-gated CRUD, /webhooks/inbound
# is a public receiver that authenticates via HMAC signature.
admin_router = APIRouter(prefix="/admin/webhooks", tags=["admin-webhooks"])
public_router = APIRouter(prefix="/webhooks", tags=["webhooks-public"])


def _secret_from_vault(db: OrmSession, secret_id) -> bytes | None:
    if secret_id is None:
        return None
    row = db.execute(text("SELECT ciphertext, nonce FROM secrets WHERE id = :id"), {"id": secret_id}).first()
    if row is None:
        return None
    from app.secrets_vault.vault import decrypt_field

    try:
        return decrypt_field(bytes(row.nonce) + bytes(row.ciphertext), domain=b"vault")
    except Exception:
        return None


# ============================================================================
# Admin CRUD
# ============================================================================
@admin_router.get("/events")
async def list_events(
    user: User = Depends(require_permission("admin.webhooks.manage")),
) -> list[dict]:
    return [{"key": k, "description": d} for k, d in EVENTS]


@admin_router.get("")
async def list_webhooks(
    direction: str | None = Query(None, pattern=r"^(inbound|outbound)$"),
    user: User = Depends(require_permission("admin.webhooks.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    stmt = select(Webhook).order_by(Webhook.direction, Webhook.name)
    if direction:
        stmt = stmt.where(Webhook.direction == direction)
    rows = db.execute(stmt).scalars().all()
    return [
        {
            "id": str(w.id),
            "direction": w.direction,
            "name": w.name,
            "description": w.description,
            "url": w.url,
            "events": list(w.events or []),
            "enabled": w.enabled,
            "has_secret": w.secret_id is not None,
            "created_at": w.created_at.isoformat() if w.created_at else None,
            "updated_at": w.updated_at.isoformat() if w.updated_at else None,
            "inbound_url": (f"/api/v1/webhooks/inbound/{w.id}" if w.direction == "inbound" else None),
        }
        for w in rows
    ]


class WebhookIn(BaseModel):
    direction: str = Field(..., pattern=r"^(inbound|outbound)$")
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field("", max_length=1024)
    url: str | None = Field(None, max_length=2048)
    events: list[str] = Field(default_factory=list)
    enabled: bool = True


@admin_router.post("", status_code=201)
async def create_webhook(
    request: Request,
    body: WebhookIn,
    user: User = Depends(require_permission("admin.webhooks.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.direction == "outbound" and not body.url:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "outbound webhooks require a url")

    # Generate a fresh HMAC signing secret. We show it to the admin ONCE on
    # create so they can paste it into the source system; after this we only
    # ever store it encrypted in the vault.
    raw_secret = secrets.token_urlsafe(32)
    secret_id = _store_secret(
        db,
        name=f"webhook:{body.name}",
        plaintext=raw_secret,
        category="token",
        owner_scope="system",
        created_by=user.id,
    )

    now = datetime.now(UTC)
    wh = Webhook(
        direction=body.direction,
        name=body.name,
        description=body.description,
        url=body.url,
        events=list(body.events),
        enabled=body.enabled,
        secret_id=secret_id,
        created_by=user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(wh)
    db.commit()
    db.refresh(wh)

    audit(
        db,
        user_id=user.id,
        action="admin.webhook.create",
        target_type="webhook",
        target_key=str(wh.id),
        payload={"direction": wh.direction, "name": wh.name, "events": list(wh.events or []), "url": wh.url},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    return {
        "id": str(wh.id),
        # Shown exactly once. The admin is expected to copy both fields now;
        # the secret cannot be retrieved again through the API.
        "signing_secret": raw_secret,
        "inbound_url": (f"/api/v1/webhooks/inbound/{wh.id}" if wh.direction == "inbound" else None),
    }


class WebhookPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=120)
    description: str | None = Field(None, max_length=1024)
    url: str | None = Field(None, max_length=2048)
    events: list[str] | None = None
    enabled: bool | None = None
    rotate_secret: bool = False


@admin_router.patch("/{webhook_id}")
async def update_webhook(
    request: Request,
    webhook_id: uuid.UUID,
    body: WebhookPatch,
    user: User = Depends(require_permission("admin.webhooks.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    wh = db.get(Webhook, webhook_id)
    if wh is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook not found")

    changed: dict = {}
    if body.name is not None:
        wh.name = body.name
        changed["name"] = body.name
    if body.description is not None:
        wh.description = body.description
    if body.url is not None:
        wh.url = body.url
        changed["url"] = body.url
    if body.events is not None:
        wh.events = list(body.events)
        changed["events"] = list(body.events)
    if body.enabled is not None:
        wh.enabled = body.enabled
        changed["enabled"] = body.enabled
    wh.updated_at = datetime.now(UTC)

    new_secret_plain: str | None = None
    if body.rotate_secret:
        _delete_secret(db, wh.secret_id)
        new_secret_plain = secrets.token_urlsafe(32)
        wh.secret_id = _store_secret(
            db,
            name=f"webhook:{wh.name}",
            plaintext=new_secret_plain,
            category="token",
            owner_scope="system",
            created_by=user.id,
        )
        changed["secret"] = "rotated"

    db.commit()
    audit(
        db,
        user_id=user.id,
        action="admin.webhook.update",
        target_type="webhook",
        target_key=str(wh.id),
        payload=changed,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    result: dict = {"ok": True}
    if new_secret_plain is not None:
        result["signing_secret"] = new_secret_plain
    return result


@admin_router.delete("/{webhook_id}", status_code=204, response_model=None)
async def delete_webhook(
    request: Request,
    webhook_id: uuid.UUID,
    user: User = Depends(require_permission("admin.webhooks.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    wh = db.get(Webhook, webhook_id)
    if wh is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook not found")
    name = wh.name
    _delete_secret(db, wh.secret_id)
    db.delete(wh)
    db.commit()
    audit(
        db,
        user_id=user.id,
        action="admin.webhook.delete",
        target_type="webhook",
        target_key=str(webhook_id),
        payload={"name": name},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


class TestSendIn(BaseModel):
    event: str = Field("meridian.test", max_length=64)
    subject: str = Field("Meridian webhook test", max_length=200)
    payload: dict = Field(default_factory=dict)


@admin_router.post("/{webhook_id}/test")
async def test_send(
    request: Request,
    webhook_id: uuid.UUID,
    body: TestSendIn,
    user: User = Depends(require_permission("admin.webhooks.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    wh = db.get(Webhook, webhook_id)
    if wh is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook not found")
    if wh.direction != "outbound":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "test send only applies to outbound webhooks")
    if not wh.url:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "webhook has no url")

    # Force-dispatch regardless of enabled flag + event subscription.
    import httpx

    from app.webhooks.dispatcher import sign_body

    envelope = {
        "event": body.event,
        "subject": body.subject,
        "body": "(test)",
        "payload": body.payload,
        "ts": datetime.now(UTC).isoformat(),
    }
    blob = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Meridian-NIP/1.0",
        "X-Meridian-Event": body.event,
        "X-Meridian-Test": "1",
    }
    secret = _secret_from_vault(db, wh.secret_id)
    if secret is not None:
        headers["X-Meridian-Signature"] = sign_body(secret, blob)

    now = datetime.now(UTC)
    d = WebhookDelivery(
        webhook_id=wh.id,
        direction="outbound",
        event=body.event,
        payload=envelope,
        status="deferred",
        ts=now,
        attempt=1,
    )
    try:
        r = httpx.post(wh.url, content=blob, headers=headers, timeout=10.0)
        d.http_status = r.status_code
        d.response = (r.text or "")[:500]
        d.status = "ok" if 200 <= r.status_code < 300 else "failed"
    except httpx.HTTPError as e:
        d.status = "failed"
        d.response = f"{type(e).__name__}: {e}"[:500]
    db.add(d)
    db.commit()
    audit(
        db,
        user_id=user.id,
        action="admin.webhook.test",
        target_type="webhook",
        target_key=str(wh.id),
        payload={
            "status": d.status,
            "http_status": d.http_status,
            "response_preview": (d.response or "")[:120],
        },
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        outcome="ok" if d.status == "ok" else "error",
    )
    return {
        "status": d.status,
        "http_status": d.http_status,
        "response": d.response,
    }


@admin_router.get("/{webhook_id}/deliveries")
async def list_deliveries(
    webhook_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=1000),
    user: User = Depends(require_permission("admin.webhooks.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(
            select(WebhookDelivery)
            .where(WebhookDelivery.webhook_id == webhook_id)
            .order_by(WebhookDelivery.ts.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": d.id,
            "direction": d.direction,
            "event": d.event,
            "status": d.status,
            "http_status": d.http_status,
            "response": d.response,
            "ts": d.ts.isoformat(),
            "attempt": d.attempt,
        }
        for d in rows
    ]


# ============================================================================
# Public inbound receiver
# ============================================================================
@public_router.post("/inbound/{webhook_id}", status_code=202)
async def inbound(
    webhook_id: uuid.UUID,
    request: Request,
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    wh = db.get(Webhook, webhook_id)
    if wh is None or wh.direction != "inbound" or not wh.enabled:
        # Don't reveal whether the ID exists or is just disabled.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")

    body_bytes = await request.body()
    secret = _secret_from_vault(db, wh.secret_id)
    if secret is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "webhook secret missing from vault")

    sig = request.headers.get("X-Meridian-Signature")
    if not verify_signature(secret, body_bytes, sig):
        record_inbound(
            db,
            webhook_id=wh.id,
            event=request.headers.get("X-Meridian-Event", "unknown"),
            payload={"error": "signature mismatch", "content_length": len(body_bytes)},
            http_status=401,
            status="failed",
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "signature verification failed")

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        record_inbound(
            db,
            webhook_id=wh.id,
            event=request.headers.get("X-Meridian-Event", "unknown"),
            payload={"error": "invalid json", "content_length": len(body_bytes)},
            http_status=400,
            status="failed",
        )
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body is not valid JSON")

    event = (payload.get("event") if isinstance(payload, dict) else None) or request.headers.get(
        "X-Meridian-Event", "inbound"
    )
    d = record_inbound(db, webhook_id=wh.id, event=event, payload=payload, http_status=202, status="ok")
    db.commit()
    return {"accepted": True, "delivery_id": d.id}

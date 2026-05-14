"""Outbound webhook dispatcher + inbound verifier."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import hmac
import json
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.models.webhook import Webhook, WebhookDelivery
from app.secrets_vault.vault import decrypt_field

# Known event keys that internal code can emit. Keeping these in one place so
# the UI can show a typed picker instead of a free-text field.
EVENTS: list[tuple[str, str]] = [
    ("monitor.incident.open", "A monitor transitioned to warn/down"),
    ("monitor.incident.close", "A monitor returned to ok"),
    ("cert.expiring", "A certificate is within its warning window"),
    ("cert.expired", "A certificate passed its not_after"),
    ("wizard.fail", "A wizard run ended with outcome=fail"),
    ("audit.high_risk", "A high-risk audit event was recorded"),
    ("license.warning", "License is near expiry or over-seat"),
    ("integrity.mismatch", "HMAC row-hash scan found a tampered row"),
    ("vuln.critical", "A new critical CVE finding was recorded"),
    ("device.config_changed", "A network device's running config changed since the last snapshot"),
    ("device.backup_failed", "A scheduled device backup could not reach the target"),
]


# ============================================================================
# Secret helpers — split nonce/body correctly when round-tripping through
# the secrets table.
# ============================================================================
def _load_secret(db: OrmSession, secret_id) -> bytes | None:
    if secret_id is None:
        return None
    row = db.execute(text("SELECT ciphertext, nonce FROM secrets WHERE id = :id"), {"id": secret_id}).first()
    if row is None:
        return None
    try:
        return decrypt_field(bytes(row.nonce) + bytes(row.ciphertext), domain=b"vault")
    except Exception:
        return None


def sign_body(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, body: bytes, header_value: str | None) -> bool:
    if not header_value or not header_value.startswith("sha256="):
        return False
    expected = sign_body(secret, body)
    # constant-time compare
    return hmac.compare_digest(expected, header_value)


# ============================================================================
# Outbound fan-out
# ============================================================================
def fanout(
    db: OrmSession,
    *,
    event: str,
    payload: dict[str, Any],
    subject: str = "",
    body: str = "",
) -> list[WebhookDelivery]:
    """POST envelope to every enabled outbound webhook subscribed to event.

    Always records a WebhookDelivery row per target, even on failure, so the
    admin UI can surface deferred / failed deliveries.

    Uses a synchronous httpx.Client rather than async — this runs inside Celery
    tasks which are themselves sync workers, and the typical fanout fits a
    handful of targets.
    """
    envelope = {
        "event": event,
        "subject": subject,
        "body": body,
        "payload": payload or {},
        "ts": datetime.now(UTC).isoformat(),
    }
    blob = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()

    subs = (
        db.execute(
            text("""
        SELECT id FROM webhooks
         WHERE direction = 'outbound'
           AND enabled
           AND :event = ANY(events)
    """),
            {"event": event},
        )
        .scalars()
        .all()
    )

    deliveries: list[WebhookDelivery] = []
    for wh_id in subs:
        wh = db.get(Webhook, wh_id)
        if wh is None or not wh.url:
            continue
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Meridian-NIP/1.0",
            "X-Meridian-Event": event,
        }
        secret = _load_secret(db, wh.secret_id)
        if secret is not None:
            headers["X-Meridian-Signature"] = sign_body(secret, blob)

        now = datetime.now(UTC)
        d = WebhookDelivery(
            webhook_id=wh.id,
            direction="outbound",
            event=event,
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
        deliveries.append(d)
    return deliveries


# ============================================================================
# Inbound record — called from the receiver route after HMAC verify
# ============================================================================
def record_inbound(
    db: OrmSession,
    *,
    webhook_id,
    event: str,
    payload: dict[str, Any],
    http_status: int = 200,
    status: str = "ok",
) -> WebhookDelivery:
    d = WebhookDelivery(
        webhook_id=webhook_id,
        direction="inbound",
        event=event,
        payload=payload,
        status=status,
        http_status=http_status,
        ts=datetime.now(UTC),
        attempt=1,
    )
    db.add(d)
    return d

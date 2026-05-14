from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session as OrmSession

from app.models.notification import NotifChannel, NotifDelivery


def _sign(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def send(
    db: OrmSession,
    *,
    channel: NotifChannel,
    subject: str,
    body: str,
    payload: dict[str, Any] | None = None,
) -> NotifDelivery:
    """Generic signed outbound webhook. Works for Slack, Teams, and custom sinks."""
    envelope = {
        "event": (payload or {}).get("event_kind") or "meridian.notification",
        "subject": subject,
        "body": body,
        "payload": payload or {},
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    body_bytes = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()

    headers = {"Content-Type": "application/json", "User-Agent": "Meridian-NIP/1.0"}

    # Pull HMAC secret from the vault for signature.
    if channel.secret_id is not None:
        from sqlalchemy import text
        from app.secrets_vault.vault import decrypt_field
        row = db.execute(text(
            "SELECT ciphertext, nonce FROM secrets WHERE id = :id"
        ), {"id": channel.secret_id}).first()
        if row is not None:
            try:
                secret = decrypt_field(bytes(row.nonce) + bytes(row.ciphertext),
                                       domain=b"vault")
                headers["X-Meridian-Signature"] = _sign(secret, body_bytes)
            except Exception:  # noqa: BLE001
                pass

    d = NotifDelivery(
        channel_id=channel.id, subject=subject, body=body, payload=payload or {},
        sent_at=datetime.now(timezone.utc), status="sent",
    )
    try:
        r = httpx.post(channel.target, content=body_bytes, headers=headers, timeout=10.0)
        if r.status_code >= 300:
            d.status = "failed"
            d.error = f"HTTP {r.status_code}: {r.text[:200]}"
    except httpx.HTTPError as e:
        d.status = "failed"
        d.error = f"{type(e).__name__}: {e}"
    db.add(d)
    return d

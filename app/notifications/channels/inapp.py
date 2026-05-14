from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session as OrmSession

from app.models.notification import NotifChannel, NotifDelivery


def send(
    db: OrmSession,
    *,
    channel: NotifChannel,
    subject: str,
    body: str,
    payload: dict[str, Any] | None = None,
) -> NotifDelivery:
    """In-app notifications are delivery-logged only — the UI reads the
    notif_deliveries table via /api/v1/notifications/inbox to surface them."""
    d = NotifDelivery(
        channel_id=channel.id,
        subject=subject,
        body=body,
        payload=payload or {},
        sent_at=datetime.now(timezone.utc),
        status="sent",
    )
    db.add(d)
    return d

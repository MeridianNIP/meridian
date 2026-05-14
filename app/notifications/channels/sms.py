"""SMS channel — Twilio backend.

Sends one SMS via Twilio's REST API. Credentials come from the channel's
own config (set in `/ui/admin/integrations`) for per-channel keys, or
fall back to env vars for a portal-wide default:

  TWILIO_ACCOUNT_SID   — your Twilio account SID
  TWILIO_AUTH_TOKEN    — your Twilio auth token
  TWILIO_FROM          — E.164 sender number provisioned in Twilio

If neither path provides credentials, delivery is recorded as `skipped`
with an explanation. The handler never raises so the dispatcher can
continue fanning out to other channels.

The channel `target` must be an E.164 number (e.g. +15555550100).
"""

from __future__ import annotations

from datetime import UTC, datetime
import os
from typing import Any

import httpx
from sqlalchemy.orm import Session as OrmSession

from app.models.notification import NotifChannel, NotifDelivery

_TWILIO_API = "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"


def send(
    db: OrmSession,
    *,
    channel: NotifChannel,
    subject: str,
    body: str,
    payload: dict[str, Any] | None = None,
) -> NotifDelivery:
    cfg = channel.config or {}
    sid = cfg.get("twilio_account_sid") or os.environ.get("TWILIO_ACCOUNT_SID")
    token = cfg.get("twilio_auth_token") or os.environ.get("TWILIO_AUTH_TOKEN")
    sender = cfg.get("twilio_from") or os.environ.get("TWILIO_FROM")

    d = NotifDelivery(
        channel_id=channel.id,
        subject=subject,
        body=body,
        payload=payload or {},
        sent_at=datetime.now(UTC),
        status="sent",
    )

    if not sid or not token or not sender:
        d.status = "skipped"
        d.error = (
            "twilio credentials not configured "
            "(channel config or TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_FROM env)"
        )
        db.add(d)
        return d

    target = (channel.target or "").strip()
    if not target.startswith("+"):
        d.status = "failed"
        d.error = f"target {target!r} is not E.164 (must start with +)"
        db.add(d)
        return d

    # SMS bodies are 160 chars per segment. Concat subject + body, truncate
    # to ~480 chars (3 segments) so a runaway message doesn't burn the bill.
    text = f"{subject}\n{body}" if subject else body
    text = text[:480]

    try:
        r = httpx.post(
            _TWILIO_API.format(sid=sid),
            auth=(sid, token),
            data={"From": sender, "To": target, "Body": text},
            timeout=10.0,
        )
        if r.status_code >= 300:
            d.status = "failed"
            d.error = f"twilio HTTP {r.status_code}: {r.text[:300]}"
        else:
            payload_out = r.json()
            d.payload = {
                **(d.payload or {}),
                "twilio_sid": payload_out.get("sid"),
                "twilio_status": payload_out.get("status"),
            }
    except httpx.HTTPError as e:
        d.status = "failed"
        d.error = f"{type(e).__name__}: {e}"
    except Exception as e:
        d.status = "failed"
        d.error = f"{type(e).__name__}: {e}"
    db.add(d)
    return d

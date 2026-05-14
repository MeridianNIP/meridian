from __future__ import annotations

from datetime import UTC
from typing import Any
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.models.notification import NotifChannel


# Channel handler map. New channel types register themselves here.
# Each handler takes (db, channel=..., subject=..., body=..., payload=...) and
# returns a NotifDelivery (status already set).
def _handler_for(kind: str):
    # Delayed imports avoid circular loading during app startup.
    if kind == "inapp":
        from app.notifications.channels import inapp

        return inapp.send
    if kind == "email":
        from app.notifications.channels import email

        return email.send
    if kind in ("sms_twilio", "sms"):
        from app.notifications.channels import sms

        return sms.send
    if kind == "sms_gateway":
        # SMS-via-carrier-email gateway (e.g. number@txt.att.net) — same
        # delivery as plain email, just to a carrier MX.
        from app.notifications.channels import email

        return email.send
    if kind in ("webhook", "slack", "teams"):
        from app.notifications.channels import webhook

        return webhook.send
    return None


def _synthesize_email_channel(address: str, *, label: str) -> NotifChannel:
    """Build an in-memory NotifChannel for a user's email field.

    The handler doesn't care that the row isn't persisted; it reads
    `channel.config`, `channel.target`, and `channel.secret_id`. We pull
    SMTP defaults from the same env/config keys an admin would set on a
    real channel; if those aren't configured, the channel will fail to
    send and report it back to the caller — same behavior as if the
    admin had configured an email channel with bad SMTP settings.
    """
    from datetime import datetime
    import os

    ch = NotifChannel(
        id=uuid.uuid4(),
        kind="email",
        name=f"<synthetic:{label}>",
        target=address,
        config={
            "smtp_host": os.environ.get("MERIDIAN_SMTP_HOST", "localhost"),
            "smtp_port": int(os.environ.get("MERIDIAN_SMTP_PORT", "587")),
            "use_tls": os.environ.get("MERIDIAN_SMTP_TLS", "true").lower() != "false",
            "from_addr": os.environ.get("MERIDIAN_SMTP_FROM", "meridian@localhost"),
            "username": os.environ.get("MERIDIAN_SMTP_USER"),
        },
        secret_id=None,
        enabled=True,
        user_id=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    return ch


def _synthesize_sms_channel(number: str, *, label: str) -> NotifChannel:
    """Same idea as _synthesize_email_channel but for SMS. Uses env-var
    Twilio credentials; the SMS handler falls back to `skipped` if they
    aren't configured, so this is a no-op when no provider is wired."""
    from datetime import datetime
    import os

    return NotifChannel(
        id=uuid.uuid4(),
        kind="sms_twilio",
        name=f"<synthetic-sms:{label}>",
        target=number,
        config={
            "twilio_account_sid": os.environ.get("TWILIO_ACCOUNT_SID"),
            "twilio_auth_token": os.environ.get("TWILIO_AUTH_TOKEN"),
            "twilio_from": os.environ.get("TWILIO_FROM"),
        },
        secret_id=None,
        enabled=True,
        user_id=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def dispatch(
    db: OrmSession,
    *,
    event_kind: str,
    subject: str,
    body: str,
    payload: dict[str, Any] | None = None,
    channel_ids: list[uuid.UUID] | None = None,
    user_id: uuid.UUID | None = None,
    include_global: bool = True,
) -> list[str]:
    """Fan out a notification to all matching channels.

    Priority: explicit channel_ids → user_id-owned channels → global (user_id IS NULL).

    Returns a list of delivery statuses (one per channel), so the caller can
    surface per-channel outcomes to the UI or to downstream observability.
    """
    q = select(NotifChannel).where(NotifChannel.enabled.is_(True))
    if channel_ids is not None and channel_ids:
        q = q.where(NotifChannel.id.in_(channel_ids))
    elif user_id is not None:
        if include_global:
            q = q.where((NotifChannel.user_id == user_id) | (NotifChannel.user_id.is_(None)))
        else:
            q = q.where(NotifChannel.user_id == user_id)
    else:
        q = q.where(NotifChannel.user_id.is_(None))

    channels = list(db.execute(q).scalars())

    # Fallback path: if a specific user is being notified and they have no
    # configured email channel (own or global), synthesize an ephemeral one
    # from `users.email` and — if delivery to that fails or it's also empty
    # — `users.recovery_email`. This is the "the user's mailbox is the
    # channel of last resort" rule. Synthesized channels aren't persisted.
    synthesized = []
    if user_id is not None and channel_ids is None:
        from app.models.user import User

        target = db.get(User, user_id)
        if target is not None:
            if not any(ch.kind == "email" for ch in channels):
                if target.email:
                    synthesized.append(_synthesize_email_channel(target.email, label="primary"))
                if target.recovery_email and target.recovery_email != target.email:
                    synthesized.append(_synthesize_email_channel(target.recovery_email, label="recovery"))
            if not any(ch.kind in ("sms_twilio", "sms_gateway", "sms") for ch in channels):
                # phone_e164 is the user's daily SMS; recovery_phone is the
                # break-glass number used when the daily number is unreachable.
                if target.recovery_phone:
                    synthesized.append(_synthesize_sms_channel(target.recovery_phone, label="recovery"))
        channels.extend(synthesized)

    if not channels:
        return []

    merged_payload = {"event_kind": event_kind, **(payload or {})}
    out: list[str] = []
    for ch in channels:
        handler = _handler_for(ch.kind)
        if handler is None:
            out.append(f"{ch.kind}:unsupported")
            continue
        try:
            delivery = handler(db, channel=ch, subject=subject, body=body, payload=merged_payload)
            out.append(f"{ch.kind}:{delivery.status}")
        except Exception as e:
            out.append(f"{ch.kind}:error:{type(e).__name__}")
    return out

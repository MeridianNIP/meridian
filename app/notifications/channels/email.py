from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import aiosmtplib
from sqlalchemy.orm import Session as OrmSession

from app.models.notification import NotifChannel, NotifDelivery


def _build_message(*, from_addr: str, to_addr: str, subject: str, body: str) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))
    return msg


async def _async_send(
    *,
    host: str,
    port: int,
    use_tls: bool,
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    username: str | None,
    password: str | None,
) -> None:
    msg = _build_message(from_addr=from_addr, to_addr=to_addr, subject=subject, body=body)
    async with aiosmtplib.SMTP(hostname=host, port=port, use_tls=use_tls) as smtp:
        if username and password:
            await smtp.login(username, password)
        await smtp.send_message(msg)


def send(
    db: OrmSession,
    *,
    channel: NotifChannel,
    subject: str,
    body: str,
    payload: dict[str, Any] | None = None,
) -> NotifDelivery:
    cfg = channel.config or {}
    d = NotifDelivery(
        channel_id=channel.id,
        subject=subject,
        body=body,
        payload=payload or {},
        sent_at=datetime.now(UTC),
        status="sent",
    )

    # Credentials (if any) come from the secrets vault via channel.secret_id.
    password = None
    if channel.secret_id is not None:
        from sqlalchemy import text

        row = db.execute(
            text("SELECT ciphertext, nonce FROM secrets WHERE id = :id"), {"id": channel.secret_id}
        ).first()
        if row is not None:
            from app.secrets_vault.vault import decrypt_field

            try:
                password = decrypt_field(bytes(row.nonce) + bytes(row.ciphertext), domain=b"vault").decode()
            except Exception as e:
                d.status = "failed"
                d.error = f"secret decrypt failed: {e}"
                db.add(d)
                return d

    try:
        asyncio.run(
            _async_send(
                host=cfg.get("smtp_host", "localhost"),
                port=int(cfg.get("smtp_port", 587)),
                use_tls=bool(cfg.get("use_tls", True)),
                from_addr=cfg.get("from_addr", "meridian@localhost"),
                to_addr=channel.target,
                subject=subject,
                body=body,
                username=cfg.get("username"),
                password=password,
            )
        )
    except Exception as e:
        d.status = "failed"
        d.error = f"{type(e).__name__}: {e}"
    db.add(d)
    return d

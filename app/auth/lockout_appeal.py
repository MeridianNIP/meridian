"""Public /ui/locked-out form + POST /api/v1/auth/lockout-appeal.

The page is reachable without authentication so a user who can no longer
get past the login wall (forgotten MFA + no recovery email, account
locked, fail2ban-banned, etc.) has a path to ask an admin for help.

This is NOT a self-service unlock. The handler records the appeal,
optionally notifies the admin alias, and trusts the admin to follow up
out-of-band.

**Rate limit**: 1 submission per source IP per hour, enforced via a
small in-process counter (no extra dependency). Anyone who can reach
the page can submit *something*; the rate limit prevents flooding the
admin's inbox.

**Caveat**: if the source IP is fail2banned with an all-ports action,
they cannot reach the appeal page at all. The portal exposes this as a
documented gap in `docs/admin/lockout-recovery.md` — full mitigation
requires switching the relevant jails away from `iptables-allports`,
which is an operator-level decision.
"""

from __future__ import annotations

from collections import deque
from threading import Lock
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip
from app.db import fastapi_dep_db

router = APIRouter(prefix="/auth", tags=["auth-lockout-appeal"])


_RATE_WINDOW_S = 3600
_RATE_LIMIT_BY_IP: dict[str, deque[float]] = {}
_RATE_LOCK = Lock()


def _check_rate(ip: str) -> bool:
    now = time.monotonic()
    with _RATE_LOCK:
        dq = _RATE_LIMIT_BY_IP.setdefault(ip, deque())
        # Trim old entries
        while dq and (now - dq[0]) > _RATE_WINDOW_S:
            dq.popleft()
        if dq:
            return False
        dq.append(now)
        return True


class AppealIn(BaseModel):
    claimed_username: str | None = Field(None, max_length=64)
    contact_email: EmailStr | None = None
    context: str = Field(..., min_length=10, max_length=2000)


@router.post("/lockout-appeal")
async def submit_appeal(
    request: Request,
    body: AppealIn,
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    ip = client_ip(request) or "unknown"
    if not _check_rate(ip):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "An appeal from this address is already in flight. Try again in an hour.",
        )

    ua = (request.headers.get("user-agent") or "")[:512]
    appeal_id = db.execute(
        text("""
            INSERT INTO lockout_appeals
              (source_ip, user_agent, claimed_username, contact_email, context)
            VALUES (CAST(:ip AS INET), :ua, :u, :e, :c)
            RETURNING id
        """),
        {
            "ip": ip if ip != "unknown" else None,
            "ua": ua,
            "u": body.claimed_username or None,
            "e": body.contact_email or None,
            "c": body.context,
        },
    ).scalar_one()

    audit(
        db,
        user_id=None,
        action="auth.lockout_appeal.submitted",
        target_type="lockout_appeal",
        target_key=str(appeal_id),
        payload={"claimed_username": body.claimed_username, "contact_email": body.contact_email},
        ip=ip,
        user_agent=ua,
        outcome="ok",
    )

    # Best-effort admin notification. The notifications dispatcher already
    # knows how to fan out to email + in-portal inbox; we just emit an
    # event and let it route. Failure here is non-fatal.
    try:
        from app.notifications.dispatcher import dispatch

        ctx_preview = body.context[:300]
        dispatch(
            db,
            event_kind="auth.lockout_appeal",
            subject=f"[Meridian] lockout appeal from {ip}",
            body=(
                f"A user submitted a lockout appeal via /ui/locked-out.\n\n"
                f"  Appeal ID:        {appeal_id}\n"
                f"  Source IP:        {ip}\n"
                f"  Claimed username: {body.claimed_username or '(not provided)'}\n"
                f"  Contact email:    {body.contact_email or '(not provided)'}\n"
                f"  Context:\n    {ctx_preview}\n\n"
                f"Review at /ui/admin/appeals."
            ),
            payload={
                "appeal_id": str(appeal_id),
                "ip": ip,
                "claimed_username": body.claimed_username,
                "contact_email": body.contact_email,
            },
        )
    except Exception:
        # The audit row above is the durable record; dispatcher problems
        # shouldn't block submission.
        pass

    return {
        "ok": True,
        "appeal_id": str(appeal_id),
        "message": "Submitted. An admin will reach out via the contact channel you provided.",
    }

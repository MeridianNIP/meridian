"""Password max-age expiry notifications.

Fires reminders at 15 / 10 / 5 / 4 / 3 / 2 / 1 days before a password
expires. Each (user, threshold) pair fires at most once per password
cycle — a row in `password_expiry_notifications` acts as the dedup gate.

The policy's `max_age_days` lives on the branding row for now (0 =
disabled). When Global Settings ships a first-class `password_policy`
table this task picks it up from there instead.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.db import session_scope
from app.notifications.dispatcher import dispatch

_THRESHOLDS = (15, 10, 5, 4, 3, 2, 1)


def _password_max_age_days(db: OrmSession) -> int:
    """Read the portal's configured password max age. Falls back to 0
    (disabled) if no policy row is present."""
    row = db.execute(text("SELECT password_max_age_days FROM branding LIMIT 1")).first()
    if row is None or row[0] is None:
        return 0
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return 0


@celery_app.task(name="meridian.jobs.password.expiry_notify")
def expiry_notify() -> dict[str, Any]:
    sent = 0
    skipped = 0
    now = datetime.now(UTC)

    with session_scope() as db:
        max_age = _password_max_age_days(db)
        if max_age <= 0:
            return {"sent": 0, "skipped": 0, "reason": "password max-age disabled"}

        rows = db.execute(
            text("""
            SELECT id, username, email, password_changed_at, primary_auth
              FROM users
             WHERE enabled = TRUE
               AND deleted_at IS NULL
               AND primary_auth = 'credential'
               AND password_changed_at IS NOT NULL
        """)
        ).fetchall()

        for u in rows:
            expires_at = u.password_changed_at + timedelta(days=max_age)
            days_remaining = (expires_at - now).days
            if days_remaining < 0 or days_remaining > max(_THRESHOLDS):
                continue

            # Pick the *lowest* threshold that day falls within — so a
            # user at day 4.5 gets the 5-day reminder today, the 4-day
            # tomorrow, etc. This matches how humans read the countdown.
            threshold = next(
                (t for t in sorted(_THRESHOLDS) if days_remaining <= t),
                None,
            )
            if threshold is None:
                continue

            # Dedup: did we already fire this threshold in the current
            # password cycle?
            existing = db.execute(
                text("""
                SELECT 1 FROM password_expiry_notifications
                 WHERE user_id = :uid
                   AND days_threshold = :t
                   AND cycle_started_at = :cycle
                 LIMIT 1
            """),
                {
                    "uid": u.id,
                    "t": threshold,
                    "cycle": u.password_changed_at,
                },
            ).first()
            if existing:
                skipped += 1
                continue

            subject = f"[Meridian] your password expires in {days_remaining} day(s)"
            body = (
                f"Hi {u.username},\n\n"
                f"Your Meridian password expires in {days_remaining} day(s) — on "
                f"{expires_at.isoformat(timespec='minutes')}. Change it at any "
                f"time under Settings → Change password. Once the deadline "
                f"passes you'll be forced to rotate on next login.\n\n"
                f"-- Meridian NIP\n"
            )
            try:
                dispatch(
                    db,
                    event_kind="user.password_expiry_warning",
                    subject=subject,
                    body=body,
                    payload={
                        "user_id": str(u.id),
                        "days_remaining": days_remaining,
                        "expires_at": expires_at.isoformat(),
                        "threshold": threshold,
                    },
                    user_id=u.id,
                )
            except Exception:
                continue

            db.execute(
                text("""
                INSERT INTO password_expiry_notifications
                   (user_id, days_threshold, cycle_started_at, notified_at)
                VALUES (:uid, :t, :cycle, :now)
                ON CONFLICT DO NOTHING
            """),
                {"uid": u.id, "t": threshold, "cycle": u.password_changed_at, "now": now},
            )
            sent += 1

        if sent:
            audit(db, action="password.expiry_notify", payload={"sent": sent, "max_age_days": max_age})
    return {"sent": sent, "skipped": skipped}

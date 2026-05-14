from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session as OrmSession

from app.celery_app import celery_app
from app.db import session_scope
from app.models.monitor import Monitor, MonitorSample
from app.monitors.incidents import reconcile
from app.monitors.probes import dispatch


def _due_monitors(db: OrmSession, now: datetime) -> list[Monitor]:
    # Runtime clamp on interval_seconds — even if an admin edits the
    # monitors row directly and sets interval_seconds=1, the collector
    # will still treat it as the safety floor. The form validator at
    # /api/v1/monitors enforces the same range, but this layer is the
    # one the network actually sees.
    from app.safety.limits import MONITOR_INTERVAL_FLOOR_S, MONITOR_INTERVAL_CEILING_S, clamp
    stmt = select(Monitor).where(Monitor.enabled.is_(True))
    monitors = list(db.execute(stmt).scalars())
    return [
        m for m in monitors
        if m.last_sample_at is None
        or (now - m.last_sample_at) >= timedelta(seconds=(
            int(clamp(m.interval_seconds,
                      floor=MONITOR_INTERVAL_FLOOR_S,
                      ceiling=MONITOR_INTERVAL_CEILING_S)) - 1
        ))
    ]


async def _sample_one(db: OrmSession, m: Monitor, *, now: datetime) -> dict[str, Any]:
    result = await dispatch(
        m.kind, m.target,
        config=m.config or {},
        timeout_seconds=float(m.timeout_seconds),
    )
    db.add(MonitorSample(
        monitor_id=m.id,
        ts=now,
        status=result.status,
        value=result.value,
        detail={**result.detail, "error": result.error} if result.error else result.detail,
    ))

    prev_status = m.last_status
    m.last_sample_at = now
    m.last_status = result.status
    m.last_value = result.value
    if result.status in ("warn", "down"):
        m.consecutive_fails = (m.consecutive_fails or 0) + 1
    else:
        m.consecutive_fails = 0

    reconcile(
        db,
        monitor_id=m.id,
        new_status=result.status,
        previous_status=prev_status,
        consecutive_fails=m.consecutive_fails,
        detail=result.detail or {},
    )
    return {"id": str(m.id), "status": result.status, "value": result.value,
            "error": result.error}


@celery_app.task(name="meridian.jobs.monitor.sample_due")
def sample_due() -> dict[str, Any]:
    """Sample every monitor whose interval has elapsed.

    Called by Celery beat every ~20-30s. Probing is async and runs concurrently
    inside this one task to keep the scheduler's overhead low.
    """
    now = datetime.now(timezone.utc)
    with session_scope() as db:
        due = _due_monitors(db, now)
        if not due:
            return {"sampled": 0, "due": 0}

        async def _run() -> list[dict[str, Any]]:
            return await asyncio.gather(*[_sample_one(db, m, now=now) for m in due])

        results = asyncio.run(_run())
        return {"sampled": len(results), "results": results}


@celery_app.task(name="meridian.jobs.monitor.retention")
def retention() -> dict[str, Any]:
    """Purge raw samples older than the retention window (default 30 days)."""
    from sqlalchemy import text
    with session_scope() as db:
        keep_days = db.execute(
            text("SELECT keep_days FROM retention_rules WHERE scope = 'monitor_raw' AND enabled")
        ).scalar_one_or_none() or 30
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
        deleted = db.execute(
            text("DELETE FROM monitor_samples WHERE ts < :cutoff"),
            {"cutoff": cutoff},
        )
        return {"rows_deleted": deleted.rowcount or 0, "keep_days": keep_days}

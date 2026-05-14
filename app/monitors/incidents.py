from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.models.monitor import MonitorIncident


def reconcile(
    db: OrmSession,
    *,
    monitor_id: uuid.UUID,
    new_status: str,
    previous_status: str | None,
    consecutive_fails: int,
    detail: dict[str, Any],
    fail_threshold: int | None = None,
) -> None:
    """Open/close monitor_incidents + honor per-monitor notification knobs.

    Per-monitor knobs (read off the Monitor row):
      · fail_threshold       — N consecutive bad samples to open (default 3)
      · recovery_notify      — fire a "closed" notification? (default True)
      · quiet_hours_start/end— UTC hours where open/close notifications
                               are audited but NOT dispatched externally
      · renotify_interval_min— if >0 and incident is still open, fire
                               a re-notification every N minutes
    """
    from app.models.monitor import Monitor
    now = datetime.now(timezone.utc)
    m = db.get(Monitor, monitor_id)
    if m is None:
        return
    effective_threshold = fail_threshold if fail_threshold is not None else \
        (m.fail_threshold if m.fail_threshold else 3)

    open_incident = db.execute(
        select(MonitorIncident).where(
            and_(
                MonitorIncident.monitor_id == monitor_id,
                MonitorIncident.closed_at.is_(None),
            )
        ).order_by(MonitorIncident.opened_at.desc())
    ).scalar_one_or_none()

    is_bad = new_status in ("warn", "down")
    in_quiet = _in_quiet_hours(now, m.quiet_hours_start, m.quiet_hours_end)

    if is_bad and open_incident is None and consecutive_fails >= effective_threshold:
        inc = MonitorIncident(
            monitor_id=monitor_id,
            opened_at=now,
            severity=new_status,
            detail=detail,
        )
        db.add(inc)
        audit(db, action="monitor.incident.opened",
              target_type="monitor", target_key=str(monitor_id),
              payload={"severity": new_status, "consecutive_fails": consecutive_fails,
                       "quiet_hours_suppressed": in_quiet, "detail": detail},
              outcome="warn" if new_status == "warn" else "error")
        if not in_quiet:
            _notify(db, monitor_id=monitor_id, event="opened",
                    severity=new_status, detail=detail)

    elif not is_bad and open_incident is not None:
        open_incident.closed_at = now
        duration_s = int((now - open_incident.opened_at).total_seconds())
        audit(db, action="monitor.incident.closed",
              target_type="monitor", target_key=str(monitor_id),
              payload={"duration_s": duration_s,
                       "opened_at": open_incident.opened_at.isoformat(),
                       "recovery_notify_skipped": not m.recovery_notify,
                       "quiet_hours_suppressed": in_quiet})
        if m.recovery_notify and not in_quiet:
            _notify(db, monitor_id=monitor_id, event="closed",
                    severity="ok", detail={"duration_s": duration_s})

    # Re-notify: if we're still bad, an incident is already open, and
    # the user set a renotify interval — fire a reminder every N min
    # (tracked via the incident's detail.last_renotify_at).
    if is_bad and open_incident is not None and (m.renotify_interval_min or 0) > 0 \
       and not in_quiet:
        last_ts_s = (open_incident.detail or {}).get("last_renotify_at")
        last_ts = datetime.fromisoformat(last_ts_s) if last_ts_s else open_incident.opened_at
        if (now - last_ts).total_seconds() >= m.renotify_interval_min * 60:
            new_detail = dict(open_incident.detail or {})
            new_detail["last_renotify_at"] = now.isoformat()
            open_incident.detail = new_detail
            _notify(db, monitor_id=monitor_id, event="still_down",
                    severity=new_status, detail={"duration_s":
                        int((now - open_incident.opened_at).total_seconds())})


def _in_quiet_hours(now: datetime, start: int | None, end: int | None) -> bool:
    """UTC hour-based quiet window. Start == end (or either NULL) means
    no quiet hours. Supports ranges that cross midnight (e.g. 22→6)."""
    if start is None or end is None or start == end:
        return False
    h = now.hour
    if start < end:
        return start <= h < end
    # crosses midnight
    return h >= start or h < end


def _notify(db: OrmSession, *, monitor_id: uuid.UUID, event: str,
            severity: str, detail: dict[str, Any]) -> None:
    # Delayed import avoids a circular edge during worker boot.
    from app.models.monitor import Monitor
    from app.notifications.dispatcher import dispatch

    m = db.get(Monitor, monitor_id)
    if m is None:
        return
    channel_ids = list(m.notify_channels or []) or None
    subject = f"[Meridian] monitor {event}: {m.name}"
    body = (
        f"Monitor: {m.name}\n"
        f"Kind: {m.kind}\n"
        f"Target: {m.target}\n"
        f"Event: {event} (severity={severity})\n"
        f"Detail: {detail}\n"
    )
    dispatch(
        db,
        event_kind=f"monitor.{event}",
        subject=subject,
        body=body,
        payload={"monitor_id": str(monitor_id), "event": event,
                 "severity": severity, **(detail or {})},
        channel_ids=channel_ids,
        user_id=m.owner_id,
    )

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, desc, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user
from app.db import fastapi_dep_db
from app.models.monitor import Monitor, MonitorIncident, MonitorSample
from app.models.user import User


router = APIRouter(prefix="/monitors", tags=["monitors"])


_ALLOWED_KINDS = {"http", "https", "port_tcp", "ping_icmp", "cert_expiry", "dns_record"}


class MonitorIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    kind: str = Field(..., pattern="^[a-z_]+$")
    target: str = Field(..., min_length=1, max_length=256)
    interval_seconds: int = Field(60, ge=30, le=3600)
    timeout_seconds: int = Field(10, ge=2, le=60)
    enabled: bool = True
    config: dict = Field(default_factory=dict)
    notify_channels: list[uuid.UUID] = Field(default_factory=list)
    fail_threshold: int = Field(3, ge=1, le=20)
    recovery_notify: bool = True
    quiet_hours_start: int | None = Field(None, ge=0, le=23)
    quiet_hours_end: int | None = Field(None, ge=0, le=23)
    renotify_interval_min: int | None = Field(None, ge=0, le=1440)


class MonitorOut(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    target: str
    interval_seconds: int
    timeout_seconds: int
    enabled: bool
    last_status: str | None
    last_sample_at: datetime | None
    last_value: float | None
    consecutive_fails: int
    owner_id: uuid.UUID | None

    class Config:
        from_attributes = True


@router.get("/", response_model=list[MonitorOut])
async def list_monitors(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[Monitor]:
    # Everyone sees their own monitors + any with owner_id IS NULL (shared).
    rows = db.execute(
        select(Monitor).where(
            (Monitor.owner_id == user.id) | (Monitor.owner_id.is_(None))
        ).order_by(Monitor.name)
    ).scalars().all()
    return list(rows)


@router.post("/", response_model=MonitorOut, status_code=201)
async def create_monitor(
    request: Request,
    body: MonitorIn,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> Monitor:
    if body.kind not in _ALLOWED_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {sorted(_ALLOWED_KINDS)}")
    m = Monitor(
        id=uuid.uuid4(),
        owner_id=user.id,
        name=body.name,
        kind=body.kind,
        target=body.target,
        interval_seconds=body.interval_seconds,
        timeout_seconds=body.timeout_seconds,
        enabled=body.enabled,
        config=body.config,
        scope="both",
        notify_channels=list(body.notify_channels or []),
        fail_threshold=body.fail_threshold,
        recovery_notify=body.recovery_notify,
        quiet_hours_start=body.quiet_hours_start,
        quiet_hours_end=body.quiet_hours_end,
        renotify_interval_min=body.renotify_interval_min,
    )
    db.add(m)
    db.flush()
    audit(db, user_id=user.id, action="monitor.create",
          target_type="monitor", target_key=str(m.id),
          payload={"name": m.name, "kind": m.kind, "target": m.target},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))

    # Kick an initial probe so the operator sees a status/value row as
    # soon as the Create button returns, rather than waiting up to one
    # full Celery beat tick (~60 s) for the scheduler to hit it.
    # The handler is already running inside uvicorn's event loop, so we
    # await _sample_one directly — asyncio.run() would raise "cannot be
    # called from a running event loop" and the old except-pass was
    # swallowing that failure silently.
    if m.enabled:
        from datetime import datetime, timezone
        from app.monitors.collector import _sample_one
        try:
            await _sample_one(db, m, now=datetime.now(timezone.utc))
        except Exception as exc:  # noqa: BLE001
            # Probe-level failures (bad target, DNS miss, socket error)
            # still leave the monitor created — Celery beat will retry.
            # Surface the error for log visibility; the create succeeds.
            import logging
            logging.getLogger(__name__).warning(
                "initial monitor probe failed for %s: %s", m.id, exc)
    return m


class MonitorPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    kind: str | None = Field(None, pattern="^[a-z_]+$")
    target: str | None = Field(None, min_length=1, max_length=256)
    interval_seconds: int | None = Field(None, ge=30, le=3600)
    timeout_seconds: int | None = Field(None, ge=2, le=60)
    enabled: bool | None = None
    config: dict | None = None
    notify_channels: list[uuid.UUID] | None = None
    fail_threshold: int | None = Field(None, ge=1, le=20)
    recovery_notify: bool | None = None
    quiet_hours_start: int | None = Field(None, ge=0, le=23)
    quiet_hours_end: int | None = Field(None, ge=0, le=23)
    renotify_interval_min: int | None = Field(None, ge=0, le=1440)


@router.patch("/{monitor_id}", response_model=MonitorOut)
async def update_monitor(
    request: Request,
    monitor_id: uuid.UUID,
    body: MonitorPatch,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> Monitor:
    m = db.get(Monitor, monitor_id)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitor not found")
    if m.owner_id is not None and m.owner_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your monitor")
    changed: dict = {}
    for field in ("name", "kind", "target", "interval_seconds",
                  "timeout_seconds", "enabled", "config",
                  "fail_threshold", "recovery_notify",
                  "quiet_hours_start", "quiet_hours_end",
                  "renotify_interval_min"):
        val = getattr(body, field)
        if val is not None:
            if field == "kind" and val not in _ALLOWED_KINDS:
                raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                    f"kind must be one of {sorted(_ALLOWED_KINDS)}")
            setattr(m, field, val)
            changed[field] = val
    if body.notify_channels is not None:
        m.notify_channels = list(body.notify_channels)
        changed["notify_channels"] = len(m.notify_channels)
    audit(db, user_id=user.id, action="monitor.update",
          target_type="monitor", target_key=str(monitor_id),
          payload={"changed": sorted(changed.keys())},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    db.flush()
    return m


@router.delete("/{monitor_id}", status_code=204, response_model=None)
async def delete_monitor(
    request: Request,
    monitor_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    m = db.get(Monitor, monitor_id)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitor not found")
    if m.owner_id is not None and m.owner_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your monitor")
    db.delete(m)
    audit(db, user_id=user.id, action="monitor.delete",
          target_type="monitor", target_key=str(monitor_id),
          payload={"name": m.name},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))


@router.get("/{monitor_id}/samples")
async def recent_samples(
    monitor_id: uuid.UUID,
    hours: int = 1,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    m = db.get(Monitor, monitor_id)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitor not found")
    if m.owner_id is not None and m.owner_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your monitor")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, min(hours, 168)))
    rows = db.execute(
        select(MonitorSample).where(
            and_(MonitorSample.monitor_id == monitor_id, MonitorSample.ts >= cutoff)
        ).order_by(MonitorSample.ts.asc())
    ).scalars().all()
    return {
        "monitor_id": str(monitor_id),
        "samples": [
            {"ts": s.ts.isoformat(), "status": s.status, "value": s.value}
            for s in rows
        ],
    }


@router.get("/{monitor_id}/incidents")
async def recent_incidents(
    monitor_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rows = db.execute(
        select(MonitorIncident).where(MonitorIncident.monitor_id == monitor_id)
        .order_by(desc(MonitorIncident.opened_at)).limit(50)
    ).scalars().all()
    return {
        "incidents": [
            {
                "id": i.id,
                "opened_at": i.opened_at.isoformat(),
                "closed_at": i.closed_at.isoformat() if i.closed_at else None,
                "severity": i.severity,
                "detail": i.detail,
            }
            for i in rows
        ]
    }


@router.post("/{monitor_id}/toggle")
async def toggle(
    request: Request,
    monitor_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    m = db.get(Monitor, monitor_id)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitor not found")
    if m.owner_id is not None and m.owner_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your monitor")
    m.enabled = not m.enabled
    audit(db, user_id=user.id,
          action="monitor.enable" if m.enabled else "monitor.disable",
          target_type="monitor", target_key=str(monitor_id),
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"id": str(m.id), "enabled": m.enabled}

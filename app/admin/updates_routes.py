from __future__ import annotations

from pathlib import Path
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.updates import (
    UpdateHistoryEntry,
    UpdateSnapshot,
    VersionDrift,
    VersionManifest,
)
from app.models.user import User

router = APIRouter(prefix="/admin/updates", tags=["admin-updates"])


@router.get("/pending")
async def pending(
    user: User = Depends(require_permission("admin.updates.read")),
) -> dict:
    """Live `apt list --upgradable` via the celery task's helper (direct call here
    so the admin sees the result synchronously, not via a 3s poll)."""
    import subprocess

    from app.jobs.upgrade import _parse_upgradable

    try:
        subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=60, check=False)
        r = subprocess.run(
            ["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"apt not reachable: {e}")
    rows = _parse_upgradable(r.stdout or "")
    return {
        "total": len(rows),
        "security": sum(1 for row in rows if row.is_security),
        "rows": [
            {
                "package": row.package,
                "from_version": row.from_version,
                "to_version": row.to_version,
                "repo": row.repo,
                "is_security": row.is_security,
            }
            for row in rows
        ],
    }


@router.get("/history")
async def history(
    limit: int = Query(100, ge=1, le=1000),
    user: User = Depends(require_permission("admin.updates.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(select(UpdateHistoryEntry).order_by(UpdateHistoryEntry.applied_at.desc()).limit(limit))
        .scalars()
        .all()
    )
    return [
        {
            "id": str(h.id),
            "component": h.component,
            "from_version": h.from_version,
            "to_version": h.to_version,
            "applied_at": h.applied_at.isoformat(),
            "applied_by": str(h.applied_by) if h.applied_by else None,
            "snapshot_id": str(h.snapshot_id) if h.snapshot_id else None,
            "status": h.status,
            "notes": h.notes,
        }
        for h in rows
    ]


@router.get("/snapshots")
async def snapshots(
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(require_permission("admin.updates.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(select(UpdateSnapshot).order_by(UpdateSnapshot.created_at.desc()).limit(limit))
        .scalars()
        .all()
    )
    return [
        {
            "id": str(s.id),
            "reason": s.reason,
            "storage_path": s.storage_path,
            "size_bytes": s.size_bytes,
            "db_included": s.db_included,
            "config_included": s.config_included,
            "files_included": s.files_included,
            "created_at": s.created_at.isoformat(),
            "retention_until": s.retention_until.isoformat() if s.retention_until else None,
            "on_disk": Path(s.storage_path).is_file() if s.storage_path else False,
        }
        for s in rows
    ]


@router.get("/snapshots/{snapshot_id}/download")
async def download_snapshot(
    request: Request,
    snapshot_id: uuid.UUID,
    user: User = Depends(require_permission("admin.updates.snapshot")),
    db: OrmSession = Depends(fastapi_dep_db),
):
    snap = db.get(UpdateSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "snapshot not found")
    p = Path(snap.storage_path)
    if not p.is_file():
        raise HTTPException(status.HTTP_410_GONE, f"snapshot no longer on disk: {p}")
    audit(
        db,
        user_id=user.id,
        action="updates.snapshot.download",
        target_type="update_snapshot",
        target_key=str(snapshot_id),
        payload={"size_bytes": snap.size_bytes},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return FileResponse(p, media_type="application/zstd", filename=p.name)


@router.get("/drift")
async def drift(
    include_resolved: bool = Query(False),
    user: User = Depends(require_permission("admin.updates.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    stmt = select(VersionDrift).order_by(VersionDrift.detected_at.desc()).limit(500)
    if not include_resolved:
        stmt = stmt.where(VersionDrift.resolved_at.is_(None))
    rows = db.execute(stmt).scalars().all()
    return [
        {
            "id": d.id,
            "component_name": d.component_name,
            "category": d.category,
            "found_version": d.found_version,
            "expected_version": d.expected_version,
            "severity": d.severity,
            "detected_at": d.detected_at.isoformat(),
            "resolved_at": d.resolved_at.isoformat() if d.resolved_at else None,
            "note": d.note,
        }
        for d in rows
    ]


@router.get("/manifest")
async def manifest(
    user: User = Depends(require_permission("admin.updates.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(select(VersionManifest).order_by(VersionManifest.category, VersionManifest.component_name))
        .scalars()
        .all()
    )
    return [
        {
            "component_name": m.component_name,
            "category": m.category,
            "tested_on_debian": m.tested_on_debian,
            "pinned_version": m.pinned_version,
            "min_version": m.min_version,
            "max_version": m.max_version,
            "purpose": m.purpose,
            "release_channel": m.release_channel,
            "upstream_url": m.upstream_url,
            "changelog_url": m.changelog_url,
            "notes": m.notes,
            "pinned_at": m.pinned_at.isoformat(),
        }
        for m in rows
    ]


class SnapshotIn(BaseModel):
    reason: str = Field("manual", pattern=r"^(manual|pre-upgrade|scheduled)$")


@router.post("/snapshot", status_code=202)
async def trigger_snapshot(
    request: Request,
    body: SnapshotIn,
    user: User = Depends(require_permission("admin.updates.snapshot")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    from app.jobs.upgrade import pre_snapshot

    try:
        async_result = pre_snapshot.delay(reason=body.reason, created_by=str(user.id))
    except Exception as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"celery broker unavailable: {e}")
    audit(
        db,
        user_id=user.id,
        action="updates.snapshot.trigger",
        target_type="update_snapshot",
        target_key=async_result.id,
        payload={"reason": body.reason},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"task_id": async_result.id, "reason": body.reason}


@router.post("/drift/scan", status_code=202)
async def trigger_drift_scan(
    request: Request,
    user: User = Depends(require_permission("admin.updates.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    from app.jobs.upgrade import check_drift

    try:
        async_result = check_drift.delay()
    except Exception as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"celery broker unavailable: {e}")
    audit(
        db,
        user_id=user.id,
        action="updates.drift.trigger",
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"task_id": async_result.id}


# ============================================================================
# Update+Reboot controls — immediate + scheduled.
# ============================================================================
from datetime import UTC, datetime

from app.models.updates import SystemUpdateRun


def _serialise_run(r: SystemUpdateRun) -> dict:
    return {
        "id": str(r.id),
        "requested_by": str(r.requested_by) if r.requested_by else None,
        "scheduled_for": r.scheduled_for.isoformat() if r.scheduled_for else None,
        "reboot": r.reboot,
        "status": r.status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "exit_code": r.exit_code,
        "output_tail": r.output_tail,
        "reboot_required_after": r.reboot_required,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


class ApplyNowIn(BaseModel):
    reboot: bool = True


@router.post("/apply-now", status_code=202)
async def apply_now(
    request: Request,
    body: ApplyNowIn,
    user: User = Depends(require_permission("admin.updates.apply")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Kick an immediate apt-upgrade + optional reboot. Returns a run id
    the UI can poll via `GET /runs/{id}`."""
    now = datetime.now(UTC)
    run = SystemUpdateRun(
        id=uuid.uuid4(),
        requested_by=user.id,
        scheduled_for=None,
        reboot=body.reboot,
        status="pending",
        created_at=now,
        updated_at=now,
    )
    db.add(run)
    db.flush()
    audit(
        db,
        user_id=user.id,
        action="admin.update.apply_now",
        target_type="system_update_run",
        target_key=str(run.id),
        payload={"reboot": body.reboot},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()

    # Enqueue the worker task — the apt + reboot happens out-of-band.
    try:
        from app.jobs.upgrade import run_update

        run_update.delay(str(run.id))
    except Exception as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"celery broker unavailable: {e}")
    return {"run_id": str(run.id)}


class ScheduleIn(BaseModel):
    scheduled_for: datetime = Field(..., description="UTC datetime when the update + reboot should fire")
    reboot: bool = True


@router.post("/schedule", status_code=201)
async def create_schedule(
    request: Request,
    body: ScheduleIn,
    user: User = Depends(require_permission("admin.updates.apply")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    sched = body.scheduled_for
    if sched.tzinfo is None:
        sched = sched.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    if sched <= now:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "scheduled_for must be in the future")
    run = SystemUpdateRun(
        id=uuid.uuid4(),
        requested_by=user.id,
        scheduled_for=sched,
        reboot=body.reboot,
        status="pending",
        created_at=now,
        updated_at=now,
    )
    db.add(run)
    db.flush()
    audit(
        db,
        user_id=user.id,
        action="admin.update.scheduled",
        target_type="system_update_run",
        target_key=str(run.id),
        payload={"scheduled_for": sched.isoformat(), "reboot": body.reboot},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"id": str(run.id), "scheduled_for": sched.isoformat()}


@router.get("/runs")
async def list_runs(
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(require_permission("admin.updates.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(select(SystemUpdateRun).order_by(SystemUpdateRun.created_at.desc()).limit(limit))
        .scalars()
        .all()
    )
    return [_serialise_run(r) for r in rows]


@router.get("/runs/{run_id}")
async def get_run(
    run_id: uuid.UUID,
    user: User = Depends(require_permission("admin.updates.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    r = db.get(SystemUpdateRun, run_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    return _serialise_run(r)


@router.delete("/runs/{run_id}", status_code=200)
async def cancel_run(
    request: Request,
    run_id: uuid.UUID,
    user: User = Depends(require_permission("admin.updates.apply")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    r = db.get(SystemUpdateRun, run_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    if r.status != "pending":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"can't cancel a run in state {r.status!r}")
    r.status = "cancelled"
    r.cancelled_by = user.id
    r.completed_at = datetime.now(UTC)
    audit(
        db,
        user_id=user.id,
        action="admin.update.cancel",
        target_type="system_update_run",
        target_key=str(run_id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"ok": True}

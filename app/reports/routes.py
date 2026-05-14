"""Scheduled Reports HTTP surface — list / create / edit / delete
schedules, list runs, download artifact, trigger ad-hoc runs."""

from __future__ import annotations

from pathlib import Path
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user, require_permission
from app.db import fastapi_dep_db
from app.models.report import ReportRun, ReportSchedule
from app.models.user import User
from app.reports.cron import cadence_to_cron, next_fire_after
from app.reports.generators import REPORT_REGISTRY
from app.reports.runner import execute_report

router = APIRouter(prefix="/reports", tags=["reports"])


def _ser_schedule(s: ReportSchedule) -> dict:
    return {
        "id": str(s.id),
        "name": s.name,
        "report_type": s.report_type,
        "cadence": s.cadence,
        "cron_expression": s.cron_expression,
        "format": s.format,
        "delivery": s.delivery,
        "email_to": s.email_to,
        "filters": s.filters or {},
        "enabled": s.enabled,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "consecutive_failures": s.consecutive_failures,
        "owner_id": str(s.owner_id) if s.owner_id else None,
    }


def _ser_run(r: ReportRun) -> dict:
    return {
        "id": r.id,
        "schedule_id": str(r.schedule_id) if r.schedule_id else None,
        "report_type": r.report_type,
        "format": r.format,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "status": r.status,
        "artifact_bytes": r.artifact_bytes,
        "row_count": r.row_count,
        "detail": r.detail,
    }


class ScheduleIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    report_type: str
    cadence: str = Field("daily", pattern=r"^(daily|weekly|monthly|custom)$")
    time_of_day: int = Field(7, ge=0, le=23)
    day_of_week: int = Field(1, ge=0, le=6)
    day_of_month: int = Field(1, ge=1, le=28)
    custom_cron: str | None = None
    format: str = Field("csv", pattern=r"^(csv|html)$")
    delivery: str = Field("download", pattern=r"^(download|email)$")
    email_to: str | None = Field(None, max_length=1024)
    filters: dict = Field(default_factory=dict)
    enabled: bool = True


class SchedulePatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    cadence: str | None = Field(None, pattern=r"^(daily|weekly|monthly|custom)$")
    time_of_day: int | None = Field(None, ge=0, le=23)
    day_of_week: int | None = Field(None, ge=0, le=6)
    day_of_month: int | None = Field(None, ge=1, le=28)
    custom_cron: str | None = None
    format: str | None = Field(None, pattern=r"^(csv|html)$")
    delivery: str | None = Field(None, pattern=r"^(download|email)$")
    email_to: str | None = Field(None, max_length=1024)
    filters: dict | None = None
    enabled: bool | None = None


@router.get("/catalog")
async def catalog(user: User = Depends(current_user)) -> dict:
    """Return the registry of available report types for the form."""
    return {
        "reports": [
            {
                "key": k,
                "label": v["label"],
                "description": v["description"],
                "default_filters": v["default_filters"],
                "filter_schema": v["filter_schema"],
            }
            for k, v in REPORT_REGISTRY.items()
        ],
    }


@router.get("")
async def list_schedules(
    user: User = Depends(require_permission("reports.schedule")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rows = db.execute(select(ReportSchedule).order_by(ReportSchedule.name)).scalars().all()
    return {"schedules": [_ser_schedule(s) for s in rows]}


@router.post("", status_code=201)
async def create_schedule(
    request: Request,
    body: ScheduleIn,
    user: User = Depends(require_permission("reports.schedule")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.report_type not in REPORT_REGISTRY:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown report_type {body.report_type!r}")
    if body.delivery == "email" and not body.email_to:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "email_to is required when delivery=email")
    try:
        cron_expr = cadence_to_cron(
            body.cadence,
            time_of_day=body.time_of_day,
            day_of_week=body.day_of_week,
            day_of_month=body.day_of_month,
            custom=body.custom_cron,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    s = ReportSchedule(
        owner_id=user.id,
        name=body.name,
        report_type=body.report_type,
        cadence=body.cadence,
        cron_expression=cron_expr,
        format=body.format,
        delivery=body.delivery,
        email_to=body.email_to,
        filters=body.filters or {},
        enabled=body.enabled,
        next_run_at=next_fire_after(cron_expr),
    )
    db.add(s)
    db.flush()
    audit(
        db,
        user_id=user.id,
        action="report.schedule.create",
        target_type="report_schedule",
        target_key=s.name,
        payload={"report_type": s.report_type, "cadence": s.cadence},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _ser_schedule(s)


@router.patch("/{sid}")
async def update_schedule(
    request: Request,
    sid: uuid.UUID,
    body: SchedulePatch,
    user: User = Depends(require_permission("reports.schedule")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    s = db.get(ReportSchedule, sid)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")

    data = body.model_dump(exclude_none=True)
    for f in ("name", "format", "delivery", "email_to", "filters", "enabled"):
        if f in data:
            setattr(s, f, data[f])

    # Re-derive cron expression if any cadence-related field was touched.
    if any(k in data for k in ("cadence", "time_of_day", "day_of_week", "day_of_month", "custom_cron")):
        cadence = data.get("cadence", s.cadence)
        try:
            cron_expr = cadence_to_cron(
                cadence,
                time_of_day=data.get("time_of_day", 7),
                day_of_week=data.get("day_of_week", 1),
                day_of_month=data.get("day_of_month", 1),
                custom=data.get("custom_cron"),
            )
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
        s.cadence = cadence
        s.cron_expression = cron_expr
        s.next_run_at = next_fire_after(cron_expr)

    if s.delivery == "email" and not s.email_to:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "email_to is required when delivery=email")

    db.flush()
    audit(
        db,
        user_id=user.id,
        action="report.schedule.update",
        target_type="report_schedule",
        target_key=s.name,
        payload=data,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _ser_schedule(s)


@router.delete("/{sid}")
async def delete_schedule(
    request: Request,
    sid: uuid.UUID,
    user: User = Depends(require_permission("reports.schedule")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    s = db.get(ReportSchedule, sid)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    name = s.name
    db.delete(s)
    audit(
        db,
        user_id=user.id,
        action="report.schedule.delete",
        target_type="report_schedule",
        target_key=name,
        payload={},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"ok": True}


class RunNowIn(BaseModel):
    report_type: str
    format: str = Field("csv", pattern=r"^(csv|html)$")
    filters: dict = Field(default_factory=dict)
    schedule_id: uuid.UUID | None = None


@router.post("/run")
async def run_now(
    request: Request,
    body: RunNowIn,
    user: User = Depends(require_permission("reports.schedule")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.report_type not in REPORT_REGISTRY:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown report_type {body.report_type!r}")
    schedule = None
    if body.schedule_id is not None:
        schedule = db.get(ReportSchedule, body.schedule_id)
        if schedule is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    run = execute_report(
        db,
        report_type=body.report_type,
        fmt=body.format,
        filters=body.filters or {},
        schedule=schedule,
        triggered_by=user.id,
    )
    audit(
        db,
        user_id=user.id,
        action="report.run",
        target_type="report_run",
        target_key=body.report_type,
        payload={
            "status": run.status,
            "row_count": run.row_count,
            "schedule_id": str(schedule.id) if schedule else None,
        },
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _ser_run(run)


@router.get("/runs")
async def list_runs(
    schedule_id: uuid.UUID | None = None,
    limit: int = 50,
    user: User = Depends(require_permission("reports.schedule")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    limit = max(1, min(500, limit))
    q = select(ReportRun).order_by(desc(ReportRun.started_at)).limit(limit)
    if schedule_id is not None:
        q = q.where(ReportRun.schedule_id == schedule_id)
    rows = db.execute(q).scalars().all()
    return {"runs": [_ser_run(r) for r in rows]}


@router.get("/runs/{run_id}/download")
async def download_run(
    run_id: int,
    user: User = Depends(require_permission("reports.schedule")),
    db: OrmSession = Depends(fastapi_dep_db),
):
    r = db.get(ReportRun, run_id)
    if r is None or r.status != "success" or not r.artifact_path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "artifact not available")
    path = Path(r.artifact_path)
    if not path.is_file():
        raise HTTPException(status.HTTP_410_GONE, "artifact purged from disk")
    mime = "text/csv" if r.format == "csv" else "text/html"
    return FileResponse(path, media_type=mime, filename=path.name)

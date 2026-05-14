"""Report execution. Used both by the celery tick task (runs due
schedules) and by the ad-hoc `Run now` action from the UI."""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.models.report import ReportRun, ReportSchedule
from app.reports.cron import next_fire_after
from app.reports.generators import REPORT_REGISTRY, get_generator
from app.reports.renderers import render


def reports_dir() -> Path:
    d = Path(get_settings().data_root) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_slug(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:80]


def _artifact_name(report_type: str, fmt: str, run_id: int) -> str:
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"{_safe_slug(report_type)}-{stamp}-r{run_id}.{fmt}"


def execute_report(
    db: OrmSession,
    *,
    report_type: str,
    fmt: str,
    filters: dict,
    schedule: ReportSchedule | None = None,
    triggered_by: uuid.UUID | None = None,
) -> ReportRun:
    """Run a report synchronously, persist the artifact to disk, and
    return the persisted ReportRun row (committed)."""
    if report_type not in REPORT_REGISTRY:
        raise ValueError(f"Unknown report_type {report_type!r}")

    run = ReportRun(
        schedule_id=schedule.id if schedule else None,
        triggered_by=triggered_by,
        report_type=report_type,
        format=fmt,
        started_at=datetime.now(timezone.utc),
        status="running",
    )
    db.add(run)
    db.flush()

    try:
        generator = get_generator(report_type)
        headers, rows, summary = generator(db, filters or {})
        data, _mime = render(report_type, summary, headers, rows, fmt)

        fname = _artifact_name(report_type, fmt, run.id)
        path = reports_dir() / fname
        path.write_bytes(data)
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass

        run.artifact_path = str(path)
        run.artifact_bytes = len(data)
        run.row_count = len(rows)
        run.finished_at = datetime.now(timezone.utc)
        run.status = "success"
        run.detail = {
            "summary": {k: str(v) for k, v in summary.items()},
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    except Exception as e:  # noqa: BLE001
        run.finished_at = datetime.now(timezone.utc)
        run.status = "failed"
        run.detail = {"error": f"{type(e).__name__}: {e}"}

    if schedule is not None:
        schedule.last_run_at = run.finished_at or run.started_at
        schedule.next_run_at = next_fire_after(schedule.cron_expression)
        schedule.consecutive_failures = (
            0 if run.status == "success" else schedule.consecutive_failures + 1
        )

    db.flush()

    if run.status == "success" and schedule is not None and schedule.delivery == "email":
        try:
            _deliver_email(db, schedule=schedule, run=run)
        except Exception as e:  # noqa: BLE001
            run.detail = {**(run.detail or {}), "email_error": f"{type(e).__name__}: {e}"}

    return run


def _deliver_email(db: OrmSession, *, schedule: ReportSchedule, run: ReportRun) -> None:
    """Send the artifact as an email attachment to schedule.email_to. Uses
    the first active email notification channel for SMTP config — fails
    silently into run.detail if no channel is configured."""
    if not schedule.email_to or not run.artifact_path:
        return
    import asyncio
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    import aiosmtplib

    row = db.execute(text("""
        SELECT config FROM notif_channels
         WHERE kind = 'email' AND enabled = TRUE
         ORDER BY created_at LIMIT 1
    """)).first()
    if not row:
        raise RuntimeError("No enabled email notification channel configured.")
    cfg = row.config or {}

    body_path = Path(run.artifact_path)
    body_bytes = body_path.read_bytes()

    msg = MIMEMultipart()
    msg["From"] = cfg.get("from_addr", "meridian@localhost")
    msg["Subject"] = f"[Meridian report] {schedule.name}"
    to_list = [a.strip() for a in schedule.email_to.split(",") if a.strip()]
    msg["To"] = ", ".join(to_list)
    msg.attach(MIMEText(
        f"Attached: {schedule.name}\n"
        f"Report type: {schedule.report_type}\n"
        f"Generated: {run.started_at.isoformat() if run.started_at else ''}\n",
        "plain", "utf-8"))
    sub = "csv" if schedule.format == "csv" else "html"
    att = MIMEApplication(body_bytes, _subtype=sub)
    att.add_header("Content-Disposition", "attachment", filename=body_path.name)
    msg.attach(att)

    async def _send() -> None:
        async with aiosmtplib.SMTP(
            hostname=cfg.get("smtp_host", "localhost"),
            port=int(cfg.get("smtp_port", 587)),
            use_tls=bool(cfg.get("use_tls", True)),
        ) as smtp:
            user = cfg.get("username")
            pw = cfg.get("password")
            if user and pw:
                await smtp.login(user, pw)
            await smtp.sendmail(msg["From"], to_list, msg.as_string())

    asyncio.run(_send())


def claim_and_run_due(db: OrmSession) -> int:
    """Atomic-ish scan for due schedules — locks rows individually via
    SELECT FOR UPDATE SKIP LOCKED so celery workers can't double-fire
    the same schedule. Returns the number of schedules executed."""
    now = datetime.now(timezone.utc)
    executed = 0
    while True:
        sched = db.execute(text("""
            SELECT id FROM report_schedules
             WHERE enabled = TRUE
               AND (next_run_at IS NOT NULL AND next_run_at <= :now)
             ORDER BY next_run_at
             LIMIT 1
             FOR UPDATE SKIP LOCKED
        """), {"now": now}).first()
        if not sched:
            break
        row = db.get(ReportSchedule, sched.id)
        if row is None:
            break
        execute_report(
            db, report_type=row.report_type, fmt=row.format,
            filters=row.filters or {}, schedule=row,
        )
        db.commit()
        executed += 1
    return executed

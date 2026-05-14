from __future__ import annotations

from celery.schedules import crontab
from sqlalchemy import text

from app.celery_app import celery_app
from app.db import session_scope


_HANDLER_TO_TASK = {
    "meridian.jobs.license:verify":          "meridian.jobs.license.verify",
    "meridian.jobs.license:expiry_notify":   "meridian.jobs.license.expiry_notify",
    "meridian.jobs.integrity:scan":          "meridian.jobs.integrity.scan",
    "meridian.jobs.retention:audit_cleanup": "meridian.jobs.retention.audit_cleanup",
    "meridian.jobs.retention:query_cleanup": "meridian.jobs.retention.query_cleanup",
    "meridian.jobs.sessions:cleanup":        "meridian.jobs.sessions.cleanup",
    "meridian.jobs.monitor:sample_due":      "meridian.jobs.monitor.sample_due",
    "meridian.jobs.monitor:retention":       "meridian.jobs.monitor.retention",
    "meridian.jobs.cert:expiry_check":        "meridian.jobs.cert.expiry_check",
    "meridian.jobs.upgrade:fire_scheduled":   "meridian.jobs.upgrade.fire_scheduled",
    "meridian.jobs.log_shipping:flush":       "meridian.jobs.log_shipping.flush",
    "meridian.jobs.password:expiry_notify":   "meridian.jobs.password.expiry_notify",
    "meridian.jobs.reports:tick":             "meridian.jobs.reports.tick",
    "meridian.jobs.health:auto_repair":        "meridian.jobs.health.auto_repair",
}


def _cron_from_string(expr: str) -> crontab | None:
    try:
        m, h, dom, mon, dow = expr.split()
        return crontab(minute=m, hour=h, day_of_month=dom, month_of_year=mon, day_of_week=dow)
    except ValueError:
        return None


def load_schedule_from_db() -> dict[str, dict]:
    """Build a Celery beat schedule from the `jobs` table.

    Called by `celery beat` at startup via redbeat's initial-load hook.
    Jobs whose handler is not registered yet (stubs) are silently skipped.
    """
    schedule: dict[str, dict] = {}
    with session_scope() as db:
        rows = db.execute(text("""
            SELECT name, handler, cron_expression, enabled, kind
              FROM jobs
             WHERE enabled = TRUE AND cron_expression IS NOT NULL
        """)).fetchall()
    for name, handler, expr, enabled, kind in rows:
        task = _HANDLER_TO_TASK.get(handler)
        if task is None:
            continue
        cron = _cron_from_string(expr)
        if cron is None:
            continue
        schedule[name] = {"task": task, "schedule": cron}
    return schedule


# Celery beat reads this at startup.
celery_app.conf.beat_schedule = load_schedule_from_db()

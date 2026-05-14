"""Scheduled device backup + snapshot retention."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.db import session_scope
from app.devices.backup import backup_all as _backup_all


@celery_app.task(name="meridian.jobs.devices.backup_all")
def backup_all() -> dict[str, Any]:
    with session_scope() as db:
        return _backup_all(db, trigger="scheduled")


def _keep_days(db, scope: str, default: int) -> int:
    row = db.execute(
        text("SELECT keep_days FROM retention_rules WHERE scope = :s AND enabled"),
        {"s": scope},
    ).scalar_one_or_none()
    return row if row is not None else default


def _keep_count(db, scope: str, default: int) -> int:
    row = db.execute(
        text("SELECT keep_count FROM retention_rules WHERE scope = :s AND enabled"),
        {"s": scope},
    ).scalar_one_or_none()
    return row if row is not None else default


@celery_app.task(name="meridian.jobs.devices.retention")
def retention() -> dict[str, Any]:
    """Keep each device's newest `retain_snapshots_count` snapshots (default
    50 on a new device, editable in the admin UI) AND drop anything older
    than the global age cap from retention_rules.

    The per-device count wins — so a device configured with 200 and
    another with 10 get trimmed independently. The retention_rules
    'device_snapshots' row still enforces a global age ceiling.
    """
    with session_scope() as db:
        keep_days = _keep_days(db, "device_snapshots", 365)
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)

        # Delete by age (global cap).
        aged = db.execute(text("""
            DELETE FROM device_config_snapshots WHERE ts < :cutoff
        """), {"cutoff": cutoff})
        by_age = aged.rowcount or 0

        # Delete by per-device count — each device's retain_snapshots_count
        # column sets its own keep-N. Joining network_devices inline lets
        # us use a different N for every device in a single statement.
        trimmed = db.execute(text("""
            DELETE FROM device_config_snapshots
             WHERE id IN (
               SELECT id FROM (
                 SELECT s.id,
                        ROW_NUMBER() OVER
                          (PARTITION BY s.device_id ORDER BY s.ts DESC) AS rn,
                        d.retain_snapshots_count AS keep_n
                   FROM device_config_snapshots s
                   JOIN network_devices d ON d.id = s.device_id
               ) q
               WHERE q.rn > q.keep_n
             )
        """))
        by_count = trimmed.rowcount or 0

        audit(db, action="device.snapshots.retention",
              payload={"by_age": by_age, "by_count": by_count,
                       "keep_days": keep_days,
                       "count_source": "per-device retain_snapshots_count"})
        return {"rows_deleted_by_age": by_age,
                "rows_deleted_by_count": by_count,
                "keep_days": keep_days}

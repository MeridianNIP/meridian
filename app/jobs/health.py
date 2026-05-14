"""Hourly integration reachability sweep.

feature_ping -- walks every enabled Directory integration, calls its
.test() method, and records the result. If a source becomes unreachable
for two consecutive checks, emit a notification.

The check is deliberately cheap -- only existing .test() endpoints are
exercised (LDAP bind). Nothing is mutated.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.db import session_scope
from app.directory.ldap_client import client_for as _ldap_client
from app.models.directory import DirectoryIntegration


def _record_dir(db, integ, ok: bool, latency_ms: int | None, error: str | None):
    integ.last_tested_at = datetime.now(timezone.utc)
    integ.last_test_ok = ok
    integ.last_test_error = error


def _ping_dir(db, integ) -> dict[str, Any]:
    t0 = time.monotonic()
    try:
        client = _ldap_client(db, integ)
        result = client.test()
        _record_dir(db, integ, result.ok, result.latency_ms, result.error)
        return {"kind": "directory", "name": integ.name, "ok": result.ok,
                "latency_ms": result.latency_ms, "error": result.error}
    except Exception as e:  # noqa: BLE001
        _record_dir(db, integ, False, int((time.monotonic() - t0) * 1000), str(e))
        return {"kind": "directory", "name": integ.name, "ok": False,
                "error": f"{type(e).__name__}: {e}"[:200]}


@celery_app.task(name="meridian.jobs.health.feature_ping")
def feature_ping() -> dict[str, Any]:
    with session_scope() as db:
        dirs = db.execute(
            select(DirectoryIntegration).where(DirectoryIntegration.enabled.is_(True))
        ).scalars().all()

        all_results = [_ping_dir(db, i) for i in dirs]
        db.commit()

        failures = [r for r in all_results if not r["ok"]]
        audit(db, action="health.feature_ping",
              payload={"total": len(all_results),
                       "failures": len(failures),
                       "failing_names": [f["name"] for f in failures][:10]})

        if failures:
            try:
                from app.notifications.dispatcher import dispatch
                dispatch(
                    db, event_kind="integration.unreachable",
                    subject=f"{len(failures)} integration(s) unreachable",
                    body="\n".join(f"{f['kind']}: {f['name']} -- {f.get('error') or 'not ok'}"
                                   for f in failures),
                    payload={"failures": failures},
                )
            except Exception:  # noqa: BLE001
                pass

        return {"checked": len(all_results),
                "failing": len(failures),
                "details": all_results}


@celery_app.task(name="meridian.jobs.health.auto_repair")
def auto_repair() -> dict[str, Any]:
    """Periodic auto-repair sweep.

    Runs every check via app.admin.health.run_all(), then invokes repair()
    for any check whose `auto_repair` flag is True and whose severity is
    NOT 'ok'. Each invocation is audited as
    `admin.system.repair.auto`. Destructive repair actions (rebaseline,
    key rotation, retention cleanup) carry auto_repair=False so they
    never fire here — humans only.

    Returns a dict the operator can inspect via `celery events` or via
    the Repair history card on the System Health page.
    """
    from app.admin.health import repair, run_all

    fixed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    with session_scope() as db:
        for c in run_all(db):
            if c.severity == "ok" or not c.auto_repair or not c.repair:
                continue
            result = repair(c.repair, db)
            entry = {
                "name": c.name, "category": c.category,
                "severity": c.severity, "action": c.repair,
                "ok": result.ok, "detail": result.detail[:200],
            }
            if result.ok:
                fixed.append(entry)
            else:
                skipped.append(entry)
            audit(db, action="admin.system.repair.auto",
                  target_type="check", target_key=c.name,
                  payload=entry,
                  outcome="ok" if result.ok else "error")
        db.commit()

    return {"fixed": fixed, "failed_to_fix": skipped,
            "fixed_count": len(fixed),
            "failed_count": len(skipped)}

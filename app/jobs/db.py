"""PostgreSQL maintenance tasks.

VACUUM and REINDEX must not run inside a transaction — the autocommit
isolation level is set explicitly on a one-shot engine so the statements
reach the server without the SQLAlchemy session wrapping them.

Hot tables (seeded list) get REINDEX CONCURRENTLY weekly; VACUUM ANALYZE
runs across the whole DB daily to keep planner stats fresh.
"""
from __future__ import annotations

import time
from typing import Any

from sqlalchemy import create_engine, text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.config import get_settings
from app.db import session_scope


# Tables that accumulate high churn and are hottest on the query path.
# Reindexing these weekly keeps b-tree fanout healthy without the full-DB
# cost of `reindex database`.
_HOT_TABLES = (
    "audit_events",
    "query_history",
    "monitor_samples",
    "runbook_runs",
    "wizard_runs",
    "webhook_deliveries",
    "notif_deliveries",
    "sessions",
)


def _autocommit_engine():
    """Return a SQLAlchemy engine configured for AUTOCOMMIT isolation.

    VACUUM + REINDEX CONCURRENTLY refuse to run in a transaction block.
    """
    return create_engine(get_settings().db_dsn, isolation_level="AUTOCOMMIT")


@celery_app.task(name="meridian.jobs.db.vacuum_analyze")
def vacuum_analyze() -> dict[str, Any]:
    eng = _autocommit_engine()
    start = time.monotonic()
    try:
        with eng.connect() as conn:
            conn.execute(text("VACUUM (ANALYZE)"))
        ok, err = True, None
    except Exception as e:  # noqa: BLE001
        ok, err = False, str(e)[:400]
    finally:
        eng.dispose()

    duration_s = round(time.monotonic() - start, 2)
    with session_scope() as db:
        audit(db, action="db.vacuum_analyze",
              payload={"ok": ok, "duration_s": duration_s, "error": err},
              outcome="ok" if ok else "error")
    return {"ok": ok, "duration_s": duration_s, "error": err}


@celery_app.task(name="meridian.jobs.db.reindex_hot")
def reindex_hot() -> dict[str, Any]:
    eng = _autocommit_engine()
    results: dict[str, dict[str, Any]] = {}
    try:
        with eng.connect() as conn:
            for table in _HOT_TABLES:
                start = time.monotonic()
                try:
                    # Quoted identifier — _HOT_TABLES is a constant allowlist,
                    # so this is a static string, but we keep the quoting so a
                    # future edit with an operator-supplied name is still safe.
                    conn.execute(text(f'REINDEX TABLE CONCURRENTLY "{table}"'))
                    results[table] = {"ok": True,
                                      "duration_s": round(time.monotonic() - start, 2)}
                except Exception as e:  # noqa: BLE001
                    results[table] = {"ok": False,
                                      "error": str(e)[:300],
                                      "duration_s": round(time.monotonic() - start, 2)}
    finally:
        eng.dispose()

    ok_count = sum(1 for r in results.values() if r["ok"])
    with session_scope() as db:
        audit(db, action="db.reindex_hot",
              payload={"ok_count": ok_count,
                       "total": len(_HOT_TABLES),
                       "results": results})
    return {"ok_count": ok_count, "total": len(_HOT_TABLES), "results": results}

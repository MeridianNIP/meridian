"""Celery / redbeat queue introspection — powers /ui/admin/queues.

Three snapshots, served as one JSON blob to the admin page:

  workers   — alive Celery workers from `inspect().stats()` plus their
              current task from `active()`
  queues    — broker queue depths (LLEN) for the queues Meridian uses
  schedule  — every row from the `jobs` table with cron + last-run +
              next-run, so an admin can see "did the integrity scan
              actually fire at midnight?"

All three are best-effort: if Redis or a worker is unreachable we
return a stub with status="unreachable" rather than 500'ing the page.
The whole point of this surface is "show me what's broken" — failing
hard would defeat that.
"""
from __future__ import annotations

import time
from typing import Any

from sqlalchemy import text

# NOTE: `celery_app` is imported lazily inside each function below.
# Importing it at module load triggers `scheduler.load_schedule_from_db()`,
# which hits Postgres. That breaks the import-time smoke tests and forces
# any consumer (including `app.api.v1`) onto the DB-at-import skip list.
# By keeping the import inside the function bodies, this module remains
# safe to import without a DB.
from app.config import get_settings
from app.db import session_scope


# Queue names Meridian uses. The default Celery queue is "celery"; any
# named-queue routing should add an entry here so depth shows up.
_QUEUE_NAMES = ["celery", "monitors", "scheduled", "reports"]


def _snapshot_workers(timeout_s: float = 2.0) -> dict:
    """Pull worker stats via `celery inspect`. Timeout aggressively
    because inspect blocks on broker round-trip and a dead worker
    shouldn't lock the admin page."""
    from app.celery_app import celery_app
    try:
        insp = celery_app.control.inspect(timeout=timeout_s)
        stats   = insp.stats() or {}
        active  = insp.active() or {}
        reserved = insp.reserved() or {}
    except Exception as e:
        return {
            "status": "unreachable",
            "detail": f"{type(e).__name__}: {e}",
            "workers": [],
        }

    workers = []
    for name, s in stats.items():
        cur_tasks = active.get(name, [])
        res_tasks = reserved.get(name, [])
        uptime = None
        pool = s.get("pool") or {}
        try:
            # 'rusage' has user-CPU; clock isn't here, but we synthesize
            # uptime from broker_uptime if present (older Celery).
            uptime = int(pool.get("max-concurrency") or 0)
        except Exception:
            pass
        workers.append({
            "name":             name,
            "concurrency":      pool.get("max-concurrency"),
            "processes":        len(pool.get("processes") or []),
            "current_tasks":    [{
                "name": t.get("name"),
                "id":   t.get("id"),
                "args": str(t.get("args", ""))[:200],
                "time_start": t.get("time_start"),
            } for t in cur_tasks],
            "reserved_count":   len(res_tasks),
            "broker":           s.get("broker", {}).get("transport"),
        })
    return {
        "status":  "ok" if workers else "no_workers",
        "workers": workers,
        "count":   len(workers),
    }


def _snapshot_queues() -> dict:
    """Broker queue depth — LLEN each known queue name."""
    settings = get_settings()
    out: list[dict] = []
    try:
        # Use redis.from_url so we work with redis://, rediss://, or
        # valkey:// without caring which client is installed.
        import redis  # type: ignore[import-untyped]
        r = redis.from_url(settings.redis_url, socket_connect_timeout=1.5,
                           socket_timeout=1.5)
        for q in _QUEUE_NAMES:
            try:
                depth = int(r.llen(q))
                out.append({"queue": q, "depth": depth, "status": "ok"})
            except Exception as e:
                out.append({"queue": q, "depth": None, "status": "error",
                            "detail": str(e)[:200]})
        return {"status": "ok", "queues": out, "broker": settings.redis_url}
    except Exception as e:
        return {
            "status": "unreachable",
            "detail": f"{type(e).__name__}: {e}",
            "queues": [],
        }


def _snapshot_schedule() -> dict:
    """Read the jobs table — what redbeat will fire and when."""
    try:
        with session_scope() as db:
            rows = db.execute(text("""
                SELECT name, description, kind, handler, cron_expression,
                       enabled, last_run_at, last_run_status, last_run_output,
                       next_run_at
                  FROM jobs
                 ORDER BY enabled DESC, name
            """)).mappings().all()
    except Exception as e:
        return {
            "status": "unreachable",
            "detail": f"{type(e).__name__}: {e}",
            "schedule": [],
        }
    schedule = [{
        "name":             r["name"],
        "description":      r["description"],
        "kind":             r["kind"],
        "handler":          r["handler"],
        "cron":             r["cron_expression"],
        "enabled":          r["enabled"],
        "last_run_at":      r["last_run_at"].isoformat() if r["last_run_at"] else None,
        "last_run_status":  r["last_run_status"],
        "last_run_output":  (r["last_run_output"] or "")[:500],
        "next_run_at":      r["next_run_at"].isoformat() if r["next_run_at"] else None,
    } for r in rows]
    return {
        "status":   "ok",
        "schedule": schedule,
        "total":    len(schedule),
        "enabled":  sum(1 for s in schedule if s["enabled"]),
        "disabled": sum(1 for s in schedule if not s["enabled"]),
    }


def snapshot() -> dict[str, Any]:
    """Combined snapshot — the one call the admin page makes."""
    t0 = time.monotonic()
    workers  = _snapshot_workers()
    queues   = _snapshot_queues()
    schedule = _snapshot_schedule()
    return {
        "generated_at_ms": round((time.monotonic() - t0) * 1000, 1),
        "workers":  workers,
        "queues":   queues,
        "schedule": schedule,
    }


def kick_now(handler: str) -> dict:
    """Fire a scheduled handler on demand. Resolves the handler name to
    the matching Celery task and submits it to the queue. Returns the
    task id so the admin page can show "queued".

    Safety: only handlers that are already registered in the schedule
    can be kicked — prevents an admin from invoking an arbitrary
    Python dotted path."""
    from app.celery_app import celery_app
    from app.jobs.scheduler import _HANDLER_TO_TASK
    task_name = _HANDLER_TO_TASK.get(handler)
    if task_name is None:
        raise ValueError(f"handler not registered: {handler}")
    task = celery_app.send_task(task_name)
    return {"ok": True, "handler": handler, "task": task_name, "task_id": task.id}

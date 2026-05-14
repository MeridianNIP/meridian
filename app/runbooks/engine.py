"""Runbook executor.

A runbook is an ordered list of steps stored in `runbooks.steps`. Each step
is a dict:

    {
        "tool":        "dig",                            # tools.ToolSpec key
        "params":      {"target": "example.com", ...},
        "label":       "Check apex A record",            # optional human label
        "continue_on": ["ok", "warn"]                    # outcomes that let the
                                                         # next step run. If the
                                                         # step's outcome is not
                                                         # in this list, execution
                                                         # stops. Default: all.
    }

The engine never executes a step the user lacks permission for — that step's
outcome is 'denied' and continue_on decides whether to proceed.
"""

from __future__ import annotations

from datetime import UTC, datetime
import time
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.permissions import effective_permissions
from app.config import get_settings
from app.models.runbook import Runbook
from app.models.user import User
from app.runbooks.tools import get as get_tool

_ALLOWED_OUTCOMES = {"ok", "warn", "fail", "info", "denied", "error"}
_DEFAULT_CONTINUE_ON = ["ok", "warn", "info"]


async def run_runbook(
    *,
    runbook: Runbook,
    user: User,
    db: OrmSession,
) -> dict:
    """Execute the runbook's steps sequentially. Returns the run summary and
    persists a runbook_runs row. The engine is forgiving with malformed
    step dicts — a bad step yields outcome='error' and a summary, never
    an unhandled exception."""
    run_id = uuid.uuid4()
    started = datetime.now(UTC)
    results: list[dict] = []
    worst = "ok"
    user_perms = effective_permissions(db, user)
    scope_of_use = get_settings().scope_of_use
    stopped_early = False

    for idx, step in enumerate(runbook.steps or []):
        tool_key = (step or {}).get("tool")
        tool = get_tool(tool_key or "")
        label = (step or {}).get("label") or (tool.label if tool else tool_key or "step")
        continue_on = (step or {}).get("continue_on") or _DEFAULT_CONTINUE_ON

        if tool is None:
            res = {"outcome": "error", "summary": f"unknown tool {tool_key!r}", "detail": {}}
        elif tool.required_permission not in user_perms:
            res = {
                "outcome": "denied",
                "summary": f"missing permission {tool.required_permission}",
                "detail": {"required_permission": tool.required_permission},
            }
        else:
            t0 = time.monotonic()
            try:
                res = await tool.execute(
                    (step or {}).get("params") or {},
                    user=user,
                    db=db,
                    scope=scope_of_use,
                )
            except Exception as e:
                res = {"outcome": "error", "summary": f"{type(e).__name__}: {e}", "detail": {"error": str(e)}}
            res["duration_ms"] = int((time.monotonic() - t0) * 1000)

        out = res.get("outcome", "error")
        if out not in _ALLOWED_OUTCOMES:
            out = "error"
        res["outcome"] = out
        res["index"] = idx
        res["tool"] = tool_key
        res["label"] = label

        results.append(res)

        # Track worst across the run.
        sev_rank = {"ok": 0, "info": 0, "warn": 1, "fail": 2, "denied": 2, "error": 3}
        if sev_rank.get(out, 3) > sev_rank.get(worst, 0):
            worst = out

        if out not in continue_on:
            stopped_early = True
            break

    completed = datetime.now(UTC)
    status = "ok" if worst in ("ok", "info") else "warn" if worst == "warn" else "fail"
    if stopped_early and status == "ok":
        status = "stopped"

    # Persist the run
    # CAST instead of `::jsonb` — SQLAlchemy's text() parser reads the double
    # colon as a second named-parameter prefix and breaks the substitution.
    db.execute(
        text("""
        INSERT INTO runbook_runs (id, runbook_id, user_id, started_at,
                                  completed_at, status, step_results)
        VALUES (:id, :rb, :u, :t0, :t1, :s, CAST(:r AS jsonb))
    """),
        {
            "id": run_id,
            "rb": runbook.id,
            "u": user.id,
            "t0": started,
            "t1": completed,
            "s": status,
            "r": __import__("json").dumps(results),
        },
    )

    audit(
        db,
        user_id=user.id,
        action="runbook.run",
        target_type="runbook",
        target_key=str(runbook.id),
        payload={
            "run_id": str(run_id),
            "step_count": len(runbook.steps or []),
            "executed": len(results),
            "status": status,
            "stopped_early": stopped_early,
        },
    )

    return {
        "run_id": str(run_id),
        "runbook_id": str(runbook.id),
        "name": runbook.name,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "status": status,
        "worst_outcome": worst,
        "stopped_early": stopped_early,
        "step_results": results,
    }

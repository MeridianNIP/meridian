from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
import uuid

from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.db import session_scope
from app.models.user import User

StepOutcome = str  # 'ok' | 'warn' | 'fail' | 'info'


@dataclass
class WizardStep:
    name: str
    outcome: StepOutcome
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Suggestion:
    priority: str  # 'info' | 'suggested' | 'recommended' | 'critical'
    title: str
    detail: str
    tool_deeplink: str | None = None
    external_url: str | None = None


@dataclass
class WizardContext:
    target: str
    user: User
    steps: list[WizardStep] = field(default_factory=list)
    stop_on_fail: bool = False
    _stopped: bool = False

    def add(self, step: WizardStep) -> None:
        self.steps.append(step)
        if step.outcome == "fail" and self.stop_on_fail:
            self._stopped = True

    @property
    def stopped(self) -> bool:
        return self._stopped

    def worst_outcome(self) -> StepOutcome:
        order = {"info": 0, "ok": 0, "warn": 1, "fail": 2}
        best = "ok"
        for s in self.steps:
            if order.get(s.outcome, 0) > order.get(best, 0):
                best = s.outcome
        return best


WizardFn = Callable[[WizardContext], Awaitable[list[Suggestion]]]


_REGISTRY: dict[str, WizardFn] = {}


def wizard(key: str):
    """Decorator to register a wizard implementation under a stable key."""

    def deco(fn: WizardFn) -> WizardFn:
        _REGISTRY[key] = fn
        return fn

    return deco


def list_wizards() -> list[str]:
    return sorted(_REGISTRY.keys())


async def run_wizard(
    *,
    wizard_key: str,
    target: str,
    user: User,
    db: OrmSession | None = None,
) -> dict[str, Any]:
    fn = _REGISTRY.get(wizard_key)
    if fn is None:
        raise ValueError(f"no wizard registered as {wizard_key!r}")

    ctx = WizardContext(target=target, user=user, stop_on_fail=False)
    suggestions: list[Suggestion] = []
    error: str | None = None
    try:
        suggestions = await fn(ctx)
    except Exception as e:
        error = f"{type(e).__name__}: {e}"

    started_at = datetime.now(UTC)
    run_id = uuid.uuid4()

    # Persist the wizard run + audit. If the caller supplied a session we write
    # into it; otherwise we open one ourselves.
    import json as _json

    def _jsonable(obj):
        """Coerce dataclasses, datetimes, UUIDs into JSON-safe primitives."""
        if hasattr(obj, "__dict__"):
            return {k: _jsonable(v) for k, v in obj.__dict__.items()}
        if isinstance(obj, (datetime, uuid.UUID)):
            return str(obj)
        if isinstance(obj, (list, tuple)):
            return [_jsonable(v) for v in obj]
        if isinstance(obj, dict):
            return {k: _jsonable(v) for k, v in obj.items()}
        return obj

    def _persist(s: OrmSession) -> None:
        # CAST(:... AS jsonb) instead of `::jsonb` — SQLAlchemy's text() reads
        # double-colons as a parameter prefix and raises SyntaxError.
        s.execute(
            __import__("sqlalchemy").text("""
                INSERT INTO wizard_runs
                  (id, wizard_key, user_id, target, started_at, completed_at,
                   outcome, steps, findings, suggestions)
                VALUES
                  (:id, :k, :u, :t, :start, :done, :o,
                   CAST(:steps AS jsonb), CAST(:f AS jsonb), CAST(:sug AS jsonb))
            """),
            {
                "id": run_id,
                "k": wizard_key,
                "u": user.id,
                "t": target,
                "start": started_at,
                "done": datetime.now(UTC),
                "o": "error" if error else ctx.worst_outcome(),
                "steps": _json.dumps([_jsonable(st) for st in ctx.steps]),
                "f": _json.dumps([]),
                "sug": _json.dumps([_jsonable(sg) for sg in suggestions]),
            },
        )
        audit(
            s,
            user_id=user.id,
            action="wizard.run",
            target_type="wizard",
            target_key=wizard_key,
            payload={
                "target": target,
                "outcome": ctx.worst_outcome(),
                "steps": len(ctx.steps),
                "suggestions": len(suggestions),
                "error": error,
            },
        )

    if db is not None:
        _persist(db)
    else:
        with session_scope() as s:
            _persist(s)

    return {
        "run_id": str(run_id),
        "wizard_key": wizard_key,
        "target": target,
        "outcome": "error" if error else ctx.worst_outcome(),
        "steps": [s.__dict__ for s in ctx.steps],
        "suggestions": [sg.__dict__ for sg in suggestions],
        "error": error,
    }

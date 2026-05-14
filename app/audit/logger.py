from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.audit.redact import redact as redact_payload
from app.integrity.hmac_chain import canonicalize, prev_row_hash, row_hash
from app.models.audit import AuditEvent


def _now() -> datetime:
    return datetime.now(timezone.utc)


def record(
    db: OrmSession,
    *,
    action: str,
    user_id: uuid.UUID | None = None,
    impersonator_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_key: str | None = None,
    payload: dict[str, Any] | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    justification: str | None = None,
    approval_id: uuid.UUID | None = None,
    outcome: str = "ok",
) -> AuditEvent:
    """Insert an audit event with a row_hash that chains off the last audit row.

    Flushes to DB but does not commit — caller controls the transaction.
    """
    # Defence-in-depth: scrub PII (emails, phones, cards, bearer tokens,
    # recovery contacts, etc.) from the payload before persist. Even if an
    # upstream route accidentally passes a sensitive field, the audit table
    # stays free of it. The row_hash is computed over the REDACTED payload
    # so an attacker who later reads the table can't reconstruct what was
    # there from the hash either.
    safe_payload = redact_payload(payload or {})
    ev = AuditEvent(
        ts=_now(),
        user_id=user_id,
        impersonator_id=impersonator_id,
        action=action,
        target_type=target_type,
        target_key=target_key,
        payload=safe_payload,
        ip=ip,
        user_agent=user_agent,
        justification=justification,
        approval_id=approval_id,
        outcome=outcome,
    )
    # Compute row_hash before the INSERT: canonicalize what's going in, chain off
    # whatever row_hash is present at the tail.
    canonical = canonicalize({
        "ts":              ev.ts,
        "user_id":         ev.user_id,
        "impersonator_id": ev.impersonator_id,
        "action":          ev.action,
        "target_type":     ev.target_type,
        "target_key":      ev.target_key,
        "payload":         safe_payload,
        "ip":              ev.ip,
        "user_agent":      ev.user_agent,
        "justification":   ev.justification,
        "approval_id":     ev.approval_id,
        "outcome":         ev.outcome,
    })
    ev.row_hash = row_hash(canonical, prev_row_hash(db, "audit_events"))
    db.add(ev)
    db.flush()
    return ev


def record_in_scope(**kwargs) -> None:
    """Same as record() but opens its own short-lived session + commits.

    Use this from route handlers that run long external commands — holding
    the per-request DB session across a 30s subprocess was starving the pool.
    """
    from app.db import session_scope
    with session_scope() as db:
        record(db, **kwargs)


def recent(db: OrmSession, *, limit: int = 100) -> list[AuditEvent]:
    return list(db.execute(
        select(AuditEvent).order_by(AuditEvent.ts.desc()).limit(limit)
    ).scalars())

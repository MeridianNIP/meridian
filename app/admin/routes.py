from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit_record
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.user import User


router = APIRouter(prefix="/admin", tags=["admin"])


SERVICE_DESCRIPTIONS: dict[str, str] = {
    "nginx.service":         "Web server · TLS termination · reverse proxy",
    "postgresql.service":    "Primary database · users, queries, audit logs, monitors",
    "bind9.service":         "Recursive DNS resolver · powers sandboxed dig queries (Debian 12)",
    "named.service":         "Recursive DNS resolver · powers sandboxed dig queries (Debian 13)",
    "redis-server.service":  "In-memory cache · Celery broker · session store (Debian 12)",
    "valkey-server.service": "In-memory cache · Celery broker · session store (Debian 13)",
    "meridian-app.service":   "FastAPI application workers",
    "meridian-celery.service":"Background task queue · runs bulk lookups, scheduled jobs",
    "meridian-beat.service":  "Celery beat · fires scheduled jobs",
    "fail2ban.service":       "Intrusion prevention · auto-bans IPs on repeated failures",
}


def _svc_status(name: str) -> dict[str, Any]:
    try:
        active = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=3,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        active = "unknown"
    try:
        uptime = subprocess.run(
            ["systemctl", "show", name, "--property=ActiveEnterTimestamp", "--value"],
            capture_output=True, text=True, timeout=3,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        uptime = ""
    return {
        "name": name,
        "description": SERVICE_DESCRIPTIONS.get(name, ""),
        "active": active,
        "active_since": uptime,
    }


def _unit_exists(name: str) -> bool:
    """True if systemd has a unit file for `name`. LoadState=not-found means
    the unit is absent — hide it from the UI so e.g. Debian 13 doesn't show
    redis-server as 'inactive' alongside valkey-server."""
    try:
        load_state = subprocess.run(
            ["systemctl", "show", name, "--property=LoadState", "--value"],
            capture_output=True, text=True, timeout=3,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return True
    return load_state != "not-found"


@router.get("/services")
async def services(
    user: User = Depends(require_permission("admin.services.restart")),
) -> dict:
    # Debian 13 ships valkey; Debian 12 ships redis. bind9.service is aliased
    # to named.service on Debian 13. We probe each candidate and only surface
    # the ones actually present on this host.
    names = [
        "nginx.service", "postgresql.service",
        "named.service", "bind9.service",
        "redis-server.service", "valkey-server.service",
        "meridian-app.service", "meridian-celery.service", "meridian-beat.service",
        "fail2ban.service",
    ]
    return {"services": [_svc_status(n) for n in names if _unit_exists(n)]}


@router.get("/jobs")
async def jobs(
    user: User = Depends(require_permission("admin.feature_gates.edit")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rows = db.execute(text("""
        SELECT name, description, cron_expression, enabled,
               last_run_at, last_run_status, next_run_at
          FROM jobs ORDER BY name
    """)).fetchall()
    return {"jobs": [dict(r._mapping) for r in rows]}


@router.get("/audit/recent")
async def audit_recent(
    limit: int = 50,
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rows = db.execute(text("""
        SELECT ts, user_id, action, target_type, target_key, outcome
          FROM audit_events ORDER BY ts DESC LIMIT :lim
    """), {"lim": max(1, min(limit, 500))}).fetchall()
    return {
        "events": [
            {
                "ts": r.ts.isoformat() if r.ts else None,
                "user_id": str(r.user_id) if r.user_id else None,
                "action": r.action,
                "target_type": r.target_type,
                "target_key": r.target_key,
                "outcome": r.outcome,
            }
            for r in rows
        ]
    }


@router.get("/stats")
async def stats(
    user: User = Depends(require_permission("admin.users.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    return {
        "users_enabled":    db.execute(text("SELECT count(*) FROM users WHERE enabled AND deleted_at IS NULL")).scalar_one(),
        "sessions_active":  db.execute(text("SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()")).scalar_one(),
        "monitors_enabled": db.execute(text("SELECT count(*) FROM monitors WHERE enabled")).scalar_one(),
        "audit_24h":        db.execute(text("SELECT count(*) FROM audit_events WHERE ts > :t"), {"t": day_ago}).scalar_one(),
        "integrity_last_scan": db.execute(text("""
            SELECT started_at, mismatches FROM db_integrity_scans
             ORDER BY started_at DESC LIMIT 1
        """)).first(),
    }

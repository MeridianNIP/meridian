"""Per-component health probes for /healthz.

Each probe returns a dict { name, status, detail, latency_ms } where
status is "ok", "warn", or "down". The aggregator sets the HTTP code:

  - all ok                    → 200
  - any warn, no down         → 200 (returned for visibility, not 503 —
                                we don't want a stale cert to page oncall
                                via a downed /healthz)
  - any down on critical=true → 503
  - any down on critical=false→ 200 (degraded but serving)

Critical = the portal cannot serve correctly without it. DB and broker
qualify; BIND9 is critical only when the DNS-tools features are in use;
integrations are never critical.
"""
from __future__ import annotations

import socket
import time
from typing import Callable

from app.db import get_engine

ProbeResult = dict


def _time(label: str, critical: bool, fn: Callable[[], tuple[str, str]]) -> ProbeResult:
    t0 = time.monotonic()
    try:
        status, detail = fn()
    except Exception as e:
        return {
            "name":       label,
            "status":     "down",
            "critical":   critical,
            "detail":     f"{type(e).__name__}: {e}",
            "latency_ms": round((time.monotonic() - t0) * 1000, 1),
        }
    return {
        "name":       label,
        "status":     status,
        "critical":   critical,
        "detail":     detail,
        "latency_ms": round((time.monotonic() - t0) * 1000, 1),
    }


def _probe_db() -> tuple[str, str]:
    with get_engine().connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    return "ok", "SELECT 1 returned"


def _probe_broker() -> tuple[str, str]:
    """Redis/Valkey reachability. Reads the broker URL from settings and
    opens a TCP socket — no need to pull the full redis client just for
    a liveness check."""
    from app.config import get_settings
    url = get_settings().redis_url or ""
    if not url:
        return "warn", "redis_url not configured"
    # Parse host/port out of redis://host:port/db
    from urllib.parse import urlparse
    p = urlparse(url)
    host = p.hostname or "127.0.0.1"
    port = p.port or 6379
    with socket.create_connection((host, port), timeout=2.0) as s:
        s.sendall(b"PING\r\n")
        reply = s.recv(64)
    if b"PONG" in reply:
        return "ok", f"{host}:{port} PONG"
    return "warn", f"{host}:{port} unexpected reply {reply!r}"


def _probe_bind() -> tuple[str, str]:
    """BIND9 recursive resolver on localhost:53. Marked non-critical
    because the portal can still serve admin/auth/integrations without
    BIND — only the DNS-tools features depend on it."""
    with socket.create_connection(("127.0.0.1", 53), timeout=2.0):
        pass
    return "ok", "127.0.0.1:53 reachable"


def _probe_certs() -> tuple[str, str]:
    """Surface the soonest expiry from the `certificates` table. Doesn't
    fail /healthz — just reports."""
    try:
        from app.db import session_scope
        from sqlalchemy import text
        with session_scope() as db:
            row = db.execute(text(
                "SELECT min(valid_until) AS soonest "
                "FROM certificates "
                "WHERE valid_until IS NOT NULL AND revoked_at IS NULL"
            )).first()
    except Exception as e:
        return "warn", f"watchlist unavailable: {type(e).__name__}"
    if row is None or row.soonest is None:
        return "ok", "no watchlist entries"
    from datetime import datetime, timezone
    days = (row.soonest - datetime.now(timezone.utc)).days
    if days <= 7:
        return "warn", f"soonest expiry in {days}d"
    return "ok", f"soonest expiry in {days}d"


# Order matters in output — DB first, then anything that depends on DB.
PROBES: list[tuple[str, bool, Callable[[], tuple[str, str]]]] = [
    ("db",      True,  _probe_db),
    ("broker",  True,  _probe_broker),
    ("bind9",   False, _probe_bind),
    ("certs",   False, _probe_certs),
]


def gather() -> tuple[dict, int]:
    """Run every probe and return (response_body, http_status_code)."""
    components = [_time(name, crit, fn) for name, crit, fn in PROBES]
    any_critical_down = any(c["status"] == "down" and c["critical"] for c in components)
    if any_critical_down:
        overall = "unhealthy"
        code = 503
    elif any(c["status"] == "down" for c in components):
        overall = "degraded"
        code = 200
    elif any(c["status"] == "warn" for c in components):
        overall = "warn"
        code = 200
    else:
        overall = "ok"
        code = 200
    return {
        "status":     overall,
        "service":    "meridian-app",
        "components": components,
    }, code

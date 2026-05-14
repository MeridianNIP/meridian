"""Report generators — pure DB → rows functions.

Each generator returns `(headers, rows, summary)`:
  headers  -- list[str] column names in render order
  rows     -- list[list[str|int|float|None]] ready for CSV/HTML
  summary  -- dict with aggregate stats shown above the table

Add a new report_type by registering in REPORT_REGISTRY at the bottom.
Each entry is a dict with: `label`, `description`, `generator`,
`default_filters`, and `filter_schema` (used by the UI to build the
form). All generators are synchronous and take a `filters: dict`."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession


def _pct(num: int, den: int) -> str:
    return f"{(num / den * 100):.2f}%" if den else "—"


def monitor_uptime(db: OrmSession, filters: dict) -> tuple[list[str], list[list], dict]:
    """Per-monitor uptime over the configured window."""
    hours = max(1, int(filters.get("window_hours") or 24))
    cutoff = datetime.now(UTC) - timedelta(hours=hours)

    rows = db.execute(
        text("""
        SELECT
          m.id, m.name, m.kind, m.target, m.enabled, m.last_status,
          COUNT(s.ts) AS samples,
          COUNT(*) FILTER (WHERE s.status = 'ok')   AS ok_ct,
          COUNT(*) FILTER (WHERE s.status = 'fail') AS fail_ct,
          AVG(s.value) FILTER (WHERE s.status = 'ok') AS avg_value
        FROM monitors m
        LEFT JOIN monitor_samples s
               ON s.monitor_id = m.id AND s.ts >= :cutoff
        GROUP BY m.id, m.name, m.kind, m.target, m.enabled, m.last_status
        ORDER BY m.name
    """),
        {"cutoff": cutoff},
    ).fetchall()

    headers = [
        "Monitor",
        "Kind",
        "Target",
        "Enabled",
        "Last status",
        "Samples",
        "OK",
        "Fail",
        "Uptime",
        "Avg value",
    ]
    out_rows = []
    ok_total = fail_total = 0
    for r in rows:
        samples = r.samples or 0
        ok_ct = r.ok_ct or 0
        fail_ct = r.fail_ct or 0
        ok_total += ok_ct
        fail_total += fail_ct
        out_rows.append(
            [
                r.name,
                r.kind,
                r.target,
                "yes" if r.enabled else "no",
                r.last_status or "—",
                samples,
                ok_ct,
                fail_ct,
                _pct(ok_ct, ok_ct + fail_ct),
                f"{r.avg_value:.2f}" if r.avg_value is not None else "—",
            ]
        )
    summary = {
        "Window": f"{hours} h",
        "Monitors": len(out_rows),
        "Total samples": ok_total + fail_total,
        "Overall uptime": _pct(ok_total, ok_total + fail_total),
    }
    return headers, out_rows, summary


def cert_expiry(db: OrmSession, filters: dict) -> tuple[list[str], list[list], dict]:
    """Certificates expiring within the configured horizon."""
    days = max(1, int(filters.get("horizon_days") or 60))
    cutoff = datetime.now(UTC) + timedelta(days=days)

    rows = db.execute(
        text("""
        SELECT subject_cn, issuer_cn, serial_hex,
               not_before, not_after, kind, source
          FROM certificates
         WHERE not_after <= :cutoff
         ORDER BY not_after
    """),
        {"cutoff": cutoff},
    ).fetchall()

    headers = ["Subject CN", "Issuer", "Serial", "Valid from", "Expires", "Days left", "Kind", "Source"]
    out_rows = []
    expired = soon = healthy = 0
    now = datetime.now(UTC)
    for r in rows:
        days_left = (r.not_after - now).days if r.not_after else None
        if days_left is None or days_left < 0:
            expired += 1
        elif days_left <= 14:
            soon += 1
        else:
            healthy += 1
        out_rows.append(
            [
                r.subject_cn,
                r.issuer_cn or "—",
                r.serial_hex or "—",
                r.not_before.isoformat() if r.not_before else "—",
                r.not_after.isoformat() if r.not_after else "—",
                days_left if days_left is not None else "—",
                r.kind or "—",
                r.source or "—",
            ]
        )
    summary = {
        "Horizon": f"{days} days",
        "Certificates": len(out_rows),
        "Expired": expired,
        "Expiring ≤14d": soon,
        "Healthy (in range)": healthy,
    }
    return headers, out_rows, summary


def dns_health(db: OrmSession, filters: dict) -> tuple[list[str], list[list], dict]:
    """Recent resolver errors + query-log rollup."""
    hours = max(1, int(filters.get("window_hours") or 24))
    cutoff = datetime.now(UTC) - timedelta(hours=hours)

    rows = db.execute(
        text("""
        SELECT COALESCE(rcode, 'unknown') AS rcode,
               COUNT(*) AS n,
               COUNT(DISTINCT client_ip) AS clients,
               COUNT(DISTINCT qname) AS names
          FROM dns_queries
         WHERE received_at >= :cutoff
         GROUP BY rcode
         ORDER BY n DESC
    """),
        {"cutoff": cutoff},
    ).fetchall()

    headers = ["Response code", "Queries", "Distinct clients", "Distinct names"]
    out_rows = [[r.rcode, r.n, r.clients, r.names] for r in rows]
    total = sum(r.n for r in rows)
    errs = sum(r.n for r in rows if r.rcode not in ("NOERROR", "unknown"))
    summary = {
        "Window": f"{hours} h",
        "Total queries": total,
        "Errors (non-NOERROR)": errs,
        "Error rate": _pct(errs, total),
    }
    return headers, out_rows, summary


def audit_activity(db: OrmSession, filters: dict) -> tuple[list[str], list[list], dict]:
    """Audit event rollup — who did what, how often."""
    hours = max(1, int(filters.get("window_hours") or 24))
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    rows = db.execute(
        text("""
        SELECT actor_username AS actor, action, COUNT(*) AS n,
               MAX(ts) AS last_ts
          FROM audit_events
         WHERE ts >= :cutoff
         GROUP BY actor_username, action
         ORDER BY n DESC
         LIMIT 500
    """),
        {"cutoff": cutoff},
    ).fetchall()
    headers = ["Actor", "Action", "Count", "Most recent"]
    out_rows = [[r.actor or "—", r.action, r.n, r.last_ts.isoformat() if r.last_ts else "—"] for r in rows]
    summary = {
        "Window": f"{hours} h",
        "Actor/action pairs": len(out_rows),
        "Total events": sum(r.n for r in rows),
    }
    return headers, out_rows, summary


REPORT_REGISTRY: dict[str, dict[str, Any]] = {
    "monitor_uptime": {
        "label": "Monitor uptime rollup",
        "description": "Per-monitor OK/fail counts and uptime % over the selected window.",
        "generator": monitor_uptime,
        "default_filters": {"window_hours": 24},
        "filter_schema": [
            {
                "key": "window_hours",
                "label": "Window (hours)",
                "type": "int",
                "min": 1,
                "max": 8760,
                "default": 24,
            },
        ],
    },
    "cert_expiry": {
        "label": "Certificate expiry",
        "description": "Certificates expiring within the configured horizon.",
        "generator": cert_expiry,
        "default_filters": {"horizon_days": 60},
        "filter_schema": [
            {
                "key": "horizon_days",
                "label": "Horizon (days)",
                "type": "int",
                "min": 1,
                "max": 3650,
                "default": 60,
            },
        ],
    },
    "dns_health": {
        "label": "DNS health rollup",
        "description": "Response-code mix + error rate from the resolver query log.",
        "generator": dns_health,
        "default_filters": {"window_hours": 24},
        "filter_schema": [
            {
                "key": "window_hours",
                "label": "Window (hours)",
                "type": "int",
                "min": 1,
                "max": 8760,
                "default": 24,
            },
        ],
    },
    "audit_activity": {
        "label": "Audit activity",
        "description": "Actor × action event counts over the selected window.",
        "generator": audit_activity,
        "default_filters": {"window_hours": 24},
        "filter_schema": [
            {
                "key": "window_hours",
                "label": "Window (hours)",
                "type": "int",
                "min": 1,
                "max": 8760,
                "default": 24,
            },
        ],
    },
}


def get_generator(report_type: str) -> Callable:
    entry = REPORT_REGISTRY.get(report_type)
    if entry is None:
        raise ValueError(f"Unknown report_type {report_type!r}")
    return entry["generator"]

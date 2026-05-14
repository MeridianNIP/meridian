from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.db import session_scope


def _keep_days(db, scope: str, default: int) -> int:
    row = db.execute(
        text("SELECT keep_days FROM retention_rules WHERE scope = :s AND enabled"),
        {"s": scope},
    ).scalar_one_or_none()
    return row if row is not None else default


@celery_app.task(name="meridian.jobs.retention.audit_cleanup")
def audit_cleanup() -> dict[str, Any]:
    with session_scope() as db:
        days = _keep_days(db, "audit_events", 90)
        cutoff = datetime.now(UTC) - timedelta(days=days)
        result = db.execute(
            text("DELETE FROM audit_events WHERE ts < :cutoff"),
            {"cutoff": cutoff},
        )
        n = result.rowcount or 0
        # Logging a cleanup event into the same table is fine; the chain catches
        # any future deletion of THIS row the same way.
        audit(db, action="retention.audit_events.cleanup", payload={"rows_deleted": n, "keep_days": days})
        return {"rows_deleted": n, "keep_days": days}


@celery_app.task(name="meridian.jobs.retention.query_cleanup")
def query_cleanup() -> dict[str, Any]:
    with session_scope() as db:
        days = _keep_days(db, "query_history", 30)
        # Keep last 500 per user AND enforce N-day cap — whichever is stricter.
        cutoff = datetime.now(UTC) - timedelta(days=days)
        result = db.execute(
            text("""
            WITH ranked AS (
              SELECT id, row_number() OVER (PARTITION BY user_id ORDER BY started_at DESC) AS rn
                FROM query_history
            )
            DELETE FROM query_history qh
            USING ranked r
            WHERE qh.id = r.id
              AND (r.rn > 500 OR qh.started_at < :cutoff)
              AND qh.pinned = FALSE
        """),
            {"cutoff": cutoff},
        )
        n = result.rowcount or 0
        audit(db, action="retention.query_history.cleanup", payload={"rows_deleted": n, "keep_days": days})
        return {"rows_deleted": n, "keep_days": days}


@celery_app.task(name="meridian.jobs.sessions.cleanup")
def session_cleanup() -> dict[str, Any]:
    with session_scope() as db:
        cutoff = datetime.now(UTC) - timedelta(hours=12)
        result = db.execute(
            text("""
            UPDATE sessions
               SET revoked_at = now(),
                   revoked_reason = 'stale_idle'
             WHERE revoked_at IS NULL
               AND last_active_at < :cutoff
        """),
            {"cutoff": cutoff},
        )
        n = result.rowcount or 0
        audit(db, action="retention.sessions.cleanup", payload={"sessions_revoked": n})
        return {"sessions_revoked": n}


@celery_app.task(name="meridian.jobs.retention.celery_purge")
def celery_purge() -> dict[str, Any]:
    """Drop Celery result/task metadata older than the retention window.

    Celery stores results in Redis/Valkey by default (TTL handled by the broker),
    but when a DB result backend is configured we prune here. No-op when the
    tables don't exist.
    """
    with session_scope() as db:
        days = _keep_days(db, "celery_results", 7)
        cutoff = datetime.now(UTC) - timedelta(days=days)
        purged: dict[str, int] = {}

        for table in ("celery_taskmeta", "celery_tasksetmeta"):
            exists = db.execute(
                text(
                    "SELECT 1 FROM information_schema.tables " "WHERE table_schema='public' AND table_name=:n"
                ),
                {"n": table},
            ).first()
            if not exists:
                continue
            r = db.execute(text(f"DELETE FROM {table} WHERE date_done < :cutoff"), {"cutoff": cutoff})
            purged[table] = r.rowcount or 0

        audit(db, action="retention.celery.purge", payload={"purged": purged, "keep_days": days})
        return {"purged": purged, "keep_days": days}


@celery_app.task(name="meridian.jobs.retention.pcap_cleanup")
def pcap_cleanup() -> dict[str, Any]:
    """Delete pcap files older than retention window unless the FileRecord is pinned.

    Walks the files table for category='pcap' and removes on-disk blobs past the
    cutoff, then drops the matching rows.
    """
    with session_scope() as db:
        days = _keep_days(db, "pcap", 14)
        cutoff = datetime.now(UTC) - timedelta(days=days)
        rows = db.execute(
            text("""
            SELECT id, storage_path FROM files
             WHERE category = 'pcap' AND pinned = FALSE AND uploaded_at < :cutoff
        """),
            {"cutoff": cutoff},
        ).all()

        removed_files = 0
        removed_rows = 0
        for r in rows:
            p = Path(r.storage_path)
            try:
                if p.is_file():
                    p.unlink()
                    removed_files += 1
                try:
                    p.parent.rmdir()
                except OSError:
                    pass
            except OSError:
                pass
            db.execute(text("DELETE FROM files WHERE id = :id"), {"id": r.id})
            removed_rows += 1

        audit(
            db,
            action="retention.pcap.cleanup",
            payload={"rows_deleted": removed_rows, "files_removed": removed_files, "keep_days": days},
        )
        return {"rows_deleted": removed_rows, "files_removed": removed_files, "keep_days": days}


@celery_app.task(name="meridian.jobs.retention.file_quota")
def file_quota() -> dict[str, Any]:
    """Enforce per-user quota. Evicts the oldest non-pinned files until each
    user is back under the hard cap configured in retention_rules.scope='file_repo_user'.
    """
    with session_scope() as db:
        hard_row = db.execute(
            text("SELECT max_bytes FROM retention_rules WHERE scope='file_repo_user' AND enabled")
        ).scalar_one_or_none()
        hard_cap = int(hard_row) if hard_row is not None else 1024 * 1024 * 1024

        users_over = db.execute(
            text("""
            SELECT owner_id, SUM(size_bytes) AS bytes
              FROM files GROUP BY owner_id HAVING SUM(size_bytes) > :cap
        """),
            {"cap": hard_cap},
        ).all()

        evicted: list[dict[str, Any]] = []
        for row in users_over:
            overage = int(row.bytes) - hard_cap
            victims = db.execute(
                text("""
                SELECT id, storage_path, size_bytes FROM files
                 WHERE owner_id = :u AND pinned = FALSE
                 ORDER BY uploaded_at ASC
            """),
                {"u": row.owner_id},
            ).all()
            freed = 0
            ids_evicted: list[str] = []
            for v in victims:
                if freed >= overage:
                    break
                p = Path(v.storage_path)
                try:
                    if p.is_file():
                        p.unlink()
                    try:
                        p.parent.rmdir()
                    except OSError:
                        pass
                except OSError:
                    pass
                db.execute(text("DELETE FROM files WHERE id = :id"), {"id": v.id})
                freed += int(v.size_bytes or 0)
                ids_evicted.append(str(v.id))
            evicted.append(
                {"owner_id": str(row.owner_id), "bytes_freed": freed, "files_evicted": len(ids_evicted)}
            )

        audit(
            db,
            action="retention.file_repo.quota",
            payload={"hard_cap_bytes": hard_cap, "users_trimmed": len(evicted), "evicted": evicted},
        )
        return {"hard_cap_bytes": hard_cap, "users_trimmed": len(evicted), "evicted": evicted}

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.db import session_scope
from app.integrity.hmac_chain import TAMPER_EVIDENT_TABLES, canonicalize, row_hash


_CANONICAL_COLUMNS: dict[str, tuple[str, ...]] = {
    "audit_events": (
        "id", "ts", "user_id", "impersonator_id", "action", "target_type",
        "target_key", "payload", "ip", "user_agent", "justification",
        "approval_id", "outcome",
    ),
    "license": (
        "id", "license_id", "tier", "max_users", "features",
        "bound_domain", "bound_fingerprint_hash", "issued_at", "expires_at",
        "activated_at", "revoked",
    ),
    "license_activations": (
        "id", "license_id", "instance_id", "fingerprint_hash", "ip", "ok",
        "reason", "ts",
    ),
    "license_verifications": ("id", "ts", "result", "latency_ms", "detail"),
    "cert_events": ("id", "cert_id", "event", "ts", "actor_id", "detail"),
    "approvals": (
        "id", "requested_by", "approver_id", "action", "target_type",
        "target_key", "payload", "justification", "state",
        "requested_at", "decided_at", "decision_note",
    ),
    "impersonations": (
        "id", "admin_id", "target_id", "reason", "started_at", "ended_at",
        "approval_id",
    ),
    "update_history": (
        "id", "component", "from_version", "to_version", "applied_at",
        "applied_by", "snapshot_id", "status", "notes",
    ),
}


@celery_app.task(name="meridian.jobs.integrity.scan")
def scan() -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    mismatches: list[dict[str, Any]] = []
    tables_scanned: list[str] = []
    rows_checked = 0

    with session_scope() as db:
        scan_id = uuid.uuid4()
        db.execute(text("""
            INSERT INTO db_integrity_scans (id, started_at, status)
            VALUES (:id, :ts, 'running')
        """), {"id": scan_id, "ts": started})

        for table in TAMPER_EVIDENT_TABLES:
            cols = _CANONICAL_COLUMNS.get(table)
            if cols is None:
                continue
            tables_scanned.append(table)
            prev_hash: bytes | None = None
            # Stream rows ordered by PK so the chain is well-defined. Every
            # tamper-evident table has either a BIGSERIAL `id` or a UUID PK; the
            # order we care about is insertion order, which ctid approximates
            # but the PK is portable across replicas.
            col_list = ", ".join(cols) + ", row_hash"
            rows = db.execute(
                text(f"SELECT {col_list} FROM {table} ORDER BY "
                     + ("id" if "id" in cols else "ts"))
            ).fetchall()
            for r in rows:
                rows_checked += 1
                values = dict(zip(cols, r[:-1]))
                # psycopg2 returns BYTEA as `memoryview`, not `bytes`. On
                # Python 3.13 `memoryview == bytes` returns False even when
                # contents are byte-identical, so EVERY row falsely reports
                # as a mismatch. Cast to bytes up front.
                stored_hash = bytes(r[-1]) if r[-1] is not None else None
                # The original hash was computed at INSERT time — BEFORE
                # the DB assigned an `id`. So `id` is excluded from the
                # canonical input even though we SELECTed it for PK
                # reporting. canonicalize() sorts keys, so exclusion
                # order doesn't matter.
                canonical_values = {k: v for k, v in values.items() if k != "id"}
                expected = row_hash(canonicalize(canonical_values), prev_hash)
                # NULL stored_hash means the row was inserted before the
                # app started computing hashes (or via a path that didn't
                # go through logger.record). That's a data-integrity
                # concern to report, but NOT tampering — don't alarm-red
                # on it. Treat it as a separate "unhashed" finding.
                if stored_hash is None:
                    mismatches.append({
                        "table": table, "pk": values.get("id"),
                        "kind": "unhashed_row",
                    })
                elif stored_hash != expected:
                    mismatches.append({
                        "table": table,
                        "pk": values.get("id"),
                        "kind": "hash_mismatch",
                        "expected": expected.hex() if expected else None,
                        "stored": stored_hash.hex(),
                    })
                prev_hash = stored_hash if stored_hash is not None else expected

        completed = datetime.now(timezone.utc)
        # Cap the detail payload — on a brand-new install with no row_hash
        # triggers every row shows as a "mismatch", which can push the
        # JSONB column into MB-sized territory and crash the UPDATE with
        # "can't adapt type 'dict'". Store at most the first 50 findings
        # plus a count; the full picture is in the logs anyway.
        import json
        capped = mismatches[:50]
        detail_json = json.dumps({
            "mismatches": capped,
            "total_reported": len(mismatches),
            "truncated": len(mismatches) > 50,
        }) if mismatches else None
        db.execute(text("""
            UPDATE db_integrity_scans
               SET completed_at = :done,
                   tables_scanned = :tables,
                   rows_checked = :n,
                   mismatches = :m,
                   mismatch_detail = CAST(:detail AS JSONB),
                   status = :status,
                   alert_fired = :alert
             WHERE id = :id
        """), {
            "id": scan_id, "done": completed,
            "tables": tables_scanned, "n": rows_checked,
            "m": len(mismatches),
            "detail": detail_json,
            "status": "fail" if mismatches else "ok",
            "alert": bool(mismatches),
        })

        audit(db, action="integrity.scan.completed",
              payload={"rows": rows_checked, "mismatches": len(mismatches),
                       "tables": tables_scanned},
              outcome="error" if mismatches else "ok")

    return {
        "scan_id": str(scan_id),
        "rows_checked": rows_checked,
        "tables_scanned": tables_scanned,
        "mismatches": len(mismatches),
    }

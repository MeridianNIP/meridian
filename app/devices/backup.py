"""Device backup engine.

Pulls the running config, SHA-256s it, and stores a new DeviceConfigSnapshot
only when the hash differs from the device's last stored hash — "backup on
change". This keeps the snapshot table scoped to actual diffs, not daily
re-reads of an unchanged config.

Diff against the previous snapshot is computed with difflib.unified_diff
once, stored alongside the snapshot, and exposed to the UI without re-read.

Notification + webhook fanout fire when a change is detected so ops can
catch unexpected drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import difflib
import hashlib
from typing import Any
import uuid

from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.devices.connection import fetch_running_config
from app.models.device import (
    DeviceBackupRun,
    DeviceConfigSnapshot,
    NetworkDevice,
)
from app.secrets_vault.vault import decrypt_field


@dataclass
class DeviceBackupResult:
    device_id: str
    device_name: str
    ok: bool
    changed: bool
    snapshot_id: str | None
    sha256: str | None
    size_bytes: int | None
    error: str | None
    duration_ms: int


def _load_secret(db: OrmSession, secret_id) -> str | None:
    """Split (nonce, ciphertext) → decrypted plaintext. Matches the pattern
    used in admin.integrations_routes for credential storage."""
    if secret_id is None:
        return None
    row = db.execute(text("SELECT ciphertext, nonce FROM secrets WHERE id = :id"), {"id": secret_id}).first()
    if row is None:
        return None
    try:
        return decrypt_field(bytes(row.nonce) + bytes(row.ciphertext), domain=b"vault").decode()
    except Exception:
        return None


def _unified_diff(prev: str, curr: str, *, context_lines: int = 3) -> tuple[str, int, int]:
    """Return (diff_text, lines_added, lines_removed)."""
    diff_lines = list(
        difflib.unified_diff(
            prev.splitlines(keepends=True),
            curr.splitlines(keepends=True),
            fromfile="previous",
            tofile="current",
            n=context_lines,
        )
    )
    added = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
    return "".join(diff_lines), added, removed


def backup_device(
    db: OrmSession,
    device: NetworkDevice,
    *,
    trigger: str = "scheduled",
    captured_by: uuid.UUID | None = None,
) -> DeviceBackupResult:
    import time

    t0 = time.monotonic()
    password = _load_secret(db, device.secret_id)
    enable_password = _load_secret(db, device.enable_secret_id)

    try:
        raw = fetch_running_config(
            kind=device.kind,
            host=device.mgmt_host,
            port=device.mgmt_port,
            username=device.username,
            password=password,
            enable_password=enable_password,
            overrides=device.config or {},
        )
    except Exception as e:
        err = f"{type(e).__name__}: {e}"[:512]
        device.last_backup_at = datetime.now(UTC)
        device.last_backup_ok = False
        device.last_backup_error = err
        return DeviceBackupResult(
            device_id=str(device.id),
            device_name=device.name,
            ok=False,
            changed=False,
            snapshot_id=None,
            sha256=None,
            size_bytes=None,
            error=err,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    sha256 = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    changed = device.last_config_sha256 != sha256
    now = datetime.now(UTC)

    device.last_backup_at = now
    device.last_backup_ok = True
    device.last_backup_error = None

    if not changed:
        return DeviceBackupResult(
            device_id=str(device.id),
            device_name=device.name,
            ok=True,
            changed=False,
            snapshot_id=None,
            sha256=sha256,
            size_bytes=len(raw.encode()),
            error=None,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    # Config changed — build diff vs the most recent stored snapshot.
    prev = (
        db.execute(
            select(DeviceConfigSnapshot)
            .where(DeviceConfigSnapshot.device_id == device.id)
            .order_by(DeviceConfigSnapshot.ts.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )

    diff_text = None
    added = removed = None
    if prev is not None:
        diff_text, added, removed = _unified_diff(prev.raw_config, raw)

    snap = DeviceConfigSnapshot(
        device_id=device.id,
        ts=now,
        trigger_kind=trigger if prev is not None else "initial",
        raw_config=raw,
        size_bytes=len(raw.encode()),
        sha256_hex=sha256,
        line_count=raw.count("\n") + 1,
        prev_snapshot_id=prev.id if prev is not None else None,
        diff_from_prev=diff_text,
        diff_lines_added=added,
        diff_lines_removed=removed,
        captured_by=captured_by,
    )
    db.add(snap)
    device.last_config_sha256 = sha256
    db.flush()

    # Notification + webhook fan-out — change-detected event
    subject = f"Config change on {device.name} (+{added or 0}/-{removed or 0})"
    body = (
        f"Device: {device.name} ({device.kind} @ {device.mgmt_host})\n"
        f"Trigger: {trigger}\n"
        f"Lines added: {added or 0}\nLines removed: {removed or 0}\n"
        f"Snapshot id: {snap.id}\n\n"
        f"{(diff_text or '')[:4000]}"
    )
    payload = {
        "device_id": str(device.id),
        "device_name": device.name,
        "kind": device.kind,
        "mgmt_host": device.mgmt_host,
        "snapshot_id": str(snap.id),
        "sha256": sha256,
        "lines_added": added,
        "lines_removed": removed,
        "trigger": trigger,
    }
    try:
        from app.notifications.dispatcher import dispatch

        dispatch(db, event_kind="device.config_changed", subject=subject, body=body, payload=payload)
    except Exception:
        pass
    try:
        from app.webhooks.dispatcher import fanout

        fanout(db, event="device.config_changed", payload=payload, subject=subject, body=body)
    except Exception:
        pass

    audit(
        db,
        action="device.config.snapshot",
        target_type="network_device",
        target_key=device.name,
        payload={
            "snapshot_id": str(snap.id),
            "sha256": sha256,
            "lines_added": added,
            "lines_removed": removed,
            "trigger": trigger,
        },
    )

    import time as _time

    return DeviceBackupResult(
        device_id=str(device.id),
        device_name=device.name,
        ok=True,
        changed=True,
        snapshot_id=str(snap.id),
        sha256=sha256,
        size_bytes=len(raw.encode()),
        error=None,
        duration_ms=int((_time.monotonic() - t0) * 1000),
    )


def backup_all(
    db: OrmSession,
    *,
    trigger: str = "scheduled",
    captured_by: uuid.UUID | None = None,
    only_device_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Run backup_device for every enabled + auto_backup device (or a single
    device when only_device_id is supplied). Records a DeviceBackupRun row
    with aggregate counts."""
    started = datetime.now(UTC)
    run = DeviceBackupRun(
        started_at=started,
        trigger_kind=trigger,
    )
    db.add(run)
    db.flush()

    q = select(NetworkDevice).where(NetworkDevice.enabled.is_(True))
    if only_device_id is not None:
        q = q.where(NetworkDevice.id == only_device_id)
    else:
        q = q.where(NetworkDevice.auto_backup.is_(True))

    devices = db.execute(q).scalars().all()
    results: list[DeviceBackupResult] = []
    for d in devices:
        r = backup_device(db, d, trigger=trigger, captured_by=captured_by)
        results.append(r)

    run.completed_at = datetime.now(UTC)
    run.devices_attempted = len(results)
    run.devices_ok = sum(1 for r in results if r.ok)
    run.devices_changed = sum(1 for r in results if r.changed)
    run.devices_failed = sum(1 for r in results if not r.ok)
    run.status = "ok" if run.devices_failed == 0 else "partial" if run.devices_ok else "failed"

    audit(
        db,
        action="device.backup.run",
        target_type="device_backup_run",
        target_key=str(run.id),
        payload={
            "trigger": trigger,
            "attempted": run.devices_attempted,
            "ok": run.devices_ok,
            "changed": run.devices_changed,
            "failed": run.devices_failed,
        },
    )

    return {
        "run_id": str(run.id),
        "started_at": started.isoformat(),
        "completed_at": run.completed_at.isoformat(),
        "trigger": trigger,
        "attempted": run.devices_attempted,
        "ok": run.devices_ok,
        "changed": run.devices_changed,
        "failed": run.devices_failed,
        "status": run.status,
        "results": [
            {
                "device_id": r.device_id,
                "device_name": r.device_name,
                "ok": r.ok,
                "changed": r.changed,
                "snapshot_id": r.snapshot_id,
                "sha256": r.sha256,
                "size_bytes": r.size_bytes,
                "error": r.error,
                "duration_ms": r.duration_ms,
            }
            for r in results
        ],
    }

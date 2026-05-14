from __future__ import annotations

from datetime import UTC, datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.admin.integrations_routes import _delete_secret, _store_secret
from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.devices.backup import backup_device as _backup_device
from app.models.device import (
    DeviceBackupRun,
    DeviceConfigSnapshot,
    NetworkDevice,
)
from app.models.user import User

router = APIRouter(prefix="/admin/devices", tags=["admin-devices"])


_ALLOWED_KINDS = (
    # Cisco
    "cisco_ios",
    "cisco_iosxe",
    "cisco_iosxr",
    "cisco_nxos",
    "cisco_asa",
    "cisco_wlc",
    "cisco_s300",
    # Other enterprise
    "juniper_junos",
    "arista_eos",
    "palo_alto",
    "fortinet",
    "huawei",
    "aruba_aoscx",
    "aruba_os",
    "hp_procurve",
    "hp_comware",
    "dell_os10",
    "dell_force10",
    "dell_powerconnect",
    "extreme_exos",
    "brocade_fastiron",
    # ADC
    "f5_tmsh",
    "citrix_netscaler",
    # Firewalls
    "sonicwall",
    "pfsense",
    "opnsense",
    "sophos",
    # SoHo / open-source
    "mikrotik",
    "ubiquiti_edge",
    "ubiquiti_unifi",
    "vyos",
    # NAS
    "synology",
    "qnap",
    # Generic
    "generic_ssh",
)


def _serialize(d: NetworkDevice, *, include_tags: bool = True) -> dict:
    return {
        "id": str(d.id),
        "name": d.name,
        "description": d.description,
        "kind": d.kind,
        "mgmt_host": d.mgmt_host,
        "mgmt_port": d.mgmt_port,
        "username": d.username,
        "has_secret": d.secret_id is not None,
        "has_enable_secret": d.enable_secret_id is not None,
        "enabled": d.enabled,
        "auto_backup": d.auto_backup,
        "retain_snapshots_count": d.retain_snapshots_count,
        "tags": list(d.tags or []) if include_tags else [],
        "site": d.site,
        "last_backup_at": d.last_backup_at.isoformat() if d.last_backup_at else None,
        "last_backup_ok": d.last_backup_ok,
        "last_backup_error": d.last_backup_error,
        "last_config_sha256": d.last_config_sha256,
        "config": d.config or {},
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "updated_at": d.updated_at.isoformat() if d.updated_at else None,
    }


# ============================================================================
# CRUD
# ============================================================================
@router.get("")
async def list_devices(
    user: User = Depends(require_permission("admin.devices.view")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = db.execute(select(NetworkDevice).order_by(NetworkDevice.name)).scalars().all()
    return [_serialize(d) for d in rows]


@router.get("/kinds")
async def list_kinds(
    user: User = Depends(require_permission("admin.devices.view")),
) -> list[str]:
    return list(_ALLOWED_KINDS)


class DeviceIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str | None = Field(None, max_length=1024)
    kind: str = Field(..., min_length=1, max_length=32)
    mgmt_host: str = Field(..., min_length=1, max_length=253)
    mgmt_port: int = Field(22, ge=1, le=65535)
    username: str | None = Field(None, max_length=64)
    password: str | None = Field(None, max_length=4096)
    enable_password: str | None = Field(None, max_length=4096)
    enabled: bool = True
    auto_backup: bool = True
    retain_snapshots_count: int = Field(50, ge=1, le=10000)
    tags: list[str] = Field(default_factory=list)
    site: str | None = Field(None, max_length=64)
    config: dict = Field(default_factory=dict)


@router.post("", status_code=201)
async def create_device(
    request: Request,
    body: DeviceIn,
    user: User = Depends(require_permission("admin.devices.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.kind not in _ALLOWED_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {_ALLOWED_KINDS}")

    secret_id = None
    enable_secret_id = None
    if body.password:
        secret_id = _store_secret(
            db,
            name=f"device:{body.name}",
            plaintext=body.password,
            category="password",
            owner_scope="system",
            created_by=user.id,
        )
    if body.enable_password:
        enable_secret_id = _store_secret(
            db,
            name=f"device-enable:{body.name}",
            plaintext=body.enable_password,
            category="password",
            owner_scope="system",
            created_by=user.id,
        )

    now = datetime.now(UTC)
    d = NetworkDevice(
        name=body.name,
        description=body.description,
        kind=body.kind,
        mgmt_host=body.mgmt_host,
        mgmt_port=body.mgmt_port,
        username=body.username,
        secret_id=secret_id,
        enable_secret_id=enable_secret_id,
        enabled=body.enabled,
        auto_backup=body.auto_backup,
        retain_snapshots_count=body.retain_snapshots_count,
        tags=list(body.tags),
        site=body.site,
        config=body.config,
        created_by=user.id,
        created_at=now,
        updated_at=now,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    audit(
        db,
        user_id=user.id,
        action="device.create",
        target_type="network_device",
        target_key=d.name,
        payload={"kind": d.kind, "mgmt_host": d.mgmt_host, "has_secret": secret_id is not None},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"id": str(d.id)}


class DevicePatch(BaseModel):
    description: str | None = Field(None, max_length=1024)
    mgmt_host: str | None = Field(None, max_length=253)
    mgmt_port: int | None = Field(None, ge=1, le=65535)
    username: str | None = Field(None, max_length=64)
    password: str | None = Field(None, max_length=4096)
    enable_password: str | None = Field(None, max_length=4096)
    clear_password: bool = False
    clear_enable_password: bool = False
    enabled: bool | None = None
    auto_backup: bool | None = None
    retain_snapshots_count: int | None = Field(None, ge=1, le=10000)
    tags: list[str] | None = None
    site: str | None = Field(None, max_length=64)
    config: dict | None = None


@router.patch("/{device_id}")
async def update_device(
    request: Request,
    device_id: uuid.UUID,
    body: DevicePatch,
    user: User = Depends(require_permission("admin.devices.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    d = db.get(NetworkDevice, device_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")

    changed: dict = {}
    for field in (
        "description",
        "mgmt_host",
        "mgmt_port",
        "username",
        "enabled",
        "auto_backup",
        "retain_snapshots_count",
        "site",
    ):
        v = getattr(body, field)
        if v is not None:
            setattr(d, field, v)
            changed[field] = v
    if body.tags is not None:
        d.tags = list(body.tags)
        changed["tags"] = list(body.tags)
    if body.config is not None:
        d.config = body.config
        changed["config_keys"] = sorted(body.config.keys())

    if body.clear_password:
        _delete_secret(db, d.secret_id)
        d.secret_id = None
        changed["password"] = "cleared"
    elif body.password:
        _delete_secret(db, d.secret_id)
        d.secret_id = _store_secret(
            db,
            name=f"device:{d.name}",
            plaintext=body.password,
            category="password",
            owner_scope="system",
            created_by=user.id,
        )
        changed["password"] = "rotated"

    if body.clear_enable_password:
        _delete_secret(db, d.enable_secret_id)
        d.enable_secret_id = None
        changed["enable_password"] = "cleared"
    elif body.enable_password:
        _delete_secret(db, d.enable_secret_id)
        d.enable_secret_id = _store_secret(
            db,
            name=f"device-enable:{d.name}",
            plaintext=body.enable_password,
            category="password",
            owner_scope="system",
            created_by=user.id,
        )
        changed["enable_password"] = "rotated"

    d.updated_at = datetime.now(UTC)
    db.commit()
    audit(
        db,
        user_id=user.id,
        action="device.update",
        target_type="network_device",
        target_key=d.name,
        payload=changed,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"ok": True}


@router.delete("/{device_id}", status_code=204, response_model=None)
async def delete_device(
    request: Request,
    device_id: uuid.UUID,
    user: User = Depends(require_permission("admin.devices.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    d = db.get(NetworkDevice, device_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    name = d.name
    _delete_secret(db, d.secret_id)
    _delete_secret(db, d.enable_secret_id)
    db.delete(d)
    db.commit()
    audit(
        db,
        user_id=user.id,
        action="device.delete",
        target_type="network_device",
        target_key=name,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


# ============================================================================
# Backup triggers + snapshot history
# ============================================================================
@router.post("/{device_id}/backup", status_code=202)
async def backup_now(
    request: Request,
    device_id: uuid.UUID,
    user: User = Depends(require_permission("admin.devices.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    d = db.get(NetworkDevice, device_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    result = _backup_device(db, d, trigger="manual", captured_by=user.id)
    db.commit()
    audit(
        db,
        user_id=user.id,
        action="device.backup.manual",
        target_type="network_device",
        target_key=d.name,
        payload={"ok": result.ok, "changed": result.changed, "sha256": result.sha256, "error": result.error},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        outcome="ok" if result.ok else "error",
    )
    return {
        "ok": result.ok,
        "changed": result.changed,
        "snapshot_id": result.snapshot_id,
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
        "error": result.error,
        "duration_ms": result.duration_ms,
    }


@router.get("/{device_id}/snapshots")
async def list_snapshots(
    device_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=1000),
    user: User = Depends(require_permission("admin.devices.view")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(
            select(DeviceConfigSnapshot)
            .where(DeviceConfigSnapshot.device_id == device_id)
            .order_by(DeviceConfigSnapshot.ts.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": str(s.id),
            "ts": s.ts.isoformat(),
            "trigger_kind": s.trigger_kind,
            "size_bytes": s.size_bytes,
            "sha256_hex": s.sha256_hex,
            "line_count": s.line_count,
            "prev_snapshot_id": str(s.prev_snapshot_id) if s.prev_snapshot_id else None,
            "diff_lines_added": s.diff_lines_added,
            "diff_lines_removed": s.diff_lines_removed,
            "has_diff": bool(s.diff_from_prev),
        }
        for s in rows
    ]


@router.get("/{device_id}/snapshots/{snapshot_id}")
async def get_snapshot(
    device_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    user: User = Depends(require_permission("admin.devices.view")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    s = db.get(DeviceConfigSnapshot, snapshot_id)
    if s is None or s.device_id != device_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "snapshot not found")
    return {
        "id": str(s.id),
        "device_id": str(s.device_id),
        "ts": s.ts.isoformat(),
        "trigger_kind": s.trigger_kind,
        "raw_config": s.raw_config,
        "size_bytes": s.size_bytes,
        "sha256_hex": s.sha256_hex,
        "line_count": s.line_count,
        "prev_snapshot_id": str(s.prev_snapshot_id) if s.prev_snapshot_id else None,
        "diff_from_prev": s.diff_from_prev,
        "diff_lines_added": s.diff_lines_added,
        "diff_lines_removed": s.diff_lines_removed,
    }


@router.get("/{device_id}/snapshots/{a}/diff/{b}")
async def diff_snapshots(
    device_id: uuid.UUID,
    a: uuid.UUID,
    b: uuid.UUID,
    user: User = Depends(require_permission("admin.devices.view")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    sa = db.get(DeviceConfigSnapshot, a)
    sb = db.get(DeviceConfigSnapshot, b)
    if sa is None or sb is None or sa.device_id != device_id or sb.device_id != device_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "snapshot(s) not found")
    from app.devices.backup import _unified_diff

    diff_text, added, removed = _unified_diff(sa.raw_config, sb.raw_config)
    return {
        "from": {"id": str(sa.id), "ts": sa.ts.isoformat(), "sha256": sa.sha256_hex},
        "to": {"id": str(sb.id), "ts": sb.ts.isoformat(), "sha256": sb.sha256_hex},
        "diff": diff_text,
        "lines_added": added,
        "lines_removed": removed,
    }


# ============================================================================
# Backup run history
# ============================================================================
@router.get("/runs")
async def list_runs(
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(require_permission("admin.devices.view")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(select(DeviceBackupRun).order_by(DeviceBackupRun.started_at.desc()).limit(limit))
        .scalars()
        .all()
    )
    return [
        {
            "id": str(r.id),
            "started_at": r.started_at.isoformat(),
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "trigger_kind": r.trigger_kind,
            "devices_attempted": r.devices_attempted,
            "devices_ok": r.devices_ok,
            "devices_changed": r.devices_changed,
            "devices_failed": r.devices_failed,
            "status": r.status,
        }
        for r in rows
    ]

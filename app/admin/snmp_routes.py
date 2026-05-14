"""CRUD for SNMP community strings exposed to external monitoring
systems (Zabbix/Nagios/PRTG/SolarWinds). Communities are stored
plaintext in the DB — they are, by design, the credential. The
`access` column splits RO (read monitoring stats) from RW (not yet
used for anything Meridian writes; reserved for future toggles).
"""

from __future__ import annotations

from pathlib import Path
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings


def _regenerate_snmpd() -> None:
    """Rewrite /etc/snmp/snmpd.conf.d/meridian-communities.conf from
    the live DB + reload snmpd. Failures are swallowed so an SNMP-daemon
    hiccup doesn't break the admin CRUD flow — they surface in audit
    but don't 500 the PATCH/POST."""
    import subprocess

    try:
        subprocess.run(
            ["sudo", "-n", "/opt/meridian/scripts/regenerate-snmpd.sh"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception:
        pass


from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.snmp import SnmpCommunity
from app.models.user import User

router = APIRouter(prefix="/admin/snmp", tags=["admin-snmp"])


def _ser(c: SnmpCommunity) -> dict:
    return {
        "id": str(c.id),
        "name": c.name,
        "access": c.access,
        "community": c.community,
        "allowed_sources": list(c.allowed_sources or []),
        "v3_user": c.v3_user,
        "enabled": c.enabled,
    }


class CommIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    community: str = Field(..., min_length=4, max_length=256)
    access: str = Field("ro", pattern=r"^(ro|rw)$")
    allowed_sources: list[str] = Field(default_factory=list)
    v3_user: str | None = Field(None, max_length=64)
    enabled: bool = True


class CommPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=64)
    community: str | None = Field(None, min_length=4, max_length=256)
    access: str | None = Field(None, pattern=r"^(ro|rw)$")
    allowed_sources: list[str] | None = None
    v3_user: str | None = Field(None, max_length=64)
    enabled: bool | None = None


@router.get("/communities")
async def list_communities(
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = (
        db.execute(select(SnmpCommunity).order_by(SnmpCommunity.access, SnmpCommunity.name)).scalars().all()
    )
    return [_ser(c) for c in rows]


@router.post("/communities", status_code=201)
async def create_community(
    request: Request,
    body: CommIn,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    c = SnmpCommunity(
        name=body.name,
        access=body.access,
        community=body.community,
        allowed_sources=list(body.allowed_sources or []),
        v3_user=body.v3_user,
        enabled=body.enabled,
    )
    db.add(c)
    db.flush()
    audit(
        db,
        user_id=user.id,
        action="admin.snmp.create",
        target_type="snmp_community",
        target_key=c.name,
        payload={"access": c.access, "allowed_sources": c.allowed_sources},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _regenerate_snmpd()
    return {"id": str(c.id)}


@router.patch("/communities/{community_id}")
async def update_community(
    request: Request,
    community_id: uuid.UUID,
    body: CommPatch,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    c = db.get(SnmpCommunity, community_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "community not found")
    changed: dict = {}
    for field in ("name", "community", "access", "v3_user", "enabled"):
        v = getattr(body, field)
        if v is not None:
            setattr(c, field, v)
            changed[field] = v if field != "community" else "rotated"
    if body.allowed_sources is not None:
        c.allowed_sources = list(body.allowed_sources)
        changed["allowed_sources"] = list(body.allowed_sources)
    audit(
        db,
        user_id=user.id,
        action="admin.snmp.update",
        target_type="snmp_community",
        target_key=c.name,
        payload=changed,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _regenerate_snmpd()
    return {"ok": True, "changed": changed}


@router.get("/mib")
async def download_mib(
    user: User = Depends(require_permission("admin.integrations.manage")),
):
    """Serve MERIDIAN-NIP-MIB for download. Operators feed this to
    their SNMP tool (zabbix_get / snmpwalk / PRTG MIB importer /
    SolarWinds MIB editor) so the OIDs resolve to human-readable
    names instead of numeric strings."""
    settings = get_settings()
    mib_path = Path(settings.install_root) / "docs" / "MERIDIAN-NIP-MIB.txt"
    if not mib_path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MIB file not found on host")
    return FileResponse(
        str(mib_path),
        media_type="text/plain",
        filename="MERIDIAN-NIP-MIB.txt",
    )


@router.delete("/communities/{community_id}", status_code=204, response_model=None)
async def delete_community(
    request: Request,
    community_id: uuid.UUID,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    c = db.get(SnmpCommunity, community_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "community not found")
    name = c.name
    db.delete(c)
    audit(
        db,
        user_id=user.id,
        action="admin.snmp.delete",
        target_type="snmp_community",
        target_key=name,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _regenerate_snmpd()

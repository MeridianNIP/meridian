from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.directory import DirectoryIntegration
from app.models.threat_intel_integration import ThreatIntelIntegration
from app.models.threat_intel_source import ThreatIntelSource
from app.models.user import User
from app.secrets_vault.vault import encrypt_field


router = APIRouter(prefix="/admin/integrations", tags=["admin-integrations"])


_ALLOWED_DIR = (
    "active_directory", "entra_id", "ldap_generic",
    "samba_ad_dc", "freeipa", "ds_389", "openldap", "jumpcloud",
)


def _store_secret(
    db: OrmSession, *, name: str, plaintext: str, category: str,
    owner_scope: str, created_by: uuid.UUID,
) -> uuid.UUID:
    """Encrypt plaintext and insert a row in secrets. Returns the secret id.

    Ciphertext is split into (nonce, body) columns to match the schema. The
    vault module always prepends a 12-byte nonce.
    """
    blob = encrypt_field(plaintext.encode("utf-8"), domain=b"vault")
    nonce, body = blob[:12], blob[12:]
    now = datetime.now(timezone.utc)
    row_id = uuid.uuid4()
    db.execute(text("""
        INSERT INTO secrets (id, name, category, ciphertext, nonce,
                             owner_scope, created_by, created_at, updated_at)
        VALUES (:id, :name, :category, :ct, :nonce, :scope, :by, :now, :now)
    """), {
        "id": row_id, "name": name, "category": category,
        "ct": body, "nonce": nonce, "scope": owner_scope,
        "by": created_by, "now": now,
    })
    return row_id


def _delete_secret(db: OrmSession, secret_id: uuid.UUID | None) -> None:
    if secret_id is None:
        return
    db.execute(text("DELETE FROM secrets WHERE id = :id"), {"id": secret_id})



# ============================================================================
# Directory integrations (LDAP / AD / Entra)
# ============================================================================
class DirIn(BaseModel):
    kind: str = Field(..., min_length=1, max_length=32)
    name: str = Field(..., min_length=1, max_length=64)
    fqdn: str | None = Field(None, max_length=253)
    primary_uri: str = Field(..., min_length=1, max_length=512)  # ldaps://host:636
    fallback_uri: str | None = Field(None, max_length=512)
    base_dn: str | None = Field(None, max_length=256)
    bind_account: str | None = Field(None, max_length=256)
    bind_password: str | None = Field(None, max_length=4096)
    auth_method: str = Field("password", max_length=32)
    ca_cert_path: str | None = Field(None, max_length=512)
    query_timeout_s: int = Field(10, ge=1, le=60)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


@router.get("/directory")
async def list_dir(
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = db.execute(
        select(DirectoryIntegration).order_by(DirectoryIntegration.name)
    ).scalars().all()
    return [{
        "id": str(i.id), "kind": i.kind, "name": i.name, "enabled": i.enabled,
        "fqdn": i.fqdn, "primary_uri": i.primary_uri, "fallback_uri": i.fallback_uri,
        "base_dn": i.base_dn, "bind_account": i.bind_account,
        "auth_method": i.auth_method, "ca_cert_path": i.ca_cert_path,
        "query_timeout_s": i.query_timeout_s, "config": i.config or {},
        "has_secret": i.bind_secret_id is not None,
        "last_tested_at": i.last_tested_at.isoformat() if i.last_tested_at else None,
        "last_test_ok": i.last_test_ok,
        "last_test_error": i.last_test_error,
    } for i in rows]


@router.post("/directory", status_code=201)
async def create_dir(
    request: Request,
    body: DirIn,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.kind not in _ALLOWED_DIR:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {_ALLOWED_DIR}")
    sec_id = None
    if body.bind_password:
        sec_id = _store_secret(db, name=f"directory:{body.name}",
                               plaintext=body.bind_password,
                               category="password", owner_scope="system",
                               created_by=user.id)
    integ = DirectoryIntegration(
        kind=body.kind, name=body.name, enabled=body.enabled,
        fqdn=body.fqdn, primary_uri=body.primary_uri,
        fallback_uri=body.fallback_uri, base_dn=body.base_dn,
        bind_account=body.bind_account, bind_secret_id=sec_id,
        auth_method=body.auth_method, ca_cert_path=body.ca_cert_path,
        query_timeout_s=body.query_timeout_s, config=body.config,
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    audit(db, user_id=user.id, action="admin.integration.create",
          target_type="directory", target_key=integ.name,
          payload={"kind": integ.kind, "primary_uri": integ.primary_uri,
                   "base_dn": integ.base_dn, "has_secret": sec_id is not None},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"id": str(integ.id)}


class DirPatch(BaseModel):
    fqdn: str | None = Field(None, max_length=253)
    primary_uri: str | None = Field(None, max_length=512)
    fallback_uri: str | None = Field(None, max_length=512)
    base_dn: str | None = Field(None, max_length=256)
    bind_account: str | None = Field(None, max_length=256)
    bind_password: str | None = Field(None, max_length=4096)
    clear_password: bool = False
    auth_method: str | None = Field(None, max_length=32)
    ca_cert_path: str | None = Field(None, max_length=512)
    query_timeout_s: int | None = Field(None, ge=1, le=60)
    enabled: bool | None = None
    config: dict[str, Any] | None = None


@router.patch("/directory/{integ_id}")
async def update_dir(
    request: Request,
    integ_id: uuid.UUID,
    body: DirPatch,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = db.get(DirectoryIntegration, integ_id)
    if integ is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "directory integration not found")
    changed: dict = {}
    for field in ("fqdn", "primary_uri", "fallback_uri", "base_dn",
                  "bind_account", "auth_method", "ca_cert_path",
                  "query_timeout_s", "enabled"):
        v = getattr(body, field)
        if v is not None:
            setattr(integ, field, v)
            changed[field] = v
    if body.config is not None:
        integ.config = body.config
        changed["config_keys"] = sorted(body.config.keys())
    if body.clear_password:
        _delete_secret(db, integ.bind_secret_id)
        integ.bind_secret_id = None
        changed["bind_password"] = "cleared"
    elif body.bind_password:
        _delete_secret(db, integ.bind_secret_id)
        integ.bind_secret_id = _store_secret(
            db, name=f"directory:{integ.name}", plaintext=body.bind_password,
            category="password", owner_scope="system", created_by=user.id,
        )
        changed["bind_password"] = "rotated"
    db.commit()
    audit(db, user_id=user.id, action="admin.integration.update",
          target_type="directory", target_key=integ.name,
          payload=changed, ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}


@router.delete("/directory/{integ_id}", status_code=204, response_model=None)
async def delete_dir(
    request: Request,
    integ_id: uuid.UUID,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    integ = db.get(DirectoryIntegration, integ_id)
    if integ is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "directory integration not found")
    name = integ.name
    _delete_secret(db, integ.bind_secret_id)
    db.delete(integ)
    db.commit()
    audit(db, user_id=user.id, action="admin.integration.delete",
          target_type="directory", target_key=name,
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))


# ============================================================================
# Threat Intel integrations (external API keys: AbuseIPDB, GreyNoise,
# VirusTotal, URLScan, Shodan, Censys). Same vault pattern as Directory.
# ============================================================================
_ALLOWED_TI = ("abuseipdb", "greynoise", "virustotal", "urlscan", "shodan", "censys")


class TiIn(BaseModel):
    kind: str = Field(..., min_length=1, max_length=32)
    name: str = Field(..., min_length=1, max_length=64)
    api_key: str = Field(..., min_length=1, max_length=4096)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class TiPatch(BaseModel):
    api_key: str | None = Field(None, min_length=1, max_length=4096)
    enabled: bool | None = None
    config: dict[str, Any] | None = None


@router.get("/threat-intel")
async def list_ti(
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = db.execute(
        select(ThreatIntelIntegration).order_by(
            ThreatIntelIntegration.kind, ThreatIntelIntegration.name)
    ).scalars().all()
    return [{
        "id": str(i.id), "kind": i.kind, "name": i.name, "enabled": i.enabled,
        "config": i.config or {},
        "has_key": i.api_key_secret_id is not None,
        "last_tested_at": i.last_tested_at.isoformat() if i.last_tested_at else None,
        "last_test_ok": i.last_test_ok,
        "last_test_error": i.last_test_error,
    } for i in rows]


@router.post("/threat-intel", status_code=201)
async def create_ti(
    request: Request,
    body: TiIn,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if body.kind not in _ALLOWED_TI:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {_ALLOWED_TI}")
    sec_id = _store_secret(db, name=f"threat_intel:{body.kind}:{body.name}",
                           plaintext=body.api_key, category="api_token",
                           owner_scope="system", created_by=user.id)
    integ = ThreatIntelIntegration(
        kind=body.kind, name=body.name, enabled=body.enabled,
        api_key_secret_id=sec_id, config=body.config,
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    audit(db, user_id=user.id, action="admin.integration.create",
          target_type="threat_intel", target_key=f"{integ.kind}:{integ.name}",
          payload={"kind": integ.kind, "enabled": integ.enabled},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"id": str(integ.id)}


@router.patch("/threat-intel/{integ_id}")
async def update_ti(
    request: Request,
    integ_id: uuid.UUID,
    body: TiPatch,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    integ = db.get(ThreatIntelIntegration, integ_id)
    if integ is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "threat-intel integration not found")
    changed: dict = {}
    if body.enabled is not None:
        integ.enabled = body.enabled
        changed["enabled"] = body.enabled
    if body.config is not None:
        integ.config = body.config
        changed["config_keys"] = sorted(body.config.keys())
    if body.api_key:
        _delete_secret(db, integ.api_key_secret_id)
        integ.api_key_secret_id = _store_secret(
            db, name=f"threat_intel:{integ.kind}:{integ.name}",
            plaintext=body.api_key, category="api_token",
            owner_scope="system", created_by=user.id,
        )
        changed["api_key"] = "rotated"
    db.commit()
    audit(db, user_id=user.id, action="admin.integration.update",
          target_type="threat_intel", target_key=f"{integ.kind}:{integ.name}",
          payload=changed, ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}


@router.delete("/threat-intel/{integ_id}", status_code=204, response_model=None)
async def delete_ti(
    request: Request,
    integ_id: uuid.UUID,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    integ = db.get(ThreatIntelIntegration, integ_id)
    if integ is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "threat-intel integration not found")
    tag = f"{integ.kind}:{integ.name}"
    _delete_secret(db, integ.api_key_secret_id)
    db.delete(integ)
    db.commit()
    audit(db, user_id=user.id, action="admin.integration.delete",
          target_type="threat_intel", target_key=tag,
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))


# ============================================================================
# Threat Intel source catalog — per-provider on/off + config overrides.
# Read-only list of everything the UI can show; PATCH to flip enabled or
# tweak base_url / timeout_s / auth_header.
# ============================================================================
class TiSourcePatch(BaseModel):
    enabled: bool | None = None
    config: dict[str, Any] | None = None


@router.get("/threat-intel-sources")
async def list_ti_sources(
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = db.execute(
        select(ThreatIntelSource).order_by(
            ThreatIntelSource.category, ThreatIntelSource.display_name)
    ).scalars().all()
    return [{
        "source_key":   s.source_key,
        "display_name": s.display_name,
        "category":     s.category,
        "requires_key": s.requires_key,
        "enabled":      s.enabled,
        "config":       s.config or {},
    } for s in rows]


@router.patch("/threat-intel-sources/{source_key}")
async def update_ti_source(
    request: Request,
    source_key: str,
    body: TiSourcePatch,
    user: User = Depends(require_permission("admin.integrations.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    src = db.get(ThreatIntelSource, source_key)
    if src is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "threat-intel source not found")
    changed: dict = {}
    if body.enabled is not None:
        src.enabled = body.enabled
        changed["enabled"] = body.enabled
    if body.config is not None:
        src.config = body.config
        changed["config_keys"] = sorted(body.config.keys())
    db.commit()
    audit(db, user_id=user.id, action="admin.integration.update",
          target_type="threat_intel_source", target_key=source_key,
          payload=changed, ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}

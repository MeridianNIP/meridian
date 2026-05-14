from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user, require_permission
from app.certs.csr import generate as generate_csr
from app.certs.parser import parse_pem
from app.certs.parser import normalize_key_type
from app.certs.watchlist import fetch_remote_cert
from app.db import fastapi_dep_db
from app.models.cert import Certificate, CertEvent, CsrRequest
from app.models.user import User
from app.secrets_vault.vault import encrypt_field


router = APIRouter(prefix="/certs", tags=["certs"])


def _log_event(db: OrmSession, cert_id: uuid.UUID, event: str,
               actor_id: uuid.UUID | None = None, detail: dict | None = None) -> None:
    db.add(CertEvent(
        cert_id=cert_id, event=event, ts=datetime.now(timezone.utc),
        actor_id=actor_id, detail=detail,
    ))


class CertOut(BaseModel):
    id: uuid.UUID
    cert_type: str
    common_name: str
    sans: list[str]
    issuer: str | None
    valid_until: datetime | None
    days_remaining: int | None
    auto_renew: bool
    managed: bool
    key_type: str | None

    class Config:
        from_attributes = True


@router.get("/")
async def list_certs(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = db.execute(select(Certificate).order_by(Certificate.valid_until)).scalars().all()
    now = datetime.now(timezone.utc)
    out: list[dict] = []
    for c in rows:
        days = None
        if c.valid_until:
            days = max(0, (c.valid_until - now).days)
        out.append({
            "id": str(c.id),
            "cert_type": c.cert_type,
            "common_name": c.common_name,
            "sans": list(c.sans or []),
            "issuer": c.issuer,
            "serial_hex": c.serial_hex,
            "fingerprint_sha256": c.fingerprint_sha256,
            "valid_from": c.valid_from.isoformat() if c.valid_from else None,
            "valid_until": c.valid_until.isoformat() if c.valid_until else None,
            "days_remaining": days,
            "auto_renew": c.auto_renew,
            "managed": c.managed,
            "key_type": c.key_type,
            "key_size": c.key_size,
            "signature_alg": c.signature_alg,
            "renew_before_days": c.renew_before_days,
            "notify_channels": [str(uid) for uid in (c.notify_channels or [])],
            "last_renewed_at": c.last_renewed_at.isoformat() if c.last_renewed_at else None,
            "last_renew_status": c.last_renew_status,
            "ocsp_stapled": c.ocsp_stapled,
            "ct_logged": c.ct_logged,
            "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
        })
    return out


class WatchlistAdd(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(443, ge=1, le=65535)
    notify_channels: list[uuid.UUID] = Field(default_factory=list)
    renew_before_days: int = Field(30, ge=1, le=365)


class CertPatch(BaseModel):
    notify_channels: list[uuid.UUID] | None = None
    renew_before_days: int | None = Field(None, ge=1, le=365)
    auto_renew: bool | None = None


@router.post("/watchlist", status_code=201)
async def watchlist_add(
    request: Request,
    body: WatchlistAdd,
    user: User = Depends(require_permission("cert.request")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        info = await fetch_remote_cert(body.host, body.port)
    except (OSError, ValueError) as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"cert fetch failed: {e}")

    cert = Certificate(
        cert_type="monitored",
        common_name=info.common_name or body.host,
        sans=info.sans,
        issuer=info.issuer,
        serial_hex=info.serial_hex,
        fingerprint_sha256=info.fingerprint_sha256,
        valid_from=info.valid_from,
        valid_until=info.valid_until,
        # DB stores cert_key_type enum values (rsa2048/ecdsa_p256/…); the
        # parser returns human-readable strings ("RSA", "ECDSA secp256r1").
        # Normalize, falling back to NULL if the real cert uses a key
        # flavour we don't enumerate (e.g. RSA-1024 legacy, odd curves).
        key_type=normalize_key_type(info.key_type, info.key_size),
        key_size=info.key_size,
        signature_alg=info.signature_alg,
        leaf_pem=info.leaf_pem,
        auto_renew=False,
        managed=False,
        notify_channels=body.notify_channels or [],
        renew_before_days=body.renew_before_days,
    )
    db.add(cert)
    db.flush()
    _log_event(db, cert.id, "watchlist.added", actor_id=user.id,
               detail={"host": body.host, "port": body.port})
    audit(db, user_id=user.id, action="cert.watchlist.add",
          target_type="cert", target_key=cert.common_name,
          payload={"host": body.host, "days_remaining": info.days_remaining},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"id": str(cert.id), "common_name": cert.common_name,
            "days_remaining": info.days_remaining}


class UploadBody(BaseModel):
    leaf_pem: str
    chain_pem: str | None = None
    cert_type: str = "internal"


@router.post("/upload", status_code=201)
async def upload_cert(
    request: Request,
    body: UploadBody,
    user: User = Depends(require_permission("cert.request")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        info = parse_pem(body.leaf_pem.encode())
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    if body.cert_type not in ("portal", "monitored", "client_mtls", "internal"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cert_type invalid")

    cert = Certificate(
        cert_type=body.cert_type,
        common_name=info.common_name,
        sans=info.sans,
        issuer=info.issuer,
        serial_hex=info.serial_hex,
        fingerprint_sha256=info.fingerprint_sha256,
        valid_from=info.valid_from,
        valid_until=info.valid_until,
        key_type=normalize_key_type(info.key_type, info.key_size),
        key_size=info.key_size,
        signature_alg=info.signature_alg,
        leaf_pem=info.leaf_pem,
        chain_pem=body.chain_pem,
    )
    db.add(cert)
    db.flush()
    _log_event(db, cert.id, "uploaded", actor_id=user.id,
               detail={"cert_type": body.cert_type})
    audit(db, user_id=user.id, action="cert.upload",
          target_type="cert", target_key=cert.common_name,
          payload={"cert_type": body.cert_type, "days_remaining": info.days_remaining},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    return {"id": str(cert.id), "common_name": cert.common_name,
            "days_remaining": info.days_remaining}


class CsrBody(BaseModel):
    subject_cn: str = Field(..., min_length=1, max_length=253)
    sans: list[str] = Field(default_factory=list)
    key_type: str = "ecdsa_p256"
    organization: str | None = None
    country: str | None = None


@router.post("/csr", status_code=201)
async def create_csr(
    request: Request,
    body: CsrBody,
    user: User = Depends(require_permission("cert.request")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        gen = generate_csr(
            body.subject_cn, body.sans,
            key_type=body.key_type,
            organization=body.organization, country=body.country,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    # Encrypt the private key into the vault.
    key_secret_id = uuid.uuid4()
    ciphertext = encrypt_field(gen.private_key_pem, domain=b"cert-key")
    db.execute(text("""
        INSERT INTO secrets (id, name, category, description, ciphertext, nonce,
                             key_version, owner_scope, owner_id, created_by)
        VALUES (:id, :name, 'certificate', :desc, :ct, :nonce, 1,
                'user', :owner, :creator)
    """), {
        "id": key_secret_id,
        "name": f"cert-key:{body.subject_cn}:{key_secret_id}",
        "desc": f"Private key for CSR · CN={body.subject_cn} · {body.key_type}",
        # The secrets table splits ciphertext and nonce into two columns; our
        # encrypt_field prepends the nonce, so split them here.
        "ct": ciphertext[12:],
        "nonce": ciphertext[:12],
        "owner": user.id, "creator": user.id,
    })

    csr = CsrRequest(
        id=uuid.uuid4(),
        subject_cn=body.subject_cn,
        sans=body.sans or [body.subject_cn],
        key_type=body.key_type,
        key_secret_id=key_secret_id,
        csr_pem=gen.csr_pem.decode(),
        state="pending",
        created_by=user.id,
    )
    db.add(csr)
    audit(db, user_id=user.id, action="cert.csr.generate",
          target_type="csr", target_key=str(csr.id),
          payload={"cn": body.subject_cn, "sans": body.sans, "key_type": body.key_type},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    return {
        "id": str(csr.id),
        "csr_pem": gen.csr_pem.decode(),
        "key_secret_id": str(key_secret_id),
        "subject_cn": body.subject_cn,
        "key_type": body.key_type,
    }


@router.post("/{cert_id}/refresh")
async def refresh_remote(
    request: Request,
    cert_id: uuid.UUID,
    user: User = Depends(require_permission("cert.request")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    c = db.get(Certificate, cert_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cert not found")
    if c.cert_type != "monitored":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "only monitored (watchlist) certs support remote refresh")

    # Pick a resolvable host: a wildcard CN (e.g. "*.google.com") can't be
    # passed to socket.create_connection, so fall back to the first
    # concrete SAN, or strip the wildcard prefix as a last resort.
    def _refreshable_host(cert: Certificate) -> str:
        cn = cert.common_name or ""
        if cn and not cn.startswith("*"):
            return cn
        for san in (cert.sans or []):
            if san and not san.startswith("*"):
                return san
        if cn.startswith("*."):
            return cn[2:]
        return cn

    host = _refreshable_host(c)
    try:
        info = await fetch_remote_cert(host, 443)
    except (OSError, ValueError) as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"refresh failed for {host}: {e}")

    changed_fingerprint = info.fingerprint_sha256 != c.fingerprint_sha256
    c.issuer = info.issuer
    c.serial_hex = info.serial_hex
    c.fingerprint_sha256 = info.fingerprint_sha256
    c.valid_from = info.valid_from
    c.valid_until = info.valid_until
    c.key_type = normalize_key_type(info.key_type, info.key_size)
    c.key_size = info.key_size
    c.signature_alg = info.signature_alg
    c.leaf_pem = info.leaf_pem

    _log_event(db, c.id, "refreshed", actor_id=user.id,
               detail={"host": host, "fingerprint_changed": changed_fingerprint})
    if changed_fingerprint:
        audit(db, user_id=user.id, action="cert.fingerprint_changed",
              target_type="cert", target_key=c.common_name,
              payload={"new": info.fingerprint_sha256},
              ip=client_ip(request), user_agent=request.headers.get("user-agent"))
        try:
            from app.notifications.dispatcher import dispatch
            dispatch(
                db, event_kind="cert.fingerprint_changed",
                subject=f"[Meridian] cert fingerprint changed: {c.common_name}",
                body=(
                    f"Common name: {c.common_name}\n"
                    f"New fingerprint: {info.fingerprint_sha256}\n"
                    f"Issuer: {info.issuer}\n"
                    f"Valid until: {info.valid_until.isoformat() if info.valid_until else 'unknown'}\n"
                    f"If a rotation wasn't expected, this may indicate a MITM or "
                    f"unplanned re-issue — verify with the asset owner."
                ),
                payload={"cert_id": str(c.id),
                         "fingerprint": info.fingerprint_sha256},
                channel_ids=list(c.notify_channels or []) or None,
            )
        except Exception:  # noqa: BLE001
            pass
    return {
        "ok": True,
        "days_remaining": info.days_remaining,
        "fingerprint_changed": changed_fingerprint,
    }


@router.patch("/{cert_id}")
async def patch_cert(
    request: Request,
    cert_id: uuid.UUID,
    body: CertPatch,
    user: User = Depends(require_permission("cert.request")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    c = db.get(Certificate, cert_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cert not found")
    changed: dict = {}
    if body.notify_channels is not None:
        c.notify_channels = list(body.notify_channels)
        changed["notify_channels"] = len(c.notify_channels)
    if body.renew_before_days is not None:
        c.renew_before_days = body.renew_before_days
        changed["renew_before_days"] = body.renew_before_days
    if body.auto_renew is not None:
        c.auto_renew = body.auto_renew
        changed["auto_renew"] = body.auto_renew
    audit(db, user_id=user.id, action="cert.update",
          target_type="cert", target_key=c.common_name,
          payload=changed,
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    return {"ok": True, "changed": changed}


@router.delete("/{cert_id}", status_code=204, response_model=None)
async def delete_cert(
    request: Request,
    cert_id: uuid.UUID,
    user: User = Depends(require_permission("cert.request")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    c = db.get(Certificate, cert_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cert not found")
    if c.cert_type == "portal":
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "portal cert can't be deleted from UI; rotate via ACME instead")
    name = c.common_name
    db.delete(c)
    audit(db, user_id=user.id, action="cert.delete",
          target_type="cert", target_key=name,
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))

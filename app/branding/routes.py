from __future__ import annotations

from datetime import UTC, datetime
import mimetypes
from pathlib import Path
import re
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.branding.assets import (
    ALLOWED_KINDS,
    get_spec,
    remove_previous,
    save_asset,
)
from app.db import fastapi_dep_db
from app.models.branding import Branding
from app.models.branding import load as load_branding
from app.models.user import User

router = APIRouter(prefix="/branding", tags=["branding"])


_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_THEME_ALLOWED = {"dark", "midnight", "light", "high_contrast"}
_TARGET_ALLOWED = {"_blank", "_self"}


def _serialize(b: Branding) -> dict[str, Any]:
    return {
        "display_name": b.display_name,
        "short_name": b.short_name,
        "support_email": b.support_email,
        "support_url": b.support_url,
        "privacy_url": b.privacy_url,
        "imprint_url": b.imprint_url,
        "default_timezone": b.default_timezone,
        "date_format": b.date_format,
        "logo_path": b.logo_path,
        "favicon_path": b.favicon_path,
        "login_bg_path": b.login_bg_path,
        "pdf_header_path": b.pdf_header_path,
        "theme": b.theme,
        "accent_hex": b.accent_hex,
        "pre_login_warning": b.pre_login_warning,
        "aup_require_first_login": b.aup_require_first_login,
        "aup_reprompt_on_change": b.aup_reprompt_on_change,
        "aup_show_footer_link": b.aup_show_footer_link,
        "email_from_name": b.email_from_name,
        "email_from_address": b.email_from_address,
        "email_signature": b.email_signature,
        "slack_sender_name": b.slack_sender_name,
        "teams_sender_name": b.teams_sender_name,
        "sms_sender_identity": b.sms_sender_identity,
        "pdf_footer_text": b.pdf_footer_text,
        "pdf_watermark": b.pdf_watermark,
        "ssh_motd": b.ssh_motd,
        "ssh_motd_on_every_login": b.ssh_motd_on_every_login,
        "session_idle_timeout_default_min": b.session_idle_timeout_default_min,
        "session_idle_timeout_max_min": b.session_idle_timeout_max_min,
        "session_idle_timeout_options": list(b.session_idle_timeout_options or []),
        "session_idle_never_allowed": b.session_idle_never_allowed,
        "session_idle_custom_allowed": b.session_idle_custom_allowed,
        "logo_click_url": b.logo_click_url,
        "logo_click_target": b.logo_click_target,
        "vendor_attribution_hidden": b.vendor_attribution_hidden,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None,
    }


@router.get("/")
async def get_branding(
    user: User = Depends(require_permission("admin.branding.edit")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    return _serialize(load_branding(db))


class BrandingPatch(BaseModel):
    display_name: str | None = Field(None, max_length=128)
    short_name: str | None = Field(None, max_length=64)
    support_email: str | None = Field(None, max_length=256)
    support_url: str | None = Field(None, max_length=512)
    privacy_url: str | None = Field(None, max_length=512)
    imprint_url: str | None = Field(None, max_length=512)
    default_timezone: str | None = Field(None, max_length=64)
    date_format: str | None = Field(None, max_length=32)
    theme: str | None = None
    accent_hex: str | None = None
    pre_login_warning: str | None = Field(None, max_length=4000)
    aup_require_first_login: bool | None = None
    aup_reprompt_on_change: bool | None = None
    aup_show_footer_link: bool | None = None
    email_from_name: str | None = Field(None, max_length=128)
    email_from_address: str | None = Field(None, max_length=256)
    email_signature: str | None = Field(None, max_length=2000)
    slack_sender_name: str | None = Field(None, max_length=128)
    teams_sender_name: str | None = Field(None, max_length=128)
    sms_sender_identity: str | None = Field(None, max_length=64)
    pdf_footer_text: str | None = Field(None, max_length=256)
    pdf_watermark: bool | None = None
    ssh_motd: str | None = Field(None, max_length=4000)
    ssh_motd_on_every_login: bool | None = None
    session_idle_timeout_default_min: int | None = Field(None, ge=0, le=1440)
    session_idle_timeout_max_min: int | None = Field(None, ge=1, le=1440)
    session_idle_timeout_options: list[int] | None = None
    session_idle_never_allowed: bool | None = None
    session_idle_custom_allowed: bool | None = None
    logo_click_url: str | None = Field(None, max_length=1024)
    logo_click_target: str | None = None
    vendor_attribution_hidden: bool | None = None


@router.patch("/")
async def patch_branding(
    request: Request,
    body: BrandingPatch,
    user: User = Depends(require_permission("admin.branding.edit")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    b = load_branding(db)

    if body.theme is not None and body.theme not in _THEME_ALLOWED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"theme must be one of {sorted(_THEME_ALLOWED)}")
    if body.accent_hex is not None and not _HEX_RE.match(body.accent_hex):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "accent_hex must be #rrggbb")
    if body.logo_click_target is not None and body.logo_click_target not in _TARGET_ALLOWED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "logo_click_target must be _blank or _self")
    # vendor_attribution_hidden used to be Enterprise-license-gated.
    # Apache 2.0 removed the licensing subsystem (2026-05-13) — anyone
    # can hide the vendor attribution on their own deployment now.
    # The trademark on "MeridianNIP" still applies to forks per
    # NOTICE / LICENSE Section 6.

    before = _serialize(b)
    changed: list[str] = []
    for field_name, value in body.model_dump(exclude_unset=True).items():
        if getattr(b, field_name) != value:
            setattr(b, field_name, value)
            changed.append(field_name)

    b.updated_at = datetime.now(UTC)
    b.updated_by = user.id

    # Audit payload deliberately DOES NOT include the full AUP/MOTD text —
    # just the field names that changed. Full versioning of AUP text is a
    # separate mechanism (aup_versions table).
    audit(
        db,
        user_id=user.id,
        action="branding.update",
        target_type="branding",
        target_key="1",
        payload={"fields": changed},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    return {"updated": changed, "current": _serialize(b)}


# ============================================================================
# Asset upload + serve
# ============================================================================
@router.post("/assets/{kind}", status_code=201)
async def upload_asset(
    kind: str,
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_permission("admin.branding.edit")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    if kind not in ALLOWED_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {ALLOWED_KINDS}")
    spec = get_spec(kind)
    try:
        storage_path, size, sha256, sniffed = save_asset(
            kind=kind,
            filename=file.filename or "",
            declared_mime=file.content_type,
            stream=file.file,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    b = load_branding(db)
    previous = getattr(b, spec.field_name)
    setattr(b, spec.field_name, storage_path)
    b.updated_at = datetime.now(UTC)
    b.updated_by = user.id
    db.commit()

    removed = remove_previous(previous)

    audit(
        db,
        user_id=user.id,
        action="branding.asset.upload",
        target_type="branding_asset",
        target_key=kind,
        payload={
            "size_bytes": size,
            "sha256": sha256,
            "mime": sniffed,
            "storage_path": storage_path,
            "previous_removed": removed,
        },
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {
        "kind": kind,
        "url": f"/api/v1/branding/assets/{kind}?v={sha256[:8]}",
        "size_bytes": size,
        "sha256": sha256,
        "mime": sniffed,
    }


@router.get("/assets/{kind}")
async def get_asset(
    kind: str,
    db: OrmSession = Depends(fastapi_dep_db),
):
    """Public endpoint so the login page can show favicon/login_bg pre-auth."""
    if kind not in ALLOWED_KINDS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown asset kind")
    spec = get_spec(kind)
    b = load_branding(db)
    path_str = getattr(b, spec.field_name)
    if not path_str:
        return Response(status_code=404)
    p = Path(path_str)
    if not p.is_file():
        return Response(status_code=410)  # stored-but-missing
    mime, _ = mimetypes.guess_type(p.name)
    headers = {
        # Browsers should cache by querystring version (we include ?v=sha256 on upload).
        "Cache-Control": "public, max-age=300",
    }
    return FileResponse(p, media_type=mime or "application/octet-stream", headers=headers, filename=p.name)


@router.delete("/assets/{kind}", status_code=204, response_model=None)
async def delete_asset(
    kind: str,
    request: Request,
    user: User = Depends(require_permission("admin.branding.edit")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    if kind not in ALLOWED_KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"kind must be one of {ALLOWED_KINDS}")
    spec = get_spec(kind)
    b = load_branding(db)
    previous = getattr(b, spec.field_name)
    if previous:
        remove_previous(previous)
        setattr(b, spec.field_name, None)
        b.updated_at = datetime.now(UTC)
        b.updated_by = user.id
        db.commit()
    audit(
        db,
        user_id=user.id,
        action="branding.asset.delete",
        target_type="branding_asset",
        target_key=kind,
        payload={"previous": previous},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

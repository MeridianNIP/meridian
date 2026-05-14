from __future__ import annotations

from datetime import UTC, datetime
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile, status
from fastapi import File as UploadFileDep
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, current_user
from app.db import fastapi_dep_db
from app.files.storage import (
    InvalidFilename,
    QuotaExceeded,
    delete_storage,
    quota_for,
    save_upload_blob,
    stream_download,
)
from app.models.file import FileRecord
from app.models.user import User

router = APIRouter(prefix="/files", tags=["files"])


# Block anything that could execute if double-clicked on Windows/macOS/Linux,
# plus common malware/script vectors. Matches by lowercase extension — we
# treat `file.EXE.` and `file.exe ` the same as `file.exe`.
_BLOCKED_EXTENSIONS = {
    # Windows executables / scripts
    "exe",
    "com",
    "scr",
    "bat",
    "cmd",
    "msi",
    "msp",
    "ps1",
    "ps2",
    "psm1",
    "psc1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsh",
    "wsf",
    "hta",
    "cpl",
    "dll",
    "sys",
    "lnk",
    "reg",
    "inf",
    "pif",
    # macOS / Linux executables
    "app",
    "dmg",
    "pkg",
    "sh",
    "bash",
    "zsh",
    "csh",
    "run",
    "bin",
    # Office macro-enabled
    "docm",
    "xlsm",
    "pptm",
    "dotm",
    "xltm",
    "potm",
    # Jar / web-exec
    "jar",
    "war",
    "class",
    "apk",
    "swf",
}


def _reject_blocked_ext(filename: str) -> None:
    name = (filename or "").strip().rstrip(". ").lower()
    for ext in _BLOCKED_EXTENSIONS:
        if name.endswith("." + ext):
            raise HTTPException(
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                f"executable/script file type not allowed: .{ext}",
            )


def _serialize(f: FileRecord, *, uploader: str | None = None) -> dict:
    return {
        "id": str(f.id),
        "filename": f.filename,
        "mime_type": f.mime_type,
        "size_bytes": f.size_bytes,
        "sha256_hex": f.sha256_hex,
        "pinned": f.pinned,
        "category": f.category,
        "tags": list(f.tags or []),
        "uploaded_at": f.uploaded_at.isoformat() if f.uploaded_at else None,
        "expires_at": f.expires_at.isoformat() if f.expires_at else None,
        "virus_scan": f.virus_scan,
        "owner_id": str(f.owner_id),
        "uploader": uploader,
    }


@router.get("/blocked-extensions")
async def blocked_extensions() -> dict:
    """Alphabetical list of extensions the uploader rejects. Used by the UI
    to warn users before they attempt an upload."""
    return {"extensions": sorted(_BLOCKED_EXTENSIONS)}


@router.get("/")
async def list_files(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rows = (
        db.execute(
            select(FileRecord)
            .where(FileRecord.owner_id == user.id)
            .order_by(FileRecord.pinned.desc(), FileRecord.uploaded_at.desc())
        )
        .scalars()
        .all()
    )
    owners = {
        u.id: u.username
        for u in db.execute(select(User).where(User.id.in_({r.owner_id for r in rows}))).scalars()
    }
    q = quota_for(db, user.id)
    return {
        "files": [_serialize(f, uploader=owners.get(f.owner_id)) for f in rows],
        "quota": {
            "used_bytes": q.used_bytes,
            "soft_cap": q.soft_cap,
            "hard_cap": q.hard_cap,
            "headroom_bytes": q.headroom_bytes,
            "soft_pct": round(100 * q.used_bytes / q.soft_cap, 1) if q.soft_cap else 0,
            "hard_pct": round(100 * q.used_bytes / q.hard_cap, 1) if q.hard_cap else 0,
        },
    }


@router.post("/upload", status_code=201)
async def upload_file(
    request: Request,
    file: UploadFile = UploadFileDep(...),
    category: str | None = Form(None),
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    _reject_blocked_ext(file.filename or "")
    q = quota_for(db, user.id)
    if q.headroom_bytes <= 0:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"quota exhausted ({q.used_bytes}/{q.hard_cap} B)",
        )
    try:
        storage_path, size, sha256 = save_upload_blob(
            user.id,
            file.filename or "upload.bin",
            file.file,
            quota=q,
        )
    except InvalidFilename as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except QuotaExceeded as e:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(e))

    rec = FileRecord(
        id=uuid.uuid4(),
        owner_id=user.id,
        filename=file.filename or "upload.bin",
        mime_type=file.content_type,
        size_bytes=size,
        sha256_hex=sha256,
        storage_path=storage_path,
        pinned=False,
        category=category or "upload",
        encrypted=False,
        tags=[],
        uploaded_at=datetime.now(UTC),
        virus_scan="unscanned",
    )
    db.add(rec)
    db.flush()

    audit(
        db,
        user_id=user.id,
        action="file.upload",
        target_type="file",
        target_key=str(rec.id),
        payload={
            "filename": rec.filename,
            "size": size,
            "mime": rec.mime_type,
            "sha256": sha256,
            "category": rec.category,
        },
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _serialize(rec)


@router.get("/{file_id}/download")
async def download_file(
    file_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> StreamingResponse:
    rec = db.get(FileRecord, file_id)
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")
    if rec.owner_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your file")
    return StreamingResponse(
        stream_download(rec),
        media_type=rec.mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{rec.filename}"',
            "Content-Length": str(rec.size_bytes),
            "X-Meridian-SHA256": rec.sha256_hex,
        },
    )


@router.post("/{file_id}/pin")
async def toggle_pin(
    request: Request,
    file_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    rec = db.get(FileRecord, file_id)
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")
    if rec.owner_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your file")
    rec.pinned = not rec.pinned
    audit(
        db,
        user_id=user.id,
        action="file.pin" if rec.pinned else "file.unpin",
        target_type="file",
        target_key=str(rec.id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"id": str(rec.id), "pinned": rec.pinned}


@router.delete("/{file_id}", status_code=204, response_model=None)
async def delete_file(
    request: Request,
    file_id: uuid.UUID,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    rec = db.get(FileRecord, file_id)
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")
    if rec.owner_id != user.id and user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your file")
    filename = rec.filename
    size = rec.size_bytes
    delete_storage(rec)
    db.delete(rec)
    audit(
        db,
        user_id=user.id,
        action="file.delete",
        target_type="file",
        target_key=str(file_id),
        payload={"filename": filename, "size": size},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

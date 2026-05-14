from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, BinaryIO

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.models.file import FileRecord


# Matches our schema's `file_repo_user` retention defaults: soft 500 MB, hard 1 GB.
# When the retention_rules table has a row for scope='file_repo_user' with
# max_bytes set, we honor that; otherwise fall back to these defaults.
_SOFT_CAP_DEFAULT = 500 * 1024 * 1024
_HARD_CAP_DEFAULT = 1024 * 1024 * 1024

_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9._ -]{0,254}$")

# 16 MiB copy buffer keeps a 1 GB upload at <1s of wall-clock copy on NVMe.
_COPY_CHUNK = 16 * 1024 * 1024


@dataclass(frozen=True)
class QuotaInfo:
    used_bytes: int
    soft_cap: int
    hard_cap: int
    headroom_bytes: int


class QuotaExceeded(Exception):
    pass


class InvalidFilename(Exception):
    pass


def _uploads_root() -> Path:
    return get_settings().data_root / "uploads"


def safe_filename(name: str) -> str:
    """Validate a user-supplied filename. Reject slashes, parent traversals, control chars."""
    if ".." in name or "/" in name or "\\" in name:
        raise InvalidFilename("filename must not contain path separators")
    if not _SAFE_FILENAME.match(name):
        raise InvalidFilename("filename uses characters outside the allowed set")
    return name


def _per_user_caps(db: OrmSession) -> tuple[int, int]:
    row = db.execute(
        text("SELECT max_bytes FROM retention_rules WHERE scope = 'file_repo_user' AND enabled")
    ).scalar_one_or_none()
    hard = row if row is not None else _HARD_CAP_DEFAULT
    # Soft cap: 50% of hard (matches the "500MB / 1GB" spec default).
    soft = hard // 2 if hard else _SOFT_CAP_DEFAULT
    return soft, hard


def quota_for(db: OrmSession, owner_id: uuid.UUID) -> QuotaInfo:
    soft, hard = _per_user_caps(db)
    used = db.execute(
        select(func.coalesce(func.sum(FileRecord.size_bytes), 0))
        .where(FileRecord.owner_id == owner_id)
    ).scalar_one()
    return QuotaInfo(used_bytes=int(used), soft_cap=soft, hard_cap=hard,
                     headroom_bytes=max(0, hard - int(used)))


def save_upload_blob(
    owner_id: uuid.UUID,
    filename: str,
    upstream: BinaryIO,
    *,
    quota: QuotaInfo,
) -> tuple[str, int, str]:
    """Stream an upload to disk, verifying quota and computing SHA-256 as we go.

    Returns (storage_path, size_bytes, sha256_hex).
    """
    filename = safe_filename(filename)
    file_id = uuid.uuid4()
    dest_dir = _uploads_root() / str(owner_id) / str(file_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / filename

    h = hashlib.sha256()
    size = 0
    with open(dest, "wb") as out:
        while True:
            chunk = upstream.read(_COPY_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > quota.headroom_bytes:
                out.close()
                shutil.rmtree(dest_dir, ignore_errors=True)
                raise QuotaExceeded(
                    f"upload would exceed per-user quota · {size} B would put "
                    f"owner at {quota.used_bytes + size}/{quota.hard_cap} B"
                )
            h.update(chunk)
            out.write(chunk)
    try:
        os.chmod(dest, 0o640)
    except OSError:
        pass
    return str(dest), size, h.hexdigest()


def stream_download(file_rec: FileRecord) -> AsyncIterator[bytes]:
    async def _gen():
        with open(file_rec.storage_path, "rb") as f:
            while True:
                chunk = f.read(_COPY_CHUNK)
                if not chunk:
                    break
                yield chunk
    return _gen()


def delete_storage(file_rec: FileRecord) -> None:
    """Remove the on-disk blob + its enclosing <file_id> dir."""
    p = Path(file_rec.storage_path)
    if p.is_file():
        try:
            p.unlink()
        except OSError:
            pass
    try:
        p.parent.rmdir()
    except OSError:
        pass

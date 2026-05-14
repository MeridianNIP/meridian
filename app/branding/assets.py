"""Branding asset storage.

Stores uploaded logo / favicon / login background / PDF header into
`data_root/branding/{kind}/<ts>_<hash>.<ext>`. Validates content-type via both
the declared MIME and the first few bytes (magic numbers) — SVG is allowed
but sanitized to block <script> and event handlers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from pathlib import Path
import re
from typing import BinaryIO

from app.config import get_settings

ALLOWED_KINDS = ("logo", "favicon", "login_bg", "pdf_header")


@dataclass(frozen=True)
class AssetSpec:
    kind: str
    max_bytes: int
    allowed_mimes: tuple[str, ...]
    allowed_exts: tuple[str, ...]
    field_name: str  # Branding model field to update


_SPECS: dict[str, AssetSpec] = {
    "logo": AssetSpec(
        kind="logo",
        max_bytes=2 * 1024 * 1024,
        allowed_mimes=("image/png", "image/svg+xml", "image/webp", "image/jpeg"),
        allowed_exts=(".png", ".svg", ".webp", ".jpg", ".jpeg"),
        field_name="logo_path",
    ),
    "favicon": AssetSpec(
        kind="favicon",
        max_bytes=256 * 1024,
        allowed_mimes=("image/x-icon", "image/vnd.microsoft.icon", "image/png", "image/svg+xml"),
        allowed_exts=(".ico", ".png", ".svg"),
        field_name="favicon_path",
    ),
    "login_bg": AssetSpec(
        kind="login_bg",
        max_bytes=5 * 1024 * 1024,
        allowed_mimes=("image/jpeg", "image/png", "image/webp"),
        allowed_exts=(".jpg", ".jpeg", ".png", ".webp"),
        field_name="login_bg_path",
    ),
    "pdf_header": AssetSpec(
        kind="pdf_header",
        max_bytes=1 * 1024 * 1024,
        allowed_mimes=("image/png", "image/jpeg"),
        allowed_exts=(".png", ".jpg", ".jpeg"),
        field_name="pdf_header_path",
    ),
}


# Magic bytes per allowed format. Two reasons for both mime + magic check:
# 1. browsers have been known to send image/png for .jpg files,
# 2. attackers may craft a payload whose declared type doesn't match content.
_MAGIC: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\x00\x00\x01\x00", "image/x-icon"),
    (b"RIFF", "image/webp"),  # RIFF....WEBP, verify further below
]

_SVG_SCRIPT_RE = re.compile(r"<script[\s>]|on\w+\s*=", re.IGNORECASE)
_SVG_HEAD_RE = re.compile(rb"<\s*(\?xml|svg|!DOCTYPE)", re.IGNORECASE)


def get_spec(kind: str) -> AssetSpec:
    if kind not in _SPECS:
        raise ValueError(f"unknown branding asset kind: {kind!r}")
    return _SPECS[kind]


def _sniff(head: bytes) -> str | None:
    for prefix, mime in _MAGIC:
        if head.startswith(prefix):
            if mime == "image/webp" and b"WEBP" not in head[:16]:
                continue
            return mime
    if _SVG_HEAD_RE.search(head[:512]):
        return "image/svg+xml"
    return None


def _assets_root() -> Path:
    root = get_settings().data_root / "branding"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_ext(filename: str, spec: AssetSpec) -> str:
    ext = Path(filename or "").suffix.lower()
    if ext not in spec.allowed_exts:
        raise ValueError(
            f"extension {ext!r} not allowed for {spec.kind} " f"(allowed: {', '.join(spec.allowed_exts)})"
        )
    return ext


def _sanitize_svg(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace")
    if _SVG_SCRIPT_RE.search(text):
        raise ValueError("SVG contains <script> or on* event handlers — rejected")
    return data


def save_asset(
    kind: str, filename: str, declared_mime: str | None, stream: BinaryIO
) -> tuple[str, int, str, str]:
    """Validate + persist. Returns (storage_path, size_bytes, sha256_hex, sniffed_mime)."""
    spec = get_spec(kind)
    ext = _safe_ext(filename, spec)

    # Read up to max_bytes + 1 so we can detect over-cap uploads cleanly.
    buf = stream.read(spec.max_bytes + 1)
    size = len(buf)
    if size == 0:
        raise ValueError("empty upload")
    if size > spec.max_bytes:
        raise ValueError(f"upload exceeds {spec.kind} size cap of {spec.max_bytes} bytes")

    sniffed = _sniff(buf)
    if sniffed is None:
        raise ValueError("could not identify image magic bytes — rejecting")

    # Declared mime is advisory; sniffed is authoritative. Both must be in allowlist.
    for m in (sniffed, (declared_mime or "").split(";", 1)[0].strip().lower()):
        if m and m not in spec.allowed_mimes:
            raise ValueError(
                f"mime {m!r} not allowed for {spec.kind} " f"(allowed: {', '.join(spec.allowed_mimes)})"
            )

    if sniffed == "image/svg+xml":
        buf = _sanitize_svg(buf)

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha256(buf).hexdigest()
    dest_dir = _assets_root() / spec.kind
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{ts}_{digest[:12]}{ext}"
    dest.write_bytes(buf)
    try:
        dest.chmod(0o640)
    except OSError:
        pass
    return str(dest), size, digest, sniffed


def remove_previous(previous_path: str | None) -> bool:
    """Delete the previously-saved asset file, if it still exists. Bounded to
    within data_root/branding/ so an operator-typed path can't escape."""
    if not previous_path:
        return False
    try:
        p = Path(previous_path).resolve()
        root = _assets_root().resolve()
        if root in p.parents and p.is_file():
            p.unlink()
            return True
    except OSError:
        return False
    return False

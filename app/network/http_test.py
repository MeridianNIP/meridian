from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class HttpStep:
    url: str
    status: int
    reason: str
    duration_ms: float


@dataclass(frozen=True)
class HttpResult:
    final_url: str
    final_status: int
    total_ms: float
    redirect_count: int
    chain: tuple[HttpStep, ...]
    response_headers: dict[str, str]
    content_type: str | None
    content_length: int | None
    body_preview: str
    tls_info: dict[str, Any] | None


_DEFAULT_HEADERS = {
    "User-Agent": "Meridian-NIP/1.0 (tools/http-test)",
    "Accept": "*/*",
}


async def test_url(
    url: str,
    *,
    method: str = "GET",
    timeout_s: float = 15.0,
    follow_redirects: bool = True,
    max_redirects: int = 10,
    extra_headers: dict[str, str] | None = None,
    body: str | None = None,
    preview_bytes: int = 2048,
) -> HttpResult:
    if method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ValueError(f"method not allowed: {method}")
    headers = {**_DEFAULT_HEADERS, **(extra_headers or {})}

    chain: list[HttpStep] = []
    total = 0.0

    async with httpx.AsyncClient(
        timeout=timeout_s,
        follow_redirects=False,  # we walk redirects ourselves for timing detail
        headers=headers,
    ) as client:
        current = url
        redirects = 0
        while True:
            r = await client.request(method.upper(), current, content=body)
            elapsed = r.elapsed.total_seconds() * 1000
            total += elapsed
            chain.append(
                HttpStep(
                    url=str(r.url),
                    status=r.status_code,
                    reason=r.reason_phrase,
                    duration_ms=round(elapsed, 2),
                )
            )
            if not follow_redirects or not (300 <= r.status_code < 400) or "location" not in r.headers:
                break
            if redirects >= max_redirects:
                break
            current = str(r.url.join(r.headers["location"]))
            redirects += 1
        # `r` now holds the terminal response.
        body_preview = r.text[:preview_bytes] if r.text else ""
        content_type = r.headers.get("content-type")
        cl_header = r.headers.get("content-length")
        try:
            content_length = int(cl_header) if cl_header else len(r.content)
        except ValueError:
            content_length = None

    return HttpResult(
        final_url=chain[-1].url,
        final_status=chain[-1].status,
        total_ms=round(total, 2),
        redirect_count=redirects,
        chain=tuple(chain),
        response_headers=dict(r.headers),
        content_type=content_type,
        content_length=content_length,
        body_preview=body_preview,
        tls_info=None,
    )

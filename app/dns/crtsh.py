from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx


@dataclass(frozen=True)
class CtEntry:
    crt_sh_id: int
    issuer_name: str
    common_name: str | None
    name_value: str                # raw multi-line SAN list
    not_before: str
    not_after: str
    entry_timestamp: str | None


@dataclass(frozen=True)
class CrtShResult:
    target: str
    entry_count: int
    entries: tuple[CtEntry, ...]
    unique_issuers: tuple[str, ...]
    subdomains_seen: tuple[str, ...]


def _clean_dt(s: str | None) -> str:
    if not s:
        return ""
    return s.replace("T", " ")[:19]


async def query_crtsh(target: str, *, limit: int = 100,
                      include_expired: bool = True,
                      include_subdomains: bool = True,
                      timeout_s: float = 20.0) -> CrtShResult:
    """Query crt.sh's JSON endpoint for CT-logged certificates matching
    `target`.

    - `include_subdomains=True` (default) prepends a `%.` wildcard to the
      query so *.example.com subdomains are matched too -- most enterprise
      brands have the majority of their certs on subdomains, and matching
      the apex alone frequently returns zero when the brand clearly has
      public certs (e.g. fisglobal.com). The exact-apex behaviour is still
      available by setting this False.
    - Retries once on 5xx (crt.sh's public endpoint 502s intermittently).
    - Raises a RuntimeError whose message is ready to be surfaced to the
      user on exhaustion.
    """
    import asyncio as _asyncio
    q = f"%.{target}" if include_subdomains else target
    params = {"q": q, "output": "json"}
    if not include_expired:
        params["exclude"] = "expired"

    # crt.sh's public endpoint 502s frequently under load -- multiple
    # short retries with exponential backoff cover the transient case
    # without making the user re-click. Max total extra wait ~22s.
    MAX_ATTEMPTS = 6
    backoffs = [1.0, 2.0, 3.5, 6.0, 9.0]   # seconds between attempts 1-2, 2-3, ...
    last_err: Exception | None = None
    data: list[dict[str, Any]] | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient(
                timeout=timeout_s,
                headers={"User-Agent": "Meridian-NIP/1.0 (crtsh)"},
                follow_redirects=True,
            ) as c:
                r = await c.get("https://crt.sh/", params=params)
                if r.status_code == 404:
                    data = []
                    break
                if 500 <= r.status_code < 600:
                    last_err = RuntimeError(
                        f"crt.sh returned HTTP {r.status_code} after "
                        f"{attempt} attempt(s) (upstream issue)."
                    )
                    if attempt < MAX_ATTEMPTS:
                        await _asyncio.sleep(backoffs[min(attempt - 1, len(backoffs) - 1)])
                        continue
                    raise last_err
                r.raise_for_status()
                data = r.json()
                break
        except httpx.HTTPError as e:
            last_err = RuntimeError(
                f"crt.sh unreachable after {attempt} attempt(s) ({type(e).__name__})."
            )
            if attempt < MAX_ATTEMPTS:
                await _asyncio.sleep(backoffs[min(attempt - 1, len(backoffs) - 1)])
                continue
            raise last_err from e
        except ValueError as e:
            raise RuntimeError(f"crt.sh returned non-JSON: {e}") from e
    if data is None:
        raise last_err or RuntimeError("crt.sh query failed after all retries.")

    rows: list[dict[str, Any]] = data if isinstance(data, list) else []
    rows.sort(key=lambda r: r.get("not_before", ""), reverse=True)

    capped = rows[:max(1, min(limit, 1000))]
    entries = tuple(
        CtEntry(
            crt_sh_id=int(row.get("id", 0)),
            issuer_name=row.get("issuer_name", "") or "",
            common_name=row.get("common_name") or None,
            name_value=row.get("name_value", "") or "",
            not_before=_clean_dt(row.get("not_before")),
            not_after=_clean_dt(row.get("not_after")),
            entry_timestamp=_clean_dt(row.get("entry_timestamp")),
        )
        for row in capped
    )

    issuers: set[str] = set()
    subs: set[str] = set()
    for e in entries:
        issuers.add(e.issuer_name)
        for name in (e.name_value or "").splitlines():
            n = name.strip().lower()
            if n:
                subs.add(n)

    return CrtShResult(
        target=target,
        entry_count=len(rows),
        entries=entries,
        unique_issuers=tuple(sorted(issuers)),
        subdomains_seen=tuple(sorted(subs)),
    )

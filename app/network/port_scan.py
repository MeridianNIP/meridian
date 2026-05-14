from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import re

_PORT_SPEC = re.compile(r"^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$")


@dataclass(frozen=True)
class PortResult:
    port: int
    state: str  # 'open' | 'closed' | 'filtered'
    latency_ms: float | None
    error: str | None = None


@dataclass(frozen=True)
class ScanResult:
    host: str
    ports_scanned: int
    open_ports: tuple[int, ...]
    results: tuple[PortResult, ...]
    duration_ms: int


def parse_port_spec(spec: str, *, max_ports: int = 1024) -> list[int]:
    """Expand '22,80,443,8000-8010' → [22,80,443,8000,...,8010]. Rejects invalid input."""
    spec = spec.replace(" ", "")
    if not _PORT_SPEC.match(spec):
        raise ValueError(
            "ports must be a comma-separated list of single ports or ranges (e.g. 22,80,443,8000-8010)"
        )
    seen: set[int] = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if a > b or a < 1 or b > 65535:
                raise ValueError(f"invalid range: {part}")
            for p in range(a, b + 1):
                seen.add(p)
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"port out of range: {p}")
            seen.add(p)
    if len(seen) > max_ports:
        raise ValueError(f"too many ports: {len(seen)} (limit {max_ports})")
    return sorted(seen)


async def _scan_one(host: str, port: int, *, timeout_s: float) -> PortResult:
    loop = asyncio.get_event_loop()
    start = loop.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_s,
        )
        rtt = (loop.time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return PortResult(port=port, state="open", latency_ms=round(rtt, 2))
    except TimeoutError:
        return PortResult(port=port, state="filtered", latency_ms=None, error="timeout")
    except (ConnectionRefusedError, ConnectionResetError):
        return PortResult(port=port, state="closed", latency_ms=None)
    except OSError as e:
        return PortResult(port=port, state="filtered", latency_ms=None, error=str(e))


def _validate_scope(host: str, scope: str | None) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return
    if scope is None:
        return
    private = ip.is_private or ip.is_loopback or ip.is_link_local
    if scope == "internal" and not private:
        raise ValueError("internal scope forbids public IPs")
    if scope == "external" and private:
        raise ValueError("external scope forbids RFC1918/link-local/loopback")


async def scan(
    host: str,
    ports: list[int],
    *,
    timeout_s: float = 2.0,
    concurrency: int = 64,
    scope: str | None = None,
) -> ScanResult:
    _validate_scope(host, scope)
    loop = asyncio.get_event_loop()
    start = loop.time()

    sem = asyncio.Semaphore(concurrency)

    async def _guarded(p: int) -> PortResult:
        async with sem:
            return await _scan_one(host, p, timeout_s=timeout_s)

    results = await asyncio.gather(*[_guarded(p) for p in ports])
    duration_ms = int((loop.time() - start) * 1000)
    open_ports = tuple(r.port for r in results if r.state == "open")
    return ScanResult(
        host=host,
        ports_scanned=len(ports),
        open_ports=open_ports,
        results=tuple(results),
        duration_ms=duration_ms,
    )

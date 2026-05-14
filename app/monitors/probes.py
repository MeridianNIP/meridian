from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from app.network.ping import PingRequest, run_ping


@dataclass(frozen=True)
class ProbeResult:
    status: str  # 'ok' | 'warn' | 'down' | 'unknown'
    value: float | None  # rtt / response time in ms, loss %, etc.
    detail: dict  # structured extras
    error: str | None = None


async def probe_http(url: str, *, timeout_s: float = 10.0, expect_status: int | None = None) -> ProbeResult:
    try:
        async with httpx.AsyncClient(
            timeout=timeout_s,
            follow_redirects=True,
            headers={"User-Agent": "Meridian-Monitor/1.0"},
        ) as c:
            r = await c.get(url)
        rtt_ms = round(r.elapsed.total_seconds() * 1000, 2)
        expected = expect_status or 200
        if r.status_code == expected:
            status = "ok"
        elif 200 <= r.status_code < 400:
            status = "warn"
        else:
            status = "down"
        return ProbeResult(
            status=status,
            value=rtt_ms,
            detail={"http_status": r.status_code, "final_url": str(r.url)},
        )
    except httpx.TimeoutException:
        return ProbeResult(status="down", value=None, detail={}, error="timeout")
    except httpx.HTTPError as e:
        return ProbeResult(status="down", value=None, detail={}, error=f"{type(e).__name__}: {e}")


async def probe_tcp(host: str, port: int, *, timeout_s: float = 5.0) -> ProbeResult:
    loop = asyncio.get_event_loop()
    start = loop.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_s,
        )
        rtt_ms = round((loop.time() - start) * 1000, 2)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return ProbeResult(status="ok", value=rtt_ms, detail={"host": host, "port": port})
    except TimeoutError:
        return ProbeResult(status="down", value=None, detail={"host": host, "port": port}, error="timeout")
    except OSError as e:
        return ProbeResult(status="down", value=None, detail={"host": host, "port": port}, error=str(e))


async def probe_ping(target: str, *, timeout_s: float = 5.0) -> ProbeResult:
    try:
        result = await run_ping(PingRequest(target=target, count=3, interval_s=0.3, timeout_s=1.0))
    except ValueError as e:
        return ProbeResult(status="unknown", value=None, detail={}, error=str(e))
    s = result.stats
    if s.received == 0:
        return ProbeResult(
            status="down",
            value=s.loss_pct,
            detail={"rtt_avg": s.rtt_avg, "loss_pct": s.loss_pct},
        )
    loss = s.loss_pct or 0.0
    if loss >= 50:
        status = "down"
    elif loss > 0:
        status = "warn"
    else:
        status = "ok"
    return ProbeResult(
        status=status,
        value=s.rtt_avg,
        detail={
            "rtt_min": s.rtt_min,
            "rtt_avg": s.rtt_avg,
            "rtt_max": s.rtt_max,
            "loss_pct": loss,
            "jitter": s.jitter,
        },
    )


def _parse_host_port(target: str) -> tuple[str, int]:
    if ":" not in target:
        raise ValueError(f"TCP target needs host:port, got {target!r}")
    host, _, port_s = target.rpartition(":")
    return host, int(port_s)


async def dispatch(kind: str, target: str, *, config: dict, timeout_seconds: float) -> ProbeResult:
    if kind in ("http", "https"):
        url = (
            target
            if target.startswith(("http://", "https://"))
            else (("https://" if kind == "https" else "http://") + target)
        )
        return await probe_http(url, timeout_s=timeout_seconds, expect_status=config.get("expect_status"))
    if kind == "port_tcp":
        host, port = _parse_host_port(target)
        return await probe_tcp(host, port, timeout_s=timeout_seconds)
    if kind == "ping_icmp":
        return await probe_ping(target, timeout_s=timeout_seconds)
    return ProbeResult(status="unknown", value=None, detail={}, error=f"monitor kind not implemented: {kind}")

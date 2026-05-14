from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from app.sandbox.runner import run


_HOP_LINE = re.compile(
    r"^\s*(?P<ttl>\d+)\s+(?P<host>\S+)\s+\((?P<ip>[^)]+)\)\s+(?P<rtts>.+)$"
)
_RTT = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*ms")


@dataclass(frozen=True)
class Hop:
    ttl: int
    host: str | None
    ip: str | None
    rtts_ms: tuple[float, ...]


@dataclass(frozen=True)
class TraceRequest:
    target: str
    max_hops: int = 30
    timeout_s: int = 3
    per_hop_probes: int = 3
    use_icmp: bool = False


@dataclass(frozen=True)
class TraceResult:
    command: str
    stdout: str
    returncode: int
    hops: tuple[Hop, ...]


def _validate(req: TraceRequest, *, scope: str | None) -> None:
    if not (1 <= req.max_hops <= 64):
        raise ValueError("max_hops must be 1..64")
    if not (1 <= req.timeout_s <= 30):
        raise ValueError("timeout_s must be 1..30")
    if not (1 <= req.per_hop_probes <= 5):
        raise ValueError("per_hop_probes must be 1..5")
    try:
        ip = ipaddress.ip_address(req.target)
    except ValueError:
        ip = None
    if ip is not None and scope is not None:
        private = ip.is_private or ip.is_loopback or ip.is_link_local
        if scope == "internal" and not private:
            raise ValueError("internal scope forbids public IPs")
        if scope == "external" and private:
            raise ValueError("external scope forbids RFC1918/link-local/loopback")


def _parse(stdout: str) -> list[Hop]:
    hops: list[Hop] = []
    for line in stdout.splitlines():
        m = _HOP_LINE.match(line)
        if not m:
            # Lines like "  7  * * *" (unreachable) fall through.
            stripped = line.strip()
            if stripped and stripped.split()[0].isdigit():
                ttl = int(stripped.split()[0])
                hops.append(Hop(ttl=ttl, host=None, ip=None, rtts_ms=tuple()))
            continue
        ttl = int(m.group("ttl"))
        host = m.group("host")
        ip = m.group("ip")
        rtts = tuple(float(x) for x in _RTT.findall(m.group("rtts")))
        hops.append(Hop(ttl=ttl, host=host, ip=ip, rtts_ms=rtts))
    return hops


async def run_traceroute(req: TraceRequest, *, scope: str | None = None) -> TraceResult:
    _validate(req, scope=scope)
    args = [
        "-n" if False else "",  # keep hostname resolution; drop flag means show names
        "-m", str(req.max_hops),
        "-w", str(req.timeout_s),
        "-q", str(req.per_hop_probes),
    ]
    if req.use_icmp:
        args.append("-I")
    args = [a for a in args if a]  # drop empty placeholder
    args.append(req.target)

    result = await run("traceroute", args, timeout_s=req.max_hops * req.timeout_s + 10)
    hops = _parse(result.stdout)
    return TraceResult(
        command="traceroute " + " ".join(args),
        stdout=result.stdout,
        returncode=result.returncode,
        hops=tuple(hops),
    )

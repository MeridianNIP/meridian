from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import statistics

from app.sandbox.runner import run

_RTT_LINE = re.compile(r"time[=<]\s*(?P<rtt>\d+\.?\d*)\s*ms")
_SUMMARY = re.compile(
    r"(?P<tx>\d+)\s*packets?\s+transmitted,\s*(?P<rx>\d+)\s+(?:packets\s+)?received",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PingRequest:
    target: str
    count: int = 10
    interval_s: float = 1.0
    timeout_s: float = 2.0
    packet_size: int = 56
    use_ipv6: bool = False


@dataclass(frozen=True)
class PingStats:
    transmitted: int
    received: int
    loss_pct: float
    rtt_min: float | None
    rtt_avg: float | None
    rtt_max: float | None
    rtt_mdev: float | None
    jitter: float | None


@dataclass(frozen=True)
class PingResult:
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_ms: int
    stats: PingStats


def _validate(req: PingRequest, *, scope: str | None) -> None:
    if not (1 <= req.count <= 100):
        raise ValueError("count must be 1..100")
    if not (0.2 <= req.interval_s <= 5.0):
        raise ValueError("interval_s must be 0.2..5.0")
    if not (16 <= req.packet_size <= 1472):
        raise ValueError("packet_size must be 16..1472")
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


def _parse(stdout: str) -> PingStats:
    rtts: list[float] = []
    transmitted = received = 0
    rtt_min = rtt_avg = rtt_max = rtt_mdev = None

    for line in stdout.splitlines():
        m = _RTT_LINE.search(line)
        if m:
            rtts.append(float(m.group("rtt")))
            continue
        s = _SUMMARY.search(line)
        if s:
            transmitted = int(s.group("tx"))
            received = int(s.group("rx"))
        if line.startswith("rtt min/avg/max/mdev"):
            try:
                vals = line.split("=", 1)[1].strip().split()[0].split("/")
                rtt_min, rtt_avg, rtt_max, rtt_mdev = (float(v) for v in vals)
            except (IndexError, ValueError):
                pass

    if rtts and rtt_avg is None:
        rtt_min = min(rtts)
        rtt_max = max(rtts)
        rtt_avg = statistics.fmean(rtts)
        rtt_mdev = statistics.pstdev(rtts) if len(rtts) > 1 else 0.0
    jitter = rtt_mdev
    loss_pct = 0.0 if transmitted == 0 else round(100 * (transmitted - received) / transmitted, 2)
    return PingStats(
        transmitted=transmitted,
        received=received,
        loss_pct=loss_pct,
        rtt_min=rtt_min,
        rtt_avg=rtt_avg,
        rtt_max=rtt_max,
        rtt_mdev=rtt_mdev,
        jitter=jitter,
    )


async def run_ping(req: PingRequest, *, scope: str | None = None) -> PingResult:
    _validate(req, scope=scope)
    binary = "ping6" if req.use_ipv6 else "ping"
    args = [
        "-c",
        str(req.count),
        "-i",
        str(req.interval_s),
        "-W",
        str(int(req.timeout_s)),
        "-s",
        str(req.packet_size),
        "-n",  # numeric output, no reverse DNS
        req.target,
    ]
    result = await run(binary, args, timeout_s=req.count * req.interval_s + 5)
    stats = _parse(result.stdout)
    return PingResult(
        command=f"{binary} " + " ".join(args),
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
        duration_ms=result.duration_ms,
        stats=stats,
    )

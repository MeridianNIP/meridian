from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from app.sandbox.runner import SandboxResult, run


# Flags the UI exposes as clickable chips. Anything outside this set is rejected.
_ALLOWED_FLAGS = {
    "+short", "+trace", "+noall", "+answer", "+authority", "+additional",
    "+dnssec", "+cd", "+tcp", "+norecurse", "+multiline",
}

_ALLOWED_RECORD_TYPES = {
    "A", "AAAA", "ANY", "AXFR", "CAA", "CNAME", "DNSKEY", "DS", "MX", "NS",
    "PTR", "SOA", "SRV", "TLSA", "TXT",
}

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
_IPV4_RE   = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$")


@dataclass(frozen=True)
class DigRequest:
    target: str
    record_type: str = "A"
    resolver: str | None = None
    flags: tuple[str, ...] = ("+short", "+noall", "+answer")
    # Optional per-query caps. When set, dig is invoked with +time=<n> and
    # +tries=<n>. Used by the propagation panel to avoid a slow public
    # resolver stalling the whole batch.
    timeout_s: int | None = None
    tries: int | None = None


@dataclass(frozen=True)
class DigResult:
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_ms: int
    truncated: bool
    timed_out: bool


def _validate(req: DigRequest) -> None:
    if req.record_type.upper() not in _ALLOWED_RECORD_TYPES:
        raise ValueError(f"record type not allowed: {req.record_type!r}")
    if not (_DOMAIN_RE.match(req.target) or _IPV4_RE.match(req.target)):
        raise ValueError(f"target not a valid domain or IPv4: {req.target!r}")
    for f in req.flags:
        if f not in _ALLOWED_FLAGS:
            raise ValueError(f"flag not allowed: {f!r}")
    if req.resolver is not None and not _IPV4_RE.match(req.resolver):
        raise ValueError(f"resolver must be an IPv4 literal: {req.resolver!r}")


def _build_args(req: DigRequest) -> list[str]:
    args: list[str] = []
    if req.resolver:
        args.append(f"@{req.resolver}")
    args += [req.target, req.record_type.upper(), *req.flags]
    if req.timeout_s is not None:
        t = int(req.timeout_s)
        if 1 <= t <= 30:
            args.append(f"+time={t}")
    if req.tries is not None:
        n = int(req.tries)
        if 1 <= n <= 5:
            args.append(f"+tries={n}")
    return args


async def run_dig(req: DigRequest) -> DigResult:
    _validate(req)
    args = _build_args(req)
    result: SandboxResult = await run("dig", args, timeout_s=15)
    return DigResult(
        command="dig " + " ".join(args),
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
        duration_ms=result.duration_ms,
        truncated=result.truncated,
        timed_out=result.timed_out,
    )

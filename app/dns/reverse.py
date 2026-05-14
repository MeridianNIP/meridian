from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from app.sandbox.runner import run

_ANSWER_RE = re.compile(
    r"^(?P<owner>\S+)\s+\d+\s+IN\s+PTR\s+(?P<ptr>\S+)\.?\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class ReverseRecord:
    ptr: str
    owner: str


@dataclass(frozen=True)
class ReverseResult:
    ip: str
    reverse_zone: str
    records: tuple[ReverseRecord, ...]
    raw: str
    returncode: int


def _arpa_for(ip: str) -> str:
    """Return the in-addr.arpa / ip6.arpa name used for reverse queries."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(str(addr).split("."))) + ".in-addr.arpa."
    exp = addr.exploded.replace(":", "")
    return ".".join(reversed(exp)) + ".ip6.arpa."


async def reverse_lookup(ip: str, *, resolver: str | None = None) -> ReverseResult:
    # Validate the input is actually an IP.
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError(f"not a valid IP address: {ip!r}") from e
    if resolver is not None:
        try:
            ipaddress.ip_address(resolver)
        except ValueError:
            raise ValueError(f"resolver must be an IPv4 literal: {resolver!r}")

    args = [f"@{resolver}"] if resolver else []
    args += ["-x", ip, "+noall", "+answer"]

    result = await run("dig", args, timeout_s=8)
    records = tuple(
        ReverseRecord(ptr=m.group("ptr"), owner=m.group("owner")) for m in _ANSWER_RE.finditer(result.stdout)
    )
    return ReverseResult(
        ip=ip,
        reverse_zone=_arpa_for(ip),
        records=records,
        raw=result.stdout,
        returncode=result.returncode,
    )

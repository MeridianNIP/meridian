from __future__ import annotations

import re
from dataclasses import dataclass

from app.sandbox.runner import run


# Allow common safe OIDs + numeric OIDs like .1.3.6.1.2.1.1.1.0.
# Reject anything with shell metachars (the sandbox's allowlist would catch it
# anyway, but we want to reject at the app layer with a clean error).
_SAFE_OID = re.compile(r"^[A-Za-z0-9._:\-]+$")

_OID_LINE = re.compile(
    r"^(?P<oid>[A-Za-z0-9._:\-]+)\s*=\s*(?P<type>[A-Z0-9-]+):\s*(?P<value>.*)$",
)


@dataclass(frozen=True)
class SnmpRow:
    oid: str
    type: str
    value: str


@dataclass(frozen=True)
class SnmpResult:
    command: str
    host: str
    oid_root: str
    rows: tuple[SnmpRow, ...]
    raw: str
    returncode: int
    error: str | None


def _validate(host: str, oid: str, version: str, community: str | None) -> None:
    if not _SAFE_OID.match(oid):
        raise ValueError(f"oid contains characters outside the allowlist: {oid!r}")
    if version not in ("1", "2c", "3"):
        raise ValueError("version must be 1, 2c, or 3")
    if version in ("1", "2c") and not community:
        raise ValueError(f"community required for SNMPv{version}")
    # Host validation is loose on purpose — DNS names are fine.
    if not re.match(r"^[A-Za-z0-9._:\-]{1,253}$", host):
        raise ValueError(f"host contains invalid characters: {host!r}")


async def walk(
    host: str, oid: str = "system",
    *,
    version: str = "2c",
    community: str | None = "public",
    timeout_s: float = 8.0,
) -> SnmpResult:
    _validate(host, oid, version, community)
    args: list[str] = [
        "-On",                      # numeric OIDs
        "-Oa",                      # ASCII strings where useful
        "-Lf", "/dev/null",         # silence the log-file hint
        f"-v{version}",
        "-t", str(int(timeout_s)),
        "-r", "1",
    ]
    if version in ("1", "2c"):
        args += ["-c", community or "public"]
    # SNMPv3 creds (authKey/privKey) would load from the vault; first cut is v2c.
    args += [host, oid]

    result = await run("snmpwalk", args, timeout_s=timeout_s + 5)
    rows: list[SnmpRow] = []
    for line in result.stdout.splitlines():
        m = _OID_LINE.match(line.strip())
        if m:
            rows.append(SnmpRow(
                oid=m.group("oid"),
                type=m.group("type"),
                value=m.group("value"),
            ))

    error = None
    if result.returncode != 0 and not rows:
        error = (result.stderr.strip().splitlines() or ["snmpwalk failed"])[-1]
    return SnmpResult(
        command=f"snmpwalk {' '.join(args)}",
        host=host, oid_root=oid,
        rows=tuple(rows),
        raw=result.stdout,
        returncode=result.returncode,
        error=error,
    )

"""rndc flush panel — cache-flush the local BIND9 recursive resolver.

Requires `rndc-confgen -a` to have been run during install (which sets up
/etc/bind/rndc.key + `controls` in named.conf) — the installer ships a
local-only control channel bound to 127.0.0.1:953. If rndc isn't configured,
the call fails cleanly.
"""

from __future__ import annotations

import asyncio
import re

_ZONE_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


async def rndc_flush(
    *, zone: str | None = None, view: str | None = None, timeout_s: float = 15.0
) -> dict[str, object]:
    """Call `rndc flush` (all) or `rndc flushname <zone>` (targeted).

    `rndc` is NOT in the sandbox allowlist because it's an administrative
    control channel — gated by permission at the route level instead.
    """
    args: list[str] = []
    action = "flush-all"
    if zone:
        if not _ZONE_RE.match(zone):
            raise ValueError(f"not a valid zone: {zone!r}")
        args = ["flushname", zone]
        action = "flushname"
    else:
        args = ["flush"]

    if view:
        if not _ZONE_RE.match(view):
            raise ValueError(f"not a valid view name: {view!r}")
        args += ["in", view]

    proc = await asyncio.create_subprocess_exec(
        "/usr/sbin/rndc",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout_s,
        )
    except TimeoutError:
        proc.kill()
        raise RuntimeError(f"rndc {' '.join(args)} timed out after {timeout_s}s")

    return {
        "action": action,
        "zone": zone,
        "view": view,
        "returncode": proc.returncode,
        "stdout": stdout_b.decode("utf-8", "replace")[:4096],
        "stderr": stderr_b.decode("utf-8", "replace")[:4096],
    }

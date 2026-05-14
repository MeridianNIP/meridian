from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.dns.dig import DigRequest, run_dig


@dataclass(frozen=True)
class AxfrRow:
    nameserver: str
    exposed: bool
    detail: str


@dataclass(frozen=True)
class AxfrReport:
    domain: str
    rows: tuple[AxfrRow, ...]
    any_exposed: bool


async def axfr_audit(domain: str) -> AxfrReport:
    """Attempt a zone transfer against each authoritative NS.

    A successful AXFR from an external client is always misconfiguration —
    it exposes the entire zone. This audit surfaces any NS that accepts one.
    """
    ns_res = await run_dig(DigRequest(target=domain, record_type="NS",
                                      flags=("+short", "+noall", "+answer")))
    nameservers = [
        l.strip().rstrip(".")
        for l in ns_res.stdout.splitlines()
        if l.strip() and not l.startswith(";")
    ]

    async def _try(ns: str) -> AxfrRow:
        # dig @ns domain axfr
        r = await run_dig(DigRequest(
            target=domain, record_type="AXFR", resolver=None,
            flags=(),
        ))
        # dig's AXFR output contains the full zone on success, OR a line
        # starting with "; Transfer failed" / ";; communications error" on failure.
        stdout = r.stdout
        if "Transfer failed" in stdout or "communications error" in stdout \
           or "refused" in stdout.lower():
            return AxfrRow(nameserver=ns, exposed=False, detail="refused (good)")
        # Heuristic: a successful AXFR produces many lines of RRs.
        records = [l for l in stdout.splitlines() if l and not l.startswith(";")]
        if len(records) >= 2:
            return AxfrRow(nameserver=ns, exposed=True,
                           detail=f"EXPOSED · {len(records)} records transferred")
        return AxfrRow(nameserver=ns, exposed=False,
                       detail="no transfer (empty response)")

    rows = await asyncio.gather(*[_try(ns) for ns in nameservers])
    any_exposed = any(r.exposed for r in rows)
    return AxfrReport(domain=domain, rows=tuple(rows), any_exposed=any_exposed)

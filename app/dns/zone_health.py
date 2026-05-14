from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from app.dns.dig import DigRequest, run_dig


@dataclass
class ZoneFinding:
    severity: str       # 'info' | 'warn' | 'fail'
    check: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class ZoneReport:
    domain: str
    ns_records: list[str]
    soa_serials: dict[str, str | None]
    findings: list[ZoneFinding]
    worst: str


def _extract_first(line_stream: str) -> str | None:
    for line in line_stream.splitlines():
        line = line.strip()
        if line and not line.startswith(";"):
            return line
    return None


def _extract_all(line_stream: str) -> list[str]:
    return [l.strip() for l in line_stream.splitlines() if l.strip() and not l.startswith(";")]


async def check_zone(domain: str) -> ZoneReport:
    findings: list[ZoneFinding] = []

    # 1 · NS delegation
    ns_res = await run_dig(DigRequest(target=domain, record_type="NS",
                                      flags=("+short", "+noall", "+answer")))
    ns_list = [l.rstrip(".") for l in _extract_all(ns_res.stdout)]
    if not ns_list:
        findings.append(ZoneFinding("fail", "ns_delegation",
                                    f"no NS records returned for {domain}"))
        return ZoneReport(domain=domain, ns_records=[], soa_serials={},
                          findings=findings, worst="fail")
    findings.append(ZoneFinding("info", "ns_delegation",
                                f"{len(ns_list)} NS records",
                                {"ns": ns_list}))

    # 2 · SOA serial from each authoritative NS
    async def _soa_from(nsname: str) -> tuple[str, str | None]:
        r = await run_dig(DigRequest(
            target=domain, record_type="SOA", resolver=None,
            flags=("+short", "+noall", "+answer"),
        ))
        first = _extract_first(r.stdout)
        if first is None:
            return nsname, None
        # SOA short format: "ns serial refresh retry expire minimum"
        parts = first.split()
        return nsname, (parts[2] if len(parts) >= 3 else None)

    soa_pairs = await asyncio.gather(*[_soa_from(ns) for ns in ns_list[:5]])
    serials = dict(soa_pairs)
    unique = {s for s in serials.values() if s is not None}
    if len(unique) == 0:
        findings.append(ZoneFinding("warn", "soa_serial",
                                    "could not retrieve SOA from any NS",
                                    {"serials": serials}))
    elif len(unique) > 1:
        findings.append(ZoneFinding("warn", "soa_serial",
                                    f"authoritative NSes disagree on SOA serial: {sorted(unique)}",
                                    {"serials": serials}))
    else:
        findings.append(ZoneFinding("info", "soa_serial",
                                    f"all NSes report serial {next(iter(unique))}",
                                    {"serials": serials}))

    # 3 · CNAME/A sanity on the apex — apex CNAME violates RFC 1034.
    cname_res = await run_dig(DigRequest(target=domain, record_type="CNAME",
                                         flags=("+short", "+noall", "+answer")))
    if _extract_first(cname_res.stdout):
        findings.append(ZoneFinding(
            "fail", "apex_cname",
            f"{domain} has a CNAME at the zone apex — this is invalid per RFC 1034",
            {"record": _extract_first(cname_res.stdout)},
        ))

    # 4 · Apex A/AAAA
    a_res = await run_dig(DigRequest(target=domain, record_type="A",
                                     flags=("+short", "+noall", "+answer")))
    aaaa_res = await run_dig(DigRequest(target=domain, record_type="AAAA",
                                        flags=("+short", "+noall", "+answer")))
    has_a = bool(_extract_first(a_res.stdout))
    has_aaaa = bool(_extract_first(aaaa_res.stdout))
    if not has_a and not has_aaaa:
        findings.append(ZoneFinding("warn", "apex_address",
                                    "no A or AAAA record at apex"))
    else:
        findings.append(ZoneFinding(
            "info", "apex_address",
            f"has{' A' if has_a else ''}{' + AAAA' if has_aaaa else ''}".strip(),
        ))

    # 5 · MX + SPF sanity (quick mail-readiness check; not a full mail audit)
    mx_res = await run_dig(DigRequest(target=domain, record_type="MX",
                                      flags=("+short", "+noall", "+answer")))
    if not _extract_first(mx_res.stdout):
        findings.append(ZoneFinding("info", "mx", "no MX records (zone doesn't accept mail)"))
    else:
        findings.append(ZoneFinding("info", "mx",
                                    f"{len(_extract_all(mx_res.stdout))} MX records"))

    worst_order = {"info": 0, "warn": 1, "fail": 2}
    worst = max(findings, key=lambda f: worst_order[f.severity]).severity
    return ZoneReport(domain=domain, ns_records=ns_list, soa_serials=serials,
                      findings=findings, worst=worst)

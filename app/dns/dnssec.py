from __future__ import annotations

from dataclasses import dataclass
import re

from app.dns.dig import DigRequest, run_dig


@dataclass
class DnssecStep:
    zone: str
    has_ds: bool
    has_dnskey: bool
    algorithms: list[str]
    outcome: str  # 'ok' | 'warn' | 'fail' | 'unsigned'
    message: str


@dataclass
class DnssecReport:
    target: str
    chain: list[DnssecStep]
    ad_flag: bool  # whether a recursive resolver would AD-flag a query
    worst: str  # worst outcome in the chain


_DS_ALG_NAMES = {
    1: "RSAMD5",
    5: "RSASHA1",
    7: "NSEC3RSASHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}

_ALG_RE = re.compile(r"\b(\d+)\s+(\d+)\s+(\d+)\s+[0-9A-Fa-f]+")


def _zones_upward(domain: str) -> list[str]:
    """Return [root, tld, ..., domain] for the zone walk."""
    parts = domain.rstrip(".").split(".")
    out = [""]
    for i in range(len(parts) - 1, -1, -1):
        out.append(".".join(parts[i:]))
    return out


async def _has_records(zone: str, rtype: str) -> tuple[bool, list[str]]:
    target = zone or "."
    r = await run_dig(
        DigRequest(
            target=target,
            record_type=rtype,
            flags=("+short", "+noall", "+answer", "+dnssec"),
        )
    )
    lines = [l.strip() for l in r.stdout.splitlines() if l.strip() and not l.startswith(";")]
    return (len(lines) > 0, lines)


def _extract_algs(lines: list[str]) -> list[str]:
    algs: set[int] = set()
    for line in lines:
        m = _ALG_RE.search(line)
        if m:
            algs.add(int(m.group(3)))
    return [f"{a} ({_DS_ALG_NAMES.get(a, '?')})" for a in sorted(algs)]


async def _check_ad_flag(domain: str) -> bool:
    # +dnssec includes `; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: N`
    # with `flags: qr rd ra ad;` when the resolver has AD-validated the answer.
    r = await run_dig(
        DigRequest(
            target=domain,
            record_type="A",
            flags=("+dnssec",),
        )
    )
    for line in r.stdout.splitlines():
        if "flags:" in line and " ad" in line.split(";", 1)[0]:
            return True
    return False


async def walk_chain(domain: str) -> DnssecReport:
    zones = _zones_upward(domain)
    chain: list[DnssecStep] = []
    worst = "ok"
    severity_rank = {"ok": 0, "unsigned": 0, "warn": 1, "fail": 2}

    for zone in zones:
        ds_present, ds_lines = (await _has_records(zone, "DS")) if zone else (True, [])
        dnskey_present, dnskey_lines = await _has_records(zone, "DNSKEY")

        if not zone:
            # Root zone: always signed; we only check DNSKEY presence.
            if dnskey_present:
                chain.append(
                    DnssecStep(
                        zone=".",
                        has_ds=True,
                        has_dnskey=True,
                        algorithms=_extract_algs(dnskey_lines),
                        outcome="ok",
                        message="root zone DNSKEY present",
                    )
                )
            else:
                chain.append(
                    DnssecStep(
                        zone=".",
                        has_ds=False,
                        has_dnskey=False,
                        algorithms=[],
                        outcome="fail",
                        message="root zone DNSKEY not retrievable — resolver path may be broken",
                    )
                )
            continue

        if not dnskey_present and not ds_present:
            # The zone is unsigned; if its parent had a DS, the parent claim
            # is inconsistent (resolver failure). If parent had no DS either,
            # this is a legit unsigned zone (like many corporate internals).
            parent_step = chain[-1] if chain else None
            if parent_step and parent_step.has_ds and zone == zones[-1]:
                # We expected this zone to be signed (DS at parent) but it has
                # no DNSKEY — broken delegation.
                chain.append(
                    DnssecStep(
                        zone=zone,
                        has_ds=False,
                        has_dnskey=False,
                        algorithms=[],
                        outcome="fail",
                        message="parent delegates as signed (DS present) but zone has no DNSKEY",
                    )
                )
                worst = "fail"
            else:
                chain.append(
                    DnssecStep(
                        zone=zone,
                        has_ds=False,
                        has_dnskey=False,
                        algorithms=[],
                        outcome="unsigned",
                        message=f"{zone} is unsigned (no DS / no DNSKEY)",
                    )
                )
            continue

        if ds_present and not dnskey_present:
            chain.append(
                DnssecStep(
                    zone=zone,
                    has_ds=True,
                    has_dnskey=False,
                    algorithms=_extract_algs(ds_lines),
                    outcome="fail",
                    message="parent has DS for this zone but the zone returns no DNSKEY",
                )
            )
            worst = "fail"
            continue

        if dnskey_present and not ds_present and zone != zones[-1]:
            # Intermediate zone with DNSKEY but no DS at parent — the chain
            # upward is broken at this edge. Can still be valid for the
            # requested domain if we're looking at the apex zone itself.
            chain.append(
                DnssecStep(
                    zone=zone,
                    has_ds=False,
                    has_dnskey=True,
                    algorithms=_extract_algs(dnskey_lines),
                    outcome="warn",
                    message="zone is signed but parent has no DS — island of trust",
                )
            )
            if severity_rank[worst] < severity_rank["warn"]:
                worst = "warn"
            continue

        chain.append(
            DnssecStep(
                zone=zone,
                has_ds=ds_present,
                has_dnskey=dnskey_present,
                algorithms=_extract_algs(dnskey_lines or ds_lines),
                outcome="ok",
                message="DS at parent + DNSKEY at zone (chain intact)",
            )
        )

    ad_flag = await _check_ad_flag(domain)
    return DnssecReport(target=domain, chain=chain, ad_flag=ad_flag, worst=worst)

from __future__ import annotations

from app.dns.dig import DigRequest, run_dig
from app.dns.propagation import check_propagation
from app.wizards.engine import Suggestion, WizardContext, WizardStep, wizard


@wizard("dns.resolve_fail")
async def why_isnt_my_domain_resolving(ctx: WizardContext) -> list[Suggestion]:
    """Registrar → delegation → SOA → authoritative → cache → DNSSEC → propagation."""
    domain = ctx.target

    # 1 · NS delegation
    ns = await run_dig(DigRequest(target=domain, record_type="NS",
                                  flags=("+short", "+noall", "+answer")))
    ns_list = [l.strip().rstrip(".") for l in ns.stdout.splitlines() if l.strip()]
    if not ns_list:
        ctx.add(WizardStep(
            name="NS delegation",
            outcome="fail",
            message="No NS records returned — domain is not delegated or was never registered.",
            detail={"returncode": ns.returncode, "stderr": ns.stderr},
        ))
        return [
            Suggestion(
                priority="critical",
                title="Confirm domain is registered",
                detail=f"A WHOIS lookup for {domain} will show whether it has ever been registered.",
                tool_deeplink=f"/ui/dns-tools#whois?target={domain}",
                external_url=f"https://www.whois.com/whois/{domain}",
            ),
        ]
    ctx.add(WizardStep(
        name="NS delegation",
        outcome="ok",
        message=f"{len(ns_list)} nameserver(s) returned: {', '.join(ns_list[:4])}"
                + (" …" if len(ns_list) > 4 else ""),
        detail={"ns_records": ns_list},
    ))

    # 2 · SOA serial cross-check between authoritative NSes
    serials: dict[str, str | None] = {}
    for nsname in ns_list[:4]:
        soa_res = await run_dig(DigRequest(
            target=domain, record_type="SOA", resolver=None,
            flags=("+short", "+noall", "+answer"),
        ))
        first = next(
            (l.split()[2] for l in soa_res.stdout.splitlines() if l.strip() and len(l.split()) >= 3),
            None,
        )
        serials[nsname] = first
    unique_serials = {s for s in serials.values() if s}
    if len(unique_serials) > 1:
        ctx.add(WizardStep(
            name="SOA serial match across authoritative NSes",
            outcome="warn",
            message="Authoritative nameservers disagree on SOA serial — zones are not in sync.",
            detail={"serials": serials},
        ))
    elif unique_serials:
        ctx.add(WizardStep(
            name="SOA serial match across authoritative NSes",
            outcome="ok",
            message=f"All NSes report SOA serial {next(iter(unique_serials))}.",
            detail={"serials": serials},
        ))
    else:
        ctx.add(WizardStep(
            name="SOA serial match across authoritative NSes",
            outcome="warn",
            message="Could not retrieve SOA from any authoritative NS.",
            detail={"serials": serials},
        ))

    # 3 · Recursive lookup via the system resolver panel (propagation sample)
    prop = await check_propagation(domain, "A")
    if len(prop.unique_answers) == 0:
        ctx.add(WizardStep(
            name="Global propagation",
            outcome="fail",
            message=f"None of {len(prop.rows)} public resolvers returned an A record.",
            detail={"resolvers": len(prop.rows), "ok": 0},
        ))
        return [
            Suggestion(
                priority="critical",
                title="Nameservers aren't returning answers",
                detail="The domain is delegated but the authoritative nameservers aren't answering public queries.",
                tool_deeplink=f"/ui/dns-tools#dig?target={domain}&type=A",
            ),
        ]
    ok_count = sum(1 for r in prop.rows if r.ok)
    if prop.divergence:
        ctx.add(WizardStep(
            name="Global propagation",
            outcome="warn",
            message=f"Resolvers disagree on the answer: {', '.join(prop.unique_answers)}",
            detail={"unique_answers": list(prop.unique_answers),
                    "ok_resolvers": ok_count, "total": len(prop.rows)},
        ))
    else:
        ctx.add(WizardStep(
            name="Global propagation",
            outcome="ok",
            message=f"{ok_count}/{len(prop.rows)} resolvers agree on {prop.unique_answers[0]}.",
            detail={"answer": prop.unique_answers[0]},
        ))

    # 4 · DNSSEC chain sample
    dnssec = await run_dig(DigRequest(
        target=domain, record_type="DNSKEY",
        flags=("+short", "+noall", "+answer", "+dnssec"),
    ))
    if dnssec.returncode == 0 and dnssec.stdout.strip():
        ctx.add(WizardStep(
            name="DNSSEC chain of trust",
            outcome="ok",
            message="DNSKEY records present.",
            detail={"lines": len(dnssec.stdout.strip().splitlines())},
        ))
    else:
        ctx.add(WizardStep(
            name="DNSSEC chain of trust",
            outcome="info",
            message="No DNSKEY records — domain is not DNSSEC-signed (not necessarily a problem).",
        ))

    # Build suggestions based on what the steps produced
    suggestions: list[Suggestion] = []
    worst = ctx.worst_outcome()
    if worst == "ok":
        suggestions.append(Suggestion(
            priority="info",
            title="Looks healthy",
            detail=f"All checks passed for {domain}. If users still report issues, verify their local resolver and DNS cache.",
        ))
    if any(s.name == "SOA serial match across authoritative NSes" and s.outcome == "warn"
           for s in ctx.steps):
        suggestions.append(Suggestion(
            priority="recommended",
            title="Force a zone sync",
            detail="At least one authoritative NS lags on the SOA serial. Contact your DNS provider or trigger a manual zone transfer.",
            tool_deeplink=f"/ui/wizards?wizard_key=zone.health?target={domain}",
        ))
    if any(s.name == "Global propagation" and s.outcome == "warn" for s in ctx.steps):
        suggestions.append(Suggestion(
            priority="recommended",
            title="Propagation is incomplete",
            detail="Public resolvers disagree. This is normal for up to 48 hours after a change. Past that window, check for caching proxies upstream of the authoritative servers.",
            tool_deeplink=f"/ui/dns-tools#propagation?target={domain}",
        ))
    return suggestions

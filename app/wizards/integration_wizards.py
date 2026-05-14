"""mail.flow_validator wizard -- full mail stack end-to-end probe (MX,
SMTP ports, SPF, DMARC, MTA-STS, TLS-RPT, PTR).
"""
from __future__ import annotations

from app.dns.dig import DigRequest, run_dig
from app.network.port_scan import scan as port_scan
from app.wizards.engine import Suggestion, WizardContext, WizardStep, wizard


def _answers(stdout: str) -> list[str]:
    return [
        line.strip()
        for line in stdout.splitlines()
        if line.strip() and not line.startswith(";")
    ]


# ============================================================================
# mail.flow_validator — full mail stack end-to-end
# ============================================================================
@wizard("mail.flow_validator")
async def mail_flow_validator(ctx: WizardContext) -> list[Suggestion]:
    domain = ctx.target

    mx = await run_dig(DigRequest(target=domain, record_type="MX"))
    mx_rows = _answers(mx.stdout)
    if not mx_rows:
        ctx.add(WizardStep(name="MX lookup", outcome="fail",
                           message=f"No MX for {domain}"))
        return [Suggestion(priority="critical", title="No MX record",
                           detail="Mail flow cannot begin without at least one MX.")]
    ctx.add(WizardStep(name="MX lookup", outcome="ok",
                       message=f"{len(mx_rows)} MX: {mx_rows[:3]}"))

    # Probe SMTP port 25, 465, 587 against the primary MX host
    first_mx = mx_rows[0].split()[-1].rstrip(".")
    try:
        ps = await port_scan(first_mx, [25, 465, 587], timeout_s=3.0, concurrency=3)
        open_ports = list(ps.open_ports)
        ctx.add(WizardStep(
            name=f"SMTP ports on {first_mx}",
            outcome="ok" if open_ports else "fail",
            message=(f"Open: {open_ports}" if open_ports else
                     "None of 25/465/587 reachable from this host — egress firewall, or the MX is filtered."),
        ))
    except ValueError as e:
        ctx.add(WizardStep(name="SMTP ports", outcome="warn",
                           message=f"Port scan rejected by scope: {e}"))
        open_ports = []

    # DNS-side auth stack
    spf = await run_dig(DigRequest(target=domain, record_type="TXT"))
    spf_ok = any("v=spf1" in r for r in _answers(spf.stdout))
    dmarc = await run_dig(DigRequest(target=f"_dmarc.{domain}", record_type="TXT"))
    dmarc_ok = any("v=DMARC1" in r for r in _answers(dmarc.stdout))
    ctx.add(WizardStep(name="SPF present",
                       outcome="ok" if spf_ok else "warn",
                       message="yes" if spf_ok else "missing"))
    ctx.add(WizardStep(name="DMARC present",
                       outcome="ok" if dmarc_ok else "warn",
                       message="yes" if dmarc_ok else "missing"))

    # MTA-STS + TLS-RPT
    mta_sts = await run_dig(DigRequest(target=f"_mta-sts.{domain}", record_type="TXT"))
    tls_rpt = await run_dig(DigRequest(target=f"_smtp._tls.{domain}", record_type="TXT"))
    ctx.add(WizardStep(
        name="MTA-STS + TLS-RPT",
        outcome="ok" if mta_sts.stdout.strip() and tls_rpt.stdout.strip() else "info",
        message=(
            f"MTA-STS: {'yes' if mta_sts.stdout.strip() else 'no'} · "
            f"TLS-RPT: {'yes' if tls_rpt.stdout.strip() else 'no'}"
        ),
    ))

    # PTR (reverse DNS) for the MX — important for receiver anti-spam heuristics
    a_res = await run_dig(DigRequest(target=first_mx, record_type="A"))
    first_ip = next(iter(_answers(a_res.stdout)), None)
    if first_ip:
        from app.dns.reverse import reverse_lookup
        try:
            rev = await reverse_lookup(first_ip)
            ptrs = [rec.name for rec in rev.records]
            ctx.add(WizardStep(
                name="PTR for MX host",
                outcome="ok" if ptrs else "warn",
                message=(f"PTR: {ptrs}" if ptrs else "no PTR — many receivers will flag"),
            ))
        except Exception as e:  # noqa: BLE001
            ctx.add(WizardStep(name="PTR for MX host",
                               outcome="info",
                               message=f"reverse lookup failed: {e}"))

    sug: list[Suggestion] = []
    if not spf_ok:
        sug.append(Suggestion(priority="recommended",
                              title="Publish SPF",
                              detail="Without SPF, receivers lean hard on DKIM + heuristics. Expect deliverability problems."))
    if not dmarc_ok:
        sug.append(Suggestion(priority="recommended",
                              title="Publish DMARC (at least p=none)",
                              detail="Aggregate reports are essential for debugging delivery.",
                              tool_deeplink="/ui/wizards?wizard_key=dmarc.tuning"))
    if open_ports and 25 not in open_ports:
        sug.append(Suggestion(priority="info",
                              title="Only submission ports open",
                              detail="Port 25 is filtered (typical for residential ISPs). Outbound from this host will need a relay."))
    return sug

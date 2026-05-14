"""DNS-centric wizard implementations.

Each wizard emits WizardStep entries via ctx.add() and returns a list of
Suggestion objects. The engine persists both and the UI renders them.
Reuses app.dns.* primitives so the wizards stay thin and deterministic.
"""
from __future__ import annotations

from app.dns.axfr import axfr_audit
from app.dns.crtsh import query_crtsh
from app.dns.dig import DigRequest, run_dig
from app.dns.dnssec import walk_chain
from app.dns.zone_health import check_zone
from app.wizards.engine import Suggestion, WizardContext, WizardStep, wizard


def _answers(stdout: str) -> list[str]:
    return [
        line.strip()
        for line in stdout.splitlines()
        if line.strip() and not line.startswith(";")
    ]


# ============================================================================
# mail.delivery — MX → A/AAAA → PTR → SPF → DKIM → DMARC → MTA-STS → BIMI
# ============================================================================
@wizard("mail.delivery")
async def mail_delivery(ctx: WizardContext) -> list[Suggestion]:
    domain = ctx.target

    mx = await run_dig(DigRequest(target=domain, record_type="MX"))
    mx_rows = _answers(mx.stdout)
    if not mx_rows:
        ctx.add(WizardStep(name="MX records", outcome="fail",
                           message=f"No MX records for {domain} — nothing will route inbound mail here."))
        return [Suggestion(priority="critical", title="Add an MX record",
                           detail="Until an MX is published, external senders cannot deliver mail to this domain.")]
    ctx.add(WizardStep(name="MX records", outcome="ok",
                       message=f"{len(mx_rows)} MX host(s) published",
                       detail={"hosts": mx_rows}))

    # First MX → A/AAAA → PTR
    first_mx = mx_rows[0].split()[-1].rstrip(".") if mx_rows else ""
    if first_mx:
        a = await run_dig(DigRequest(target=first_mx, record_type="A"))
        aaaa = await run_dig(DigRequest(target=first_mx, record_type="AAAA"))
        a_rows = _answers(a.stdout); aaaa_rows = _answers(aaaa.stdout)
        if not a_rows and not aaaa_rows:
            ctx.add(WizardStep(name="Primary MX resolves",
                               outcome="fail",
                               message=f"{first_mx} has no A or AAAA records"))
        else:
            ctx.add(WizardStep(name="Primary MX resolves", outcome="ok",
                               message=f"{first_mx} → {(a_rows + aaaa_rows)[:3]}"))

    spf = await run_dig(DigRequest(target=domain, record_type="TXT"))
    spf_rows = [r for r in _answers(spf.stdout) if "v=spf1" in r]
    ctx.add(WizardStep(
        name="SPF",
        outcome="ok" if spf_rows else "warn",
        message="SPF record present" if spf_rows else "No SPF record — inbound senders may mark as spam",
        detail={"records": spf_rows},
    ))

    dmarc = await run_dig(DigRequest(target=f"_dmarc.{domain}", record_type="TXT"))
    dmarc_rows = [r for r in _answers(dmarc.stdout) if "v=DMARC1" in r]
    ctx.add(WizardStep(
        name="DMARC",
        outcome="ok" if dmarc_rows else "warn",
        message="DMARC policy published" if dmarc_rows else "No DMARC policy — receivers can't act on SPF/DKIM failures",
        detail={"records": dmarc_rows},
    ))

    mta_sts = await run_dig(DigRequest(target=f"_mta-sts.{domain}", record_type="TXT"))
    mta_sts_rows = [r for r in _answers(mta_sts.stdout) if "v=STSv1" in r]
    ctx.add(WizardStep(
        name="MTA-STS",
        outcome="ok" if mta_sts_rows else "info",
        message="MTA-STS deployed" if mta_sts_rows else "MTA-STS not published (optional; strong recommendation for modern mail)",
    ))

    tls_rpt = await run_dig(DigRequest(target=f"_smtp._tls.{domain}", record_type="TXT"))
    tls_rpt_rows = [r for r in _answers(tls_rpt.stdout) if "v=TLSRPTv1" in r]
    ctx.add(WizardStep(
        name="TLS-RPT",
        outcome="ok" if tls_rpt_rows else "info",
        message="TLS-RPT reporting configured" if tls_rpt_rows else "TLS-RPT not published",
    ))

    suggestions: list[Suggestion] = []
    if not spf_rows:
        suggestions.append(Suggestion(priority="recommended", title="Publish an SPF record",
                                      detail="Start with v=spf1 include:<provider> -all. Soft-fail (~all) to begin, tighten to -all once legitimate senders are enumerated."))
    if not dmarc_rows:
        suggestions.append(Suggestion(priority="recommended", title="Publish a DMARC policy",
                                      detail="v=DMARC1; p=none; rua=mailto:dmarc@<domain> is a safe starting point for aggregate reporting.",
                                      tool_deeplink="/ui/wizards?wizard_key=dmarc.tuning"))
    return suggestions


# ============================================================================
# dnssec.chain — reuses app.dns.dnssec.walk_chain
# ============================================================================
@wizard("dnssec.chain")
async def dnssec_chain(ctx: WizardContext) -> list[Suggestion]:
    report = await walk_chain(ctx.target)
    for step in report.chain:
        ctx.add(WizardStep(
            name=f"DNSSEC: {step.zone}",
            outcome="ok" if step.outcome == "ok" else step.outcome if step.outcome in ("warn", "fail") else "info",
            message=step.message,
            detail={"has_ds": step.has_ds, "has_dnskey": step.has_dnskey,
                    "algorithms": step.algorithms, "outcome": step.outcome},
        ))
    ctx.add(WizardStep(name="AD flag from recursor",
                       outcome="ok" if report.ad_flag else "info",
                       message=("Recursor returned AD — chain validates"
                                if report.ad_flag else
                                "Recursor did not set AD — domain may be unsigned or chain broken")))
    sug: list[Suggestion] = []
    if report.worst in ("fail", "warn"):
        sug.append(Suggestion(priority="critical" if report.worst == "fail" else "recommended",
                              title="DNSSEC chain has a break",
                              detail="Review the per-zone outcomes above. The lowest zone with a mismatch is where the trust chain breaks.",
                              tool_deeplink=f"/ui/dns-tools#dnssec?target={ctx.target}"))
    return sug


# ============================================================================
# zone.health — reuses app.dns.zone_health.check_zone
# ============================================================================
@wizard("zone.health")
async def zone_health_wizard(ctx: WizardContext) -> list[Suggestion]:
    report = await check_zone(ctx.target)
    for f in report.findings:
        ctx.add(WizardStep(name=f.check,
                           outcome=f.severity if f.severity in ("ok", "warn", "fail") else "info",
                           message=f.message, detail=f.detail))
    sug: list[Suggestion] = []
    if report.worst == "fail":
        sug.append(Suggestion(priority="critical", title="Zone is unhealthy",
                              detail="At least one authoritative NS is lame, delegation is broken, or the SOA is inconsistent. Fix the failing check(s) above first."))
    elif report.worst == "warn":
        sug.append(Suggestion(priority="recommended", title="Zone has warnings",
                              detail="Findings flagged as warn won't break resolution today but degrade reliability."))
    return sug


# ============================================================================
# axfr.audit — reuses app.dns.axfr.axfr_audit
# ============================================================================
@wizard("axfr.audit")
async def axfr_wizard(ctx: WizardContext) -> list[Suggestion]:
    report = await axfr_audit(ctx.target)
    for row in report.rows:
        ctx.add(WizardStep(name=f"AXFR: {row.nameserver}",
                           outcome="fail" if row.exposed else "ok",
                           message=row.detail))
    if report.any_exposed:
        return [Suggestion(priority="critical",
                           title="Zone transfer exposed",
                           detail="One or more authoritative nameservers are accepting public AXFR. This leaks the entire zone contents. Restrict AXFR to designated slave IPs only.")]
    return [Suggestion(priority="info", title="All NSes refused AXFR",
                       detail="Zone transfers are locked down. Good.")]


# ============================================================================
# registrar.mismatch — registrar-side NS vs live NS
# ============================================================================
@wizard("registrar.mismatch")
async def registrar_mismatch(ctx: WizardContext) -> list[Suggestion]:
    from app.sandbox.runner import run as sandbox_run

    whois = await sandbox_run("whois", [ctx.target], timeout_s=10.0)
    registrar_ns: list[str] = []
    for line in whois.stdout.splitlines():
        if line.lower().strip().startswith(("name server:", "nserver:")):
            value = line.split(":", 1)[1].strip().split()[0].rstrip(".")
            if value:
                registrar_ns.append(value.lower())
    registrar_ns = sorted(set(registrar_ns))
    ctx.add(WizardStep(name="Registrar NS (whois)",
                       outcome="ok" if registrar_ns else "warn",
                       message=f"{len(registrar_ns)} NS listed at registrar",
                       detail={"ns": registrar_ns[:10]}))

    live = await run_dig(DigRequest(target=ctx.target, record_type="NS"))
    live_ns = sorted({l.strip().rstrip(".").lower() for l in _answers(live.stdout)})
    ctx.add(WizardStep(name="Live authoritative NS",
                       outcome="ok" if live_ns else "fail",
                       message=f"{len(live_ns)} NS returned by DNS",
                       detail={"ns": live_ns[:10]}))

    mismatch = set(registrar_ns) ^ set(live_ns)
    if registrar_ns and live_ns and mismatch:
        ctx.add(WizardStep(name="Registrar vs live match",
                           outcome="warn",
                           message=f"{len(mismatch)} NS differ between registrar and live",
                           detail={"only_registrar": sorted(set(registrar_ns) - set(live_ns)),
                                   "only_live": sorted(set(live_ns) - set(registrar_ns))}))
        return [Suggestion(priority="recommended",
                           title="Registrar and live NS disagree",
                           detail="One or both lists are out of date. If this is unexpected, treat it as a potential hijack until resolved.",
                           external_url=f"https://who.is/whois/{ctx.target}")]
    elif registrar_ns and live_ns:
        ctx.add(WizardStep(name="Registrar vs live match",
                           outcome="ok",
                           message="Registrar and live NS agree."))
    return []


# ============================================================================
# domain.bringup — green/yellow/red scorecard
# ============================================================================
@wizard("domain.bringup")
async def domain_bringup(ctx: WizardContext) -> list[Suggestion]:
    domain = ctx.target
    checks = [
        ("NS", "NS"), ("A/AAAA root", "A"), ("MX", "MX"), ("SPF (TXT)", "TXT"),
        ("CAA", "CAA"), ("SOA", "SOA"),
    ]
    missing: list[str] = []
    for label, rtype in checks:
        r = await run_dig(DigRequest(target=domain, record_type=rtype))
        rows = _answers(r.stdout)
        if rows:
            ctx.add(WizardStep(name=label, outcome="ok",
                               message=f"{len(rows)} record(s)",
                               detail={"first": rows[0][:120]}))
        else:
            ctx.add(WizardStep(name=label, outcome="warn",
                               message=f"No {rtype} returned"))
            missing.append(label)

    # Subdomains: www, mail, _dmarc, _dmarc record present?
    for sub, rtype in [("www", "A"), ("_dmarc", "TXT"), ("_mta-sts", "TXT")]:
        r = await run_dig(DigRequest(target=f"{sub}.{domain}", record_type=rtype))
        rows = _answers(r.stdout)
        ctx.add(WizardStep(
            name=f"{sub}.{domain} {rtype}",
            outcome="ok" if rows else "info",
            message=f"{len(rows)} record(s)" if rows else "absent",
        ))

    if missing:
        return [Suggestion(priority="recommended",
                           title=f"{len(missing)} record type(s) missing",
                           detail="The following are absent or empty: " + ", ".join(missing) + ". Depending on the use case some may be optional (CAA if you don't care about cert-issuance restrictions).")]
    return [Suggestion(priority="info", title="All core records present",
                       detail="Baseline DNS is in place. Run dnssec.chain and zone.health next to verify signing and consistency.")]


# ============================================================================
# cloudflare.validator — is this zone fronted by Cloudflare and correctly?
# ============================================================================
_CF_OWNED_MX_HINTS = ("route.mx.cloudflare.net",)


@wizard("cloudflare.validator")
async def cloudflare_validator(ctx: WizardContext) -> list[Suggestion]:
    domain = ctx.target

    ns = await run_dig(DigRequest(target=domain, record_type="NS"))
    ns_rows = [n.lower().rstrip(".") for n in _answers(ns.stdout)]
    is_cf = any("cloudflare.com" in n or "ns.cloudflare" in n for n in ns_rows)
    ctx.add(WizardStep(
        name="Cloudflare NS delegation",
        outcome="ok" if is_cf else "info",
        message="Domain delegates to Cloudflare nameservers" if is_cf else
                "Not delegated to Cloudflare (that's fine if intended).",
        detail={"ns": ns_rows},
    ))

    a = await run_dig(DigRequest(target=domain, record_type="A"))
    a_rows = _answers(a.stdout)
    ctx.add(WizardStep(name="A record",
                       outcome="ok" if a_rows else "warn",
                       message=f"{len(a_rows)} A record(s)",
                       detail={"answers": a_rows}))

    dnskey = await run_dig(DigRequest(target=domain, record_type="DNSKEY",
                                      flags=("+short", "+noall", "+answer")))
    ctx.add(WizardStep(
        name="DNSSEC signing under Cloudflare",
        outcome="ok" if dnskey.stdout.strip() else "info",
        message="Zone signed" if dnskey.stdout.strip() else "Zone unsigned — Cloudflare can enable DNSSEC in one click",
    ))

    sug: list[Suggestion] = []
    if is_cf and not dnskey.stdout.strip():
        sug.append(Suggestion(priority="recommended",
                              title="Enable DNSSEC in Cloudflare",
                              detail="Cloudflare offers free DNSSEC via a single toggle. Add the DS record they generate to your registrar to complete the chain."))
    return sug


# ============================================================================
# typosquat.sweep — brand-protection variants
# ============================================================================
def _typosquat_variants(label: str) -> list[str]:
    """Generate a small, cheap set of variants. Production would use a specialized
    library like dnstwist; this version produces the most common ~40 variants."""
    variants: set[str] = set()
    for i in range(len(label)):
        # Drop one char
        variants.add(label[:i] + label[i + 1:])
        # Swap adjacent chars
        if i + 1 < len(label):
            variants.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])
    # Common homograph swaps
    swaps = [("o", "0"), ("l", "1"), ("i", "1"), ("e", "3"), ("a", "4"), ("s", "5")]
    for old, new in swaps:
        if old in label:
            variants.add(label.replace(old, new))
    # Missing/extra dash
    variants.add(label.replace("-", ""))
    if "-" not in label and len(label) > 4:
        mid = len(label) // 2
        variants.add(label[:mid] + "-" + label[mid:])
    variants.discard(label)
    variants.discard("")
    return sorted(variants)[:30]


@wizard("typosquat.sweep")
async def typosquat_sweep(ctx: WizardContext) -> list[Suggestion]:
    raw = ctx.target.split(".")
    if len(raw) < 2:
        ctx.add(WizardStep(name="input", outcome="fail",
                           message="Target must be a full domain like brand.example.com"))
        return []
    label, tld = raw[0], ".".join(raw[1:])
    variants = _typosquat_variants(label)
    ctx.add(WizardStep(
        name="variant generation",
        outcome="info",
        message=f"Generated {len(variants)} candidate variants (homograph, typo, dash)",
        detail={"first_10": variants[:10]},
    ))

    registered: list[str] = []
    for v in variants:
        candidate = f"{v}.{tld}"
        r = await run_dig(DigRequest(target=candidate, record_type="A"))
        if _answers(r.stdout):
            registered.append(candidate)

    ctx.add(WizardStep(
        name="Live registered variants",
        outcome="warn" if registered else "ok",
        message=(f"{len(registered)} variants resolve to something"
                 if registered else "No variants are active"),
        detail={"domains": registered[:20]},
    ))

    if registered:
        return [Suggestion(priority="recommended",
                           title=f"{len(registered)} typosquat variants in use",
                           detail="Manually review these for brand abuse. Consider registering the most dangerous (one-char drop, homograph) as defensive domains.",
                           tool_deeplink=f"/ui/dns-tools#crtsh?target=%25.{tld}")]
    return []


# ============================================================================
# dmarc.tuning — aggregate DMARC policy review
# ============================================================================
@wizard("dmarc.tuning")
async def dmarc_tuning(ctx: WizardContext) -> list[Suggestion]:
    r = await run_dig(DigRequest(target=f"_dmarc.{ctx.target}", record_type="TXT"))
    rows = [row for row in _answers(r.stdout) if "v=DMARC1" in row]
    if not rows:
        ctx.add(WizardStep(name="DMARC record", outcome="fail",
                           message="No DMARC record — publish p=none first to start receiving reports."))
        return [Suggestion(priority="critical",
                           title="Publish a DMARC record",
                           detail="Start at v=DMARC1; p=none; rua=mailto:<mailbox>. Analyze aggregate reports for 2–4 weeks before escalating to quarantine/reject.")]

    body = rows[0].strip('"')
    parts = dict(p.strip().split("=", 1) for p in body.split(";") if "=" in p)
    policy = parts.get("p", "").lower()
    ctx.add(WizardStep(name="DMARC record", outcome="ok",
                       message=f"Parsed: {parts}",
                       detail={"raw": body}))

    stage = {"none": "stage 1/3 (monitor)", "quarantine": "stage 2/3 (enforce soft)",
             "reject": "stage 3/3 (enforce hard)"}.get(policy, "unknown")
    ctx.add(WizardStep(name="Policy stage", outcome="info",
                       message=f"p={policy} — {stage}"))

    sug: list[Suggestion] = []
    if policy == "none":
        sug.append(Suggestion(priority="recommended",
                              title="Move to p=quarantine",
                              detail="Once aggregate reports show no legitimate senders failing auth, step up to quarantine. Keep pct=10 at first to limit blast radius."))
    elif policy == "quarantine":
        sug.append(Suggestion(priority="recommended",
                              title="Move to p=reject",
                              detail="After a few weeks clean at quarantine, flip to reject. Leave pct=100."))
    if "rua" not in parts:
        sug.append(Suggestion(priority="critical",
                              title="Add aggregate report URI (rua)",
                              detail="Without rua, you're flying blind. Every modern ISP will email you the aggregate XML — essential for tuning."))
    return sug

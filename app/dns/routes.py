from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record_in_scope as audit_async
from app.auth.deps import client_ip, require_permission
from app.db import session_scope
from app.dns.dig import DigRequest, DigResult, run_dig
from app.dns.propagation import PropagationReport, check_propagation
from app.dns.trace import TraceReport, run_trace
from app.models.user import User


router = APIRouter(prefix="/dns", tags=["dns"])


class DigInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    record_type: str = "A"
    resolver: str | None = None
    flags: list[str] = Field(default_factory=lambda: ["+short", "+noall", "+answer"])


@router.post("/dig", response_model=DigResult)
async def dig(
    request: Request,
    body: DigInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> DigResult:
    try:
        result = await run_dig(DigRequest(
            target=body.target,
            record_type=body.record_type,
            resolver=body.resolver,
            flags=tuple(body.flags),
        ))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    audit_async(user_id=user.id, action="dns.dig",
          target_type="domain", target_key=body.target,
          payload={
              "record_type": body.record_type,
              "resolver": body.resolver,
              "flags": body.flags,
              "returncode": result.returncode,
              "duration_ms": result.duration_ms,
              "truncated": result.truncated,
              "timed_out": result.timed_out,
          },
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"),
          outcome="ok" if result.returncode == 0 else "error")
    return result


class PropagationInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    record_type: str = "A"
    group_tag: str | None = None


@router.post("/propagation", response_model=PropagationReport)
async def propagation(
    request: Request,
    body: PropagationInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> PropagationReport:
    try:
        report = await check_propagation(body.target, body.record_type,
                                         user_id=user.id,
                                         group_tag=(body.group_tag or None))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    audit_async(user_id=user.id, action="dns.propagation",
          target_type="domain", target_key=body.target,
          payload={
              "record_type": body.record_type,
              "divergence": report.divergence,
              "unique_answers": list(report.unique_answers),
              "resolvers_ok": sum(1 for r in report.rows if r.ok),
              "resolvers_total": len(report.rows),
          },
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return report


class TraceInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    record_type: str = "A"
    include_external: bool = True
    group_tag: str | None = None
    mode: str = "answer"   # "answer" | "dnssec"


@router.post("/trace", response_model=TraceReport)
async def dns_trace(
    request: Request,
    body: TraceInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> TraceReport:
    """DNS hop-trace / troubleshoot -- query every resolver the caller can
    see (house + their personal + the portal's local BIND9) plus the
    authoritative NS servers for the target, in parallel, and identify
    which resolver diverges from authoritative.

    `mode="dnssec"` layers an extra DNSKEY + DS probe per resolver and
    produces a DNSSEC-aware diagnosis summary. See app/dns/trace.py."""
    mode = body.mode if body.mode in ("answer", "dnssec") else "answer"
    try:
        report = await run_trace(body.target, body.record_type,
                                 user_id=user.id,
                                 include_external=body.include_external,
                                 group_tag=(body.group_tag or None),
                                 mode=mode)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit_async(user_id=user.id, action="dns.trace",
          target_type="domain", target_key=body.target,
          payload={
              "record_type": body.record_type,
              "mode": mode,
              "resolvers_total": len(report.rows),
              "divergence": report.divergence,
              "point_of_divergence": report.point_of_divergence,
              "summary_severity": report.summary.severity,
          },
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return report


class ZoneHealthInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)


@router.post("/zone-health")
async def zone_health(
    request: Request,
    body: ZoneHealthInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.zone_health import check_zone
    report = await check_zone(body.target)
    audit_async(user_id=user.id, action="dns.zone_health",
          target_type="domain", target_key=body.target,
          payload={"worst": report.worst,
                   "ns_count": len(report.ns_records),
                   "findings": len(report.findings)},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {
        "domain": report.domain,
        "ns_records": report.ns_records,
        "soa_serials": report.soa_serials,
        "worst": report.worst,
        "findings": [
            {"severity": f.severity, "check": f.check, "message": f.message, "detail": f.detail}
            for f in report.findings
        ],
    }


@router.post("/axfr")
async def axfr(
    request: Request,
    body: ZoneHealthInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.axfr import axfr_audit
    report = await axfr_audit(body.target)
    audit_async(user_id=user.id, action="dns.axfr_audit",
          target_type="domain", target_key=body.target,
          payload={"any_exposed": report.any_exposed,
                   "nameservers": len(report.rows)},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"),
          outcome="warn" if report.any_exposed else "ok")
    return {
        "domain": report.domain,
        "any_exposed": report.any_exposed,
        "rows": [
            {"nameserver": r.nameserver, "exposed": r.exposed, "detail": r.detail}
            for r in report.rows
        ],
    }


class DnssecInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)


@router.post("/dnssec")
async def dnssec(
    request: Request,
    body: DnssecInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.dnssec import walk_chain
    report = await walk_chain(body.target)
    audit_async(user_id=user.id, action="dns.dnssec",
          target_type="domain", target_key=body.target,
          payload={"worst": report.worst, "ad_flag": report.ad_flag,
                   "chain_len": len(report.chain)},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"),
          outcome="warn" if report.worst in ("warn", "fail") else "ok")
    return {
        "target": report.target,
        "ad_flag": report.ad_flag,
        "worst": report.worst,
        "chain": [
            {"zone": s.zone or ".", "has_ds": s.has_ds, "has_dnskey": s.has_dnskey,
             "algorithms": s.algorithms, "outcome": s.outcome, "message": s.message}
            for s in report.chain
        ],
    }


class ReverseInput(BaseModel):
    ip: str = Field(..., min_length=1, max_length=64)
    resolver: str | None = None


@router.post("/reverse")
async def reverse_dns(
    request: Request,
    body: ReverseInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.reverse import reverse_lookup
    try:
        result = await reverse_lookup(body.ip, resolver=body.resolver)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit_async(user_id=user.id, action="dns.reverse",
          target_type="ip", target_key=body.ip,
          payload={"records": len(result.records), "resolver": body.resolver},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {
        "ip": result.ip,
        "reverse_zone": result.reverse_zone,
        "records": [{"ptr": r.ptr, "owner": r.owner} for r in result.records],
        "raw": result.raw,
    }


class CrtShInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    include_expired: bool = True
    include_subdomains: bool = True
    limit: int = Field(100, ge=1, le=1000)


@router.post("/crtsh")
async def crtsh(
    request: Request,
    body: CrtShInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.crtsh import query_crtsh
    try:
        result = await query_crtsh(
            body.target, limit=body.limit,
            include_expired=body.include_expired,
            include_subdomains=body.include_subdomains,
        )
    except RuntimeError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e))
    audit_async(user_id=user.id, action="dns.crtsh",
          target_type="domain", target_key=body.target,
          payload={"entries_total": result.entry_count,
                   "entries_shown": len(result.entries),
                   "unique_issuers": len(result.unique_issuers),
                   "subdomains_seen": len(result.subdomains_seen)},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {
        "target": result.target,
        "entry_count": result.entry_count,
        "unique_issuers": list(result.unique_issuers),
        "subdomains_seen": list(result.subdomains_seen),
        "entries": [
            {"crt_sh_id": e.crt_sh_id, "issuer_name": e.issuer_name,
             "common_name": e.common_name, "name_value": e.name_value,
             "not_before": e.not_before, "not_after": e.not_after,
             "entry_timestamp": e.entry_timestamp}
            for e in result.entries
        ],
    }


# ============================================================================
# WHOIS / bulk WHOIS / typosquat / rndc flush — new diagnostics.
# ============================================================================
class WhoisInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)


@router.post("/whois")
async def whois_single(
    request: Request,
    body: WhoisInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.whois_tool import whois_domain
    try:
        result = await whois_domain(body.target)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit_async(user_id=user.id, action="dns.whois", target_type="domain",
                target_key=body.target,
                payload={"registrar": (result["parsed"] or {}).get("registrar"),
                         "rc": result["returncode"]},
                ip=client_ip(request),
                user_agent=request.headers.get("user-agent"))
    return result


class BulkWhoisInput(BaseModel):
    targets: list[str] = Field(..., min_length=1, max_length=200)


@router.post("/whois-bulk")
async def whois_bulk_route(
    request: Request,
    body: BulkWhoisInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.whois_tool import whois_bulk
    result = await whois_bulk(body.targets)
    audit_async(user_id=user.id, action="dns.whois_bulk", target_type="batch",
                target_key=f"{len(body.targets)}-domains",
                payload={"total": result["total"]},
                ip=client_ip(request),
                user_agent=request.headers.get("user-agent"))
    return result


class TyposquatInput(BaseModel):
    target: str = Field(..., min_length=3, max_length=253)
    max_variants: int = Field(150, ge=10, le=500)


@router.post("/typosquat")
async def typosquat(
    request: Request,
    body: TyposquatInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.whois_tool import typosquat_scan
    try:
        result = await typosquat_scan(body.target, max_variants=body.max_variants)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit_async(user_id=user.id, action="dns.typosquat", target_type="domain",
                target_key=body.target,
                payload={"checked": result["variants_checked"],
                         "hits": result["total_hits"]},
                ip=client_ip(request),
                user_agent=request.headers.get("user-agent"))
    return result


class RndcFlushInput(BaseModel):
    zone: str | None = Field(None, min_length=1, max_length=253)
    view: str | None = Field(None, min_length=1, max_length=64)


@router.post("/rndc-flush")
async def rndc_flush_route(
    request: Request,
    body: RndcFlushInput,
    # `admin.services.restart` is the closest existing perm — flushing the
    # resolver cache is a service-level administrative action.
    user: User = Depends(require_permission("admin.services.restart")),
) -> dict:
    from app.dns.rndc_tool import rndc_flush
    try:
        result = await rndc_flush(zone=body.zone, view=body.view)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit_async(user_id=user.id, action="dns.rndc_flush",
                target_type="zone", target_key=body.zone or "ALL",
                payload={"rc": result["returncode"], "view": body.view},
                ip=client_ip(request),
                user_agent=request.headers.get("user-agent"))
    return result


# =========================================================================
# SPF / DKIM / DMARC validators (Mail Auth tab on /ui/dns-tools)
# =========================================================================
class _SpfInput(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)


@router.post("/spf-validate")
async def spf_validate(
    request: Request, body: _SpfInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.mail_auth import validate_spf
    try:
        return await validate_spf(body.domain)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")


class _DkimInput(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    selector: str = Field(..., min_length=1, max_length=63)


@router.post("/dkim-validate")
async def dkim_validate(
    request: Request, body: _DkimInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.mail_auth import validate_dkim
    try:
        return await validate_dkim(body.domain, body.selector)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")


@router.post("/dmarc-validate")
async def dmarc_validate(
    request: Request, body: _SpfInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.mail_auth import validate_dmarc
    try:
        return await validate_dmarc(body.domain)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")


# --- Paste-in linters: validate a raw record string without a DNS lookup ---
class _LintInput(BaseModel):
    raw_record: str = Field(..., min_length=1, max_length=4096)


@router.post("/spf-lint")
async def spf_lint(
    request: Request, body: _LintInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.mail_auth import _lint_spf_record
    return _lint_spf_record(body.raw_record.strip())


@router.post("/dkim-lint")
async def dkim_lint(
    request: Request, body: _LintInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.mail_auth import _lint_dkim_record
    return _lint_dkim_record(body.raw_record.strip())


@router.post("/dmarc-lint")
async def dmarc_lint(
    request: Request, body: _LintInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.dns.mail_auth import _lint_dmarc_record
    return _lint_dmarc_record(body.raw_record.strip())

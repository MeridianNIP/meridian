from __future__ import annotations

from datetime import UTC, datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.user import User
from app.models.vuln import VulnFinding, VulnScan

router = APIRouter(prefix="/admin/vuln", tags=["admin-vuln"])


_ALLOWED_STATUS = ("open", "fixed", "suppressed", "accepted_risk", "false_positive")
_ALLOWED_SEVERITY = ("critical", "high", "medium", "low", "info")


def _ref_urls(cve: str) -> dict[str, str]:
    """Canonical external references keyed by provider."""
    if not cve.upper().startswith("CVE-"):
        return {}
    return {
        "nvd": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "mitre": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}",
        "ghsa": f"https://github.com/advisories?query={cve}",
        "vulners": f"https://vulners.com/cve/{cve}",
        "debian": f"https://security-tracker.debian.org/tracker/{cve}",
        "ubuntu": f"https://ubuntu.com/security/{cve}",
    }


@router.get("/findings")
async def list_findings(
    severity: list[str] | None = Query(None),
    status_filter: list[str] | None = Query(None, alias="status"),
    source: str | None = Query(None, max_length=32),
    component: str | None = Query(None, max_length=128),
    limit: int = Query(500, ge=1, le=5000),
    user: User = Depends(require_permission("admin.vuln.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    stmt = select(VulnFinding)
    if severity:
        good = [s for s in severity if s in _ALLOWED_SEVERITY]
        if good:
            stmt = stmt.where(VulnFinding.severity.in_(good))
    if status_filter:
        good = [s for s in status_filter if s in _ALLOWED_STATUS]
        if good:
            stmt = stmt.where(VulnFinding.status.in_(good))
    if source:
        stmt = stmt.where(VulnFinding.source == source)
    if component:
        stmt = stmt.where(VulnFinding.component.ilike(f"%{component}%"))

    stmt = stmt.order_by(
        # critical first, then high, etc.  Postgres sorts on enum defn order by default,
        # but we store as TEXT in the ORM — emulate with a CASE expression via python.
        VulnFinding.discovered_at.desc(),
    ).limit(limit)

    rows = db.execute(stmt).scalars().all()
    severity_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = sorted(rows, key=lambda r: (severity_weight.get(r.severity, 5), -r.discovered_at.timestamp()))

    counts = dict(
        db.execute(
            select(VulnFinding.severity, func.count())
            .where(VulnFinding.status == "open")
            .group_by(VulnFinding.severity)
        ).all()
    )

    return {
        "counts_open_by_severity": {s: int(counts.get(s, 0)) for s in _ALLOWED_SEVERITY},
        "findings": [
            {
                "id": str(f.id),
                "cve_id": f.cve_id,
                "severity": f.severity,
                "cvss_score": float(f.cvss_score) if f.cvss_score is not None else None,
                "cvss_vector": f.cvss_vector,
                "component": f.component,
                "installed_version": f.installed_version,
                "fixed_version": f.fixed_version,
                "source": f.source,
                "description": (f.description or "")[:400],
                "references": list(f.references_ or []),
                "status": f.status,
                "discovered_at": f.discovered_at.isoformat(),
                "suppressed_until": f.suppressed_until.isoformat() if f.suppressed_until else None,
                "suppression_note": f.suppression_note,
                "ticket_ref": f.ticket_ref,
                "ext_refs": _ref_urls(f.cve_id),
            }
            for f in rows
        ],
    }


@router.get("/scans")
async def list_scans(
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(require_permission("admin.vuln.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> list[dict]:
    rows = db.execute(select(VulnScan).order_by(VulnScan.started_at.desc()).limit(limit)).scalars().all()
    return [
        {
            "id": str(s.id),
            "started_at": s.started_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "source": s.source,
            "status": s.status,
            "findings_count": s.findings_count,
        }
        for s in rows
    ]


@router.post("/scan", status_code=202)
async def trigger_scan(
    request: Request,
    user: User = Depends(require_permission("admin.vuln.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    from app.jobs.vuln import scan as vuln_scan

    try:
        async_result = vuln_scan.delay()
        task_id = async_result.id
    except Exception as e:  # - celery broker may be unavailable in dev
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"celery broker unavailable: {e}",
        )

    audit(
        db,
        user_id=user.id,
        action="admin.vuln.scan.trigger",
        target_type="vuln_scan",
        target_key=task_id,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"task_id": task_id}


class FindingPatch(BaseModel):
    status: str | None = Field(None, pattern=r"^(open|fixed|suppressed|accepted_risk|false_positive)$")
    suppression_note: str | None = Field(None, max_length=1024)
    suppressed_until: datetime | None = None
    ticket_ref: str | None = Field(None, max_length=128)


@router.patch("/findings/{finding_id}")
async def update_finding(
    request: Request,
    finding_id: uuid.UUID,
    body: FindingPatch,
    user: User = Depends(require_permission("admin.vuln.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    f = db.get(VulnFinding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    changed: dict = {}
    if body.status is not None:
        f.status = body.status
        changed["status"] = body.status
    if body.suppression_note is not None:
        f.suppression_note = body.suppression_note
        changed["note"] = "set"
    if body.suppressed_until is not None:
        f.suppressed_until = body.suppressed_until
        changed["suppressed_until"] = body.suppressed_until.isoformat()
    if body.ticket_ref is not None:
        f.ticket_ref = body.ticket_ref
        changed["ticket_ref"] = body.ticket_ref
    f.updated_at = datetime.now(UTC)
    db.commit()
    audit(
        db,
        user_id=user.id,
        action="admin.vuln.update",
        target_type="vuln_finding",
        target_key=f"{f.cve_id}:{f.component}:{f.installed_version}",
        payload=changed,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"ok": True}


class BulkPatch(BaseModel):
    finding_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=500)
    status: str = Field(..., pattern=r"^(suppressed|accepted_risk|false_positive|open)$")
    suppression_note: str | None = Field(None, max_length=1024)


@router.post("/findings/bulk-status")
async def bulk_status(
    request: Request,
    body: BulkPatch,
    user: User = Depends(require_permission("admin.vuln.manage")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    now = datetime.now(UTC)
    updated = 0
    for fid in body.finding_ids:
        f = db.get(VulnFinding, fid)
        if f is None:
            continue
        f.status = body.status
        if body.suppression_note is not None:
            f.suppression_note = body.suppression_note
        f.updated_at = now
        updated += 1
    db.commit()
    audit(
        db,
        user_id=user.id,
        action="admin.vuln.bulk_update",
        target_type="vuln_finding",
        target_key=f"batch:{len(body.finding_ids)}",
        payload={"status": body.status, "updated": updated, "note_set": body.suppression_note is not None},
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"updated": updated}

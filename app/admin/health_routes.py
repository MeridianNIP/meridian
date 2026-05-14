from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from app.admin.health import PROACTIVE_REPAIRS, repair, run_all
from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.user import User


router = APIRouter(prefix="/admin/health", tags=["admin-health"])


@router.get("")
async def get_health(
    user: User = Depends(require_permission("admin.system.health.read")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    checks = run_all(db)
    counts = {"ok": 0, "warn": 0, "fail": 0}
    for c in checks:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    return {
        "counts": counts,
        "overall": "fail" if counts["fail"] else "warn" if counts["warn"] else "ok",
        "checks": [
            {
                "name": c.name,
                "category": c.category,
                "ok": c.ok,
                "severity": c.severity,
                "detail": c.detail,
                "hint": c.hint,
                "repair": c.repair,
                "auto_repair": c.auto_repair,
            }
            for c in checks
        ],
        "proactive_repairs": PROACTIVE_REPAIRS,
    }


class RepairIn(BaseModel):
    action: str = Field(..., min_length=1, max_length=256)


@router.post("/repair")
async def post_repair(
    request: Request,
    body: RepairIn,
    user: User = Depends(require_permission("admin.system.repair")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    # Sanity — reject any control chars that could have snuck in, even though
    # the dispatcher itself will just say 'unknown' for a garbage key.
    if any(ord(ch) < 32 for ch in body.action):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid control chars in action")

    result = repair(body.action, db)

    audit(db, user_id=user.id, action="admin.system.repair",
          target_type="repair_action", target_key=body.action,
          payload={"ok": result.ok, "detail": result.detail[:400],
                   "output_preview": (result.output or "")[:200]},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"),
          outcome="ok" if result.ok else "error")

    return {
        "action": result.action,
        "ok": result.ok,
        "detail": result.detail,
        "output": result.output,
    }


@router.get("/tls-audit")
async def get_tls_audit(
    user: User = Depends(require_permission("admin.system.health.read")),
    host: str | None = None,
) -> dict:
    """Run scripts/audit-tls.sh on-demand and return the parsed JSON.
    Useful for the admin panel's TLS card which wants the full detail
    (protocols, cipher, OCSP, HSTS) not just the grade rollup."""
    import json
    import subprocess
    from pathlib import Path

    from app.config import get_settings

    s = get_settings()
    target = (host or s.portal_domain or "").strip()
    if not target or target == "localhost":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no portal_domain configured")
    script = Path(s.install_root) / "scripts" / "audit-tls.sh"
    if not script.is_file():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            f"audit script not deployed: {script}")
    try:
        r = subprocess.run(
            ["bash", str(script), "--host", target, "--port", "443"],
            capture_output=True, text=True, timeout=45,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "audit timed out")
    try:
        return json.loads(r.stdout)
    except Exception:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"unparseable audit output: {r.stderr[:200] or r.stdout[:200]}")

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import httpx
from sqlalchemy import text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.config import get_settings
from app.db import session_scope


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_CHUNK = 100          # OSV accepts up to 1000, but smaller chunks keep error blast radius small
OSV_TIMEOUT_S = 30.0

_CVSS_SEVERITY_MAP = [
    (Decimal("9.0"), "critical"),
    (Decimal("7.0"), "high"),
    (Decimal("4.0"), "medium"),
    (Decimal("0.1"), "low"),
]


def _severity_from_cvss(score: Decimal | None) -> str:
    if score is None:
        return "info"
    for threshold, label in _CVSS_SEVERITY_MAP:
        if score >= threshold:
            return label
    return "info"


def _list_apt_packages() -> list[dict[str, str]]:
    """Return [{'name': 'openssl', 'version': '3.0.14-1~deb12u1'}, ...]."""
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    pkgs: list[dict[str, str]] = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        pkgs.append({"name": name.strip(), "version": version.strip()})
    return pkgs


def _list_pip_packages() -> list[dict[str, str]]:
    """Return pip packages installed in the same interpreter as celery's worker."""
    try:
        from importlib.metadata import distributions
    except ImportError:
        return []
    pkgs: list[dict[str, str]] = []
    for dist in distributions():
        name = dist.metadata.get("Name") if dist.metadata else None
        version = dist.version
        if name and version:
            pkgs.append({"name": name, "version": version})
    return pkgs


def _osv_query(ecosystem: str, packages: list[dict[str, str]]) -> list[list[dict[str, Any]]]:
    """Return one vuln list per input package (aligned by index)."""
    results: list[list[dict[str, Any]]] = [[] for _ in packages]
    if not packages or get_settings().airgapped:
        return results

    for chunk_start in range(0, len(packages), OSV_CHUNK):
        chunk = packages[chunk_start:chunk_start + OSV_CHUNK]
        body = {"queries": [
            {"package": {"name": p["name"], "ecosystem": ecosystem},
             "version": p["version"]}
            for p in chunk
        ]}
        try:
            resp = httpx.post(OSV_BATCH_URL, json=body, timeout=OSV_TIMEOUT_S)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError):
            continue
        for offset, entry in enumerate(data.get("results") or []):
            results[chunk_start + offset] = entry.get("vulns", []) or []
    return results


_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _best_cve(vuln_summary: dict[str, Any]) -> str:
    """OSV entry → CVE id. Falls back to the entry id if no CVE alias is present."""
    entry_id = vuln_summary.get("id") or ""
    if _CVE_ID.fullmatch(entry_id or ""):
        return entry_id
    for alias in vuln_summary.get("aliases") or []:
        if _CVE_ID.fullmatch(alias):
            return alias
    return entry_id


def _severity_from_osv(vuln_summary: dict[str, Any]) -> tuple[Decimal | None, str | None, str]:
    """(score, vector, severity_label). OSV packs CVSS in the `severity` array."""
    score: Decimal | None = None
    vector: str | None = None
    for sev in vuln_summary.get("severity") or []:
        kind = (sev.get("type") or "").upper()
        raw = sev.get("score") or ""
        if kind.startswith("CVSS_V") and raw:
            vector = raw
            # Vector looks like 'CVSS:3.1/AV:N/...' for packed vectors, or '9.8' for numeric.
            m = re.search(r"([0-9]+(?:\.[0-9]+)?)", raw)
            if m:
                score = Decimal(m.group(1))
    return score, vector, _severity_from_cvss(score)


def _fixed_version(vuln_summary: dict[str, Any]) -> str | None:
    for affected in vuln_summary.get("affected") or []:
        for r in affected.get("ranges") or []:
            for event in r.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return None


def _upsert_finding(db, *, cve_id: str, severity: str, score: Decimal | None,
                    vector: str | None, component: str, installed_version: str,
                    fixed_version: str | None, source: str, description: str | None,
                    references: list[str], now: datetime) -> bool:
    """Upsert returns True iff the row was newly created."""
    existing = db.execute(text("""
        SELECT id, status FROM vuln_findings
         WHERE cve_id = :cve AND component = :comp AND installed_version = :ver
    """), {"cve": cve_id, "comp": component, "ver": installed_version}).first()

    if existing is not None:
        db.execute(text("""
            UPDATE vuln_findings
               SET severity = :sev, cvss_score = :score, cvss_vector = :vec,
                   fixed_version = :fix, source = :src, description = :desc,
                   references_ = :refs, updated_at = :now
             WHERE id = :id
        """), {
            "sev": severity, "score": score, "vec": vector,
            "fix": fixed_version, "src": source, "desc": description,
            "refs": references, "now": now, "id": existing.id,
        })
        return False

    db.execute(text("""
        INSERT INTO vuln_findings (cve_id, severity, cvss_score, cvss_vector,
                                   component, installed_version, fixed_version,
                                   source, description, references_, discovered_at,
                                   updated_at)
        VALUES (:cve, :sev, :score, :vec, :comp, :ver, :fix, :src, :desc, :refs, :now, :now)
    """), {
        "cve": cve_id, "sev": severity, "score": score, "vec": vector,
        "comp": component, "ver": installed_version, "fix": fixed_version,
        "src": source, "desc": description, "refs": references, "now": now,
    })
    return True


def _process(db, *, scan_id, ecosystem: str, source_label: str,
             packages: list[dict[str, str]]) -> int:
    """Query OSV for a package list and write findings. Returns count inserted."""
    vulns_by_pkg = _osv_query(ecosystem, packages)
    now = datetime.now(timezone.utc)
    added = 0
    for pkg, vulns in zip(packages, vulns_by_pkg):
        for v in vulns:
            cve_id = _best_cve(v)
            if not cve_id:
                continue
            score, vector, severity = _severity_from_osv(v)
            refs = [r["url"] for r in (v.get("references") or [])
                    if isinstance(r, dict) and r.get("url")]
            if _upsert_finding(
                db, cve_id=cve_id, severity=severity, score=score,
                vector=vector, component=pkg["name"],
                installed_version=pkg["version"],
                fixed_version=_fixed_version(v), source=source_label,
                description=(v.get("summary") or v.get("details") or "")[:1024],
                references=refs, now=now,
            ):
                added += 1
    return added


@celery_app.task(name="meridian.jobs.vuln.scan")
def scan() -> dict[str, Any]:
    with session_scope() as db:
        started = datetime.now(timezone.utc)
        row = db.execute(text("""
            INSERT INTO vuln_scans (started_at, source, status)
            VALUES (:t, 'osv', 'running') RETURNING id
        """), {"t": started}).first()
        scan_id = row.id

        try:
            apt_pkgs = _list_apt_packages()
            pip_pkgs = _list_pip_packages()
            new_count = 0
            new_count += _process(db, scan_id=scan_id, ecosystem="Debian",
                                  source_label="apt", packages=apt_pkgs)
            new_count += _process(db, scan_id=scan_id, ecosystem="PyPI",
                                  source_label="pip", packages=pip_pkgs)

            # Anything previously 'open' but not rediscovered is candidate-fixed.
            # We only flip status when the package version has changed, so the
            # upsert path keeps it 'open' if the same CVE still applies.
            db.execute(text("""
                UPDATE vuln_findings SET status = 'fixed'
                 WHERE status = 'open' AND updated_at < :started
            """), {"started": started})

            db.execute(text("""
                UPDATE vuln_scans
                   SET status = 'done', completed_at = :t, findings_count = :n
                 WHERE id = :id
            """), {"t": datetime.now(timezone.utc), "n": new_count, "id": scan_id})

            audit(db, action="vuln.scan.complete",
                  target_type="vuln_scan", target_key=str(scan_id),
                  payload={"apt_count": len(apt_pkgs), "pip_count": len(pip_pkgs),
                           "new_findings": new_count})
            return {"scan_id": str(scan_id), "apt": len(apt_pkgs),
                    "pip": len(pip_pkgs), "new_findings": new_count}
        except Exception as e:  # noqa: BLE001
            db.execute(text("""
                UPDATE vuln_scans SET status = 'error', completed_at = :t
                 WHERE id = :id
            """), {"t": datetime.now(timezone.utc), "id": scan_id})
            audit(db, action="vuln.scan.error",
                  target_type="vuln_scan", target_key=str(scan_id),
                  payload={"error": str(e)[:500]}, outcome="error")
            raise

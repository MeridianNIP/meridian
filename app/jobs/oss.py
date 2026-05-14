"""OSS component inventory + SBOM generator.

scan — enumerates installed apt + pip packages, upserts oss_components with
last_seen timestamps, soft-deletes components that disappeared, emits a
CycloneDX JSON SBOM snapshot, and alerts on strong-copyleft or AGPL license
adds.

No network calls: apt license metadata comes from `dpkg-query -W
-f='${Package}\t${Version}\t${License}\n'` (custom field not available by
default), so we fall back to reading /usr/share/doc/<pkg>/copyright for
SPDX-License-Identifier lines. Python license comes from the dist's
metadata.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from sqlalchemy import text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.db import session_scope

# Minimum SPDX → family mapping. Anything unknown lands in 'other' and the
# admin UI flags it for manual categorization.
_FAMILY: dict[str, str] = {
    "MIT": "permissive",
    "BSD-3-Clause": "permissive",
    "BSD-2-Clause": "permissive",
    "Apache-2.0": "permissive",
    "ISC": "permissive",
    "Unlicense": "public_domain",
    "Python-2.0": "permissive",
    "Zlib": "permissive",
    "X11": "permissive",
    "MPL-2.0": "weak_copyleft",
    "LGPL-2.1-only": "weak_copyleft",
    "LGPL-2.1-or-later": "weak_copyleft",
    "LGPL-3.0-only": "weak_copyleft",
    "LGPL-3.0-or-later": "weak_copyleft",
    "GPL-2.0-only": "strong_copyleft",
    "GPL-2.0-or-later": "strong_copyleft",
    "GPL-3.0-only": "strong_copyleft",
    "GPL-3.0-or-later": "strong_copyleft",
    "AGPL-3.0-only": "network_copyleft",
    "AGPL-3.0-or-later": "network_copyleft",
    "OFL-1.1": "font",
    "proprietary": "proprietary",
}

_SPDX_HEADER = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\-_ ]+)")


def _family(spdx: str) -> str:
    if not spdx:
        return "other"
    first = spdx.split(" OR ")[0].strip()
    return _FAMILY.get(first, "other")


def _apt_packages() -> list[dict[str, str]]:
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    rows: list[dict[str, str]] = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        rows.append(
            {"name": name.strip(), "version": version.strip(), "license_spdx": _apt_license(name.strip())}
        )
    return rows


def _apt_license(pkg: str) -> str:
    """Read /usr/share/doc/<pkg>/copyright and grab the first SPDX header."""
    p = Path(f"/usr/share/doc/{pkg}/copyright")
    if not p.is_file():
        return ""
    try:
        data = p.read_text(errors="replace", encoding="utf-8")[:16000]
    except OSError:
        return ""
    m = _SPDX_HEADER.search(data)
    return m.group(1).strip() if m else ""


def _pip_packages() -> list[dict[str, str]]:
    try:
        from importlib.metadata import distributions
    except ImportError:
        return []
    rows: list[dict[str, str]] = []
    for d in distributions():
        md = d.metadata
        name = (md.get("Name") if md else None) or ""
        if not name:
            continue
        license_field = (md.get("License-Expression") or md.get("License") or "").strip()
        # Classifier "License :: OSI Approved :: MIT License" style:
        if not license_field and md:
            for c in md.get_all("Classifier") or []:
                if c.startswith("License :: ") and "MIT" in c:
                    license_field = "MIT"
                    break
        rows.append(
            {
                "name": name,
                "version": d.version or "",
                "license_spdx": license_field,
                "homepage": (md.get("Home-page") if md else "") or "",
            }
        )
    return rows


@celery_app.task(name="meridian.jobs.oss.scan")
def scan() -> dict[str, Any]:
    now = datetime.now(UTC)
    apt = _apt_packages()
    pip = _pip_packages()
    added = 0
    license_changes = 0
    strong_copyleft_new: list[dict[str, str]] = []

    with session_scope() as db:
        # Start a scan run row
        scan_row = db.execute(
            text("""
            INSERT INTO oss_scan_runs (started_at, status)
            VALUES (:t, 'running') RETURNING id
        """),
            {"t": now},
        ).first()
        scan_id = scan_row.id

        # Upsert apt + pip
        for pkg in apt:
            _added, _license_changed = _upsert(
                db,
                name=pkg["name"],
                version=pkg["version"],
                category="os_package",
                license_spdx=pkg["license_spdx"],
                homepage=None,
                now=now,
            )
            added += int(_added)
            license_changes += int(_license_changed)
            family = _family(pkg["license_spdx"])
            if _added and family in ("strong_copyleft", "network_copyleft"):
                strong_copyleft_new.append(
                    {
                        "name": pkg["name"],
                        "version": pkg["version"],
                        "spdx": pkg["license_spdx"],
                        "family": family,
                    }
                )

        for pkg in pip:
            _added, _license_changed = _upsert(
                db,
                name=pkg["name"],
                version=pkg["version"],
                category="python",
                license_spdx=pkg["license_spdx"],
                homepage=pkg.get("homepage"),
                now=now,
            )
            added += int(_added)
            license_changes += int(_license_changed)
            family = _family(pkg["license_spdx"])
            if _added and family in ("strong_copyleft", "network_copyleft"):
                strong_copyleft_new.append(
                    {
                        "name": pkg["name"],
                        "version": pkg["version"],
                        "spdx": pkg["license_spdx"],
                        "family": family,
                    }
                )

        # Soft-delete anything not seen in this scan
        removed = (
            db.execute(
                text("""
            UPDATE oss_components SET removed_at = :t
             WHERE last_seen < :t AND removed_at IS NULL
        """),
                {"t": now},
            ).rowcount
            or 0
        )

        # Close the scan run
        db.execute(
            text("""
            UPDATE oss_scan_runs SET completed_at = :t, status = 'ok',
                   added_count = :a, removed_count = :r,
                   license_change_count = :lc,
                   detail = CAST(:d AS jsonb)
             WHERE id = :id
        """),
            {
                "t": datetime.now(UTC),
                "a": added,
                "r": removed,
                "lc": license_changes,
                "d": json.dumps(
                    {"apt_count": len(apt), "pip_count": len(pip), "strong_copyleft_new": strong_copyleft_new}
                ),
                "id": scan_id,
            },
        )

        # SBOM snapshot (CycloneDX lite — the full generator can be extended later)
        sbom = _build_sbom_cyclonedx(db)
        db.execute(
            text("""
            INSERT INTO sbom_snapshots (format, content, component_count, generated_by)
            VALUES ('cyclonedx_json', :c, :n, 'scheduled')
        """),
            {"c": json.dumps(sbom), "n": len(sbom.get("components") or [])},
        )

        audit(
            db,
            action="oss.scan",
            payload={
                "apt_count": len(apt),
                "pip_count": len(pip),
                "added": added,
                "removed": removed,
                "license_changes": license_changes,
                "strong_copyleft_new": len(strong_copyleft_new),
            },
        )

        if strong_copyleft_new:
            try:
                from app.notifications.dispatcher import dispatch

                dispatch(
                    db,
                    event_kind="oss.copyleft_new",
                    subject=f"{len(strong_copyleft_new)} new strong-copyleft component(s)",
                    body="\n".join(
                        f"{c['name']} {c['version']} · {c['spdx']} ({c['family']})"
                        for c in strong_copyleft_new
                    ),
                    payload={"components": strong_copyleft_new},
                )
            except Exception:
                pass

    return {
        "apt": len(apt),
        "pip": len(pip),
        "added": added,
        "removed": removed,
        "license_changes": license_changes,
        "strong_copyleft_new": strong_copyleft_new,
    }


def _upsert(
    db, *, name: str, version: str, category: str, license_spdx: str, homepage: str | None, now: datetime
) -> tuple[bool, bool]:
    family = _family(license_spdx)
    existing = db.execute(
        text("""
        SELECT id, license_spdx FROM oss_components
         WHERE name = :n AND version = :v AND category = :c
    """),
        {"n": name, "v": version, "c": category},
    ).first()

    if existing is not None:
        license_changed = existing.license_spdx != license_spdx
        db.execute(
            text("""
            UPDATE oss_components
               SET last_seen = :t, license_spdx = :s, license_family = :f,
                   homepage_url = COALESCE(:h, homepage_url),
                   removed_at = NULL
             WHERE id = :id
        """),
            {"t": now, "s": license_spdx or "unknown", "f": family, "h": homepage, "id": existing.id},
        )
        return (False, license_changed)

    db.execute(
        text("""
        INSERT INTO oss_components (name, version, category, license_spdx,
                                    license_family, homepage_url,
                                    first_seen, last_seen)
        VALUES (:n, :v, :c, :s, :f, :h, :t, :t)
    """),
        {
            "n": name,
            "v": version,
            "c": category,
            "s": license_spdx or "unknown",
            "f": family,
            "h": homepage,
            "t": now,
        },
    )
    return (True, False)


def _build_sbom_cyclonedx(db) -> dict:
    rows = db.execute(
        text("""
        SELECT name, version, category, license_spdx, homepage_url
          FROM oss_components WHERE removed_at IS NULL
    """)
    ).all()
    components = []
    for r in rows:
        components.append(
            {
                "type": "library",
                "name": r.name,
                "version": r.version,
                "licenses": [{"license": {"id": r.license_spdx}}] if r.license_spdx else [],
                "externalReferences": (
                    [{"type": "website", "url": r.homepage_url}] if r.homepage_url else []
                ),
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [{"vendor": "Meridian", "name": "oss.scan"}],
        },
        "components": components,
    }

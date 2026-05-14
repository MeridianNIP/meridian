"""Update / upgrade helpers.

Three capabilities:

  1. `apt_check()` — returns the `apt list --upgradable` output, parsed into
     structured rows. No side-effects.

  2. `check_drift()` — compares installed apt + pip versions against the
     pinned entries in `version_manifest`, writes unresolved rows to
     `version_drift`, and marks previously-open rows as resolved when the
     version catches up.

  3. `pre_snapshot()` — invokes `scripts/backup.sh`, records the resulting
     bundle in `update_snapshots`. Designed to be called from the jobs table
     on the 'pre-update-snapshot' trigger (the default seed) or on demand
     from the admin UI.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.config import get_settings
from app.db import session_scope


# ============================================================================
# apt list --upgradable parser
# ============================================================================
_UPGRADABLE_LINE = re.compile(
    r"^(?P<pkg>[^/\s]+)/(?P<repo>[^\s]+)\s+"
    r"(?P<new_ver>\S+)\s+(?P<arch>\S+)\s+"
    r"\[upgradable from:\s*(?P<old_ver>[^\]]+)\]"
)


@dataclass(frozen=True)
class UpgradableRow:
    package: str
    from_version: str
    to_version: str
    repo: str
    is_security: bool


def _parse_upgradable(output: str) -> list[UpgradableRow]:
    rows: list[UpgradableRow] = []
    for line in output.splitlines():
        m = _UPGRADABLE_LINE.match(line.strip())
        if not m:
            continue
        repo = m.group("repo")
        rows.append(UpgradableRow(
            package=m.group("pkg"),
            from_version=m.group("old_ver").strip(),
            to_version=m.group("new_ver").strip(),
            repo=repo,
            # Debian's security archive names its repo 'debian-security' or similar.
            is_security=("security" in repo.lower()),
        ))
    return rows


@celery_app.task(name="meridian.jobs.upgrade.apt_check")
def apt_check() -> dict[str, Any]:
    """Return the parsed output of apt list --upgradable. Read-only."""
    try:
        subprocess.run(
            ["apt-get", "update", "-qq"],
            capture_output=True, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        r = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": str(e), "rows": []}
    rows = _parse_upgradable(r.stdout or "")
    sec = sum(1 for row in rows if row.is_security)
    return {
        "total": len(rows),
        "security": sec,
        "stale_cache_note": "apt-get update may have failed silently in airgapped installs",
        "rows": [
            {"package": row.package, "from_version": row.from_version,
             "to_version": row.to_version, "repo": row.repo,
             "is_security": row.is_security}
            for row in rows
        ],
    }


# ============================================================================
# Drift detection (dpkg + pip vs version_manifest)
# ============================================================================
def _dpkg_versions() -> dict[str, str]:
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    out: dict[str, str] = {}
    for line in r.stdout.splitlines():
        if "\t" in line:
            name, ver = line.split("\t", 1)
            out[name.strip()] = ver.strip()
    return out


def _pip_versions() -> dict[str, str]:
    try:
        from importlib.metadata import distributions
    except ImportError:
        return {}
    out: dict[str, str] = {}
    for dist in distributions():
        name = (dist.metadata.get("Name") if dist.metadata else None) or ""
        if name:
            out[name.lower()] = dist.version or ""
    return out


def _detect_debian_major() -> str:
    try:
        with open("/etc/os-release") as f:
            kv = dict(
                line.strip().split("=", 1)
                for line in f if "=" in line
            )
    except OSError:
        return "13"
    vid = (kv.get("VERSION_ID", "").strip('"') or "13").split(".")[0]
    return vid if vid in ("12", "13") else "13"


def _severity(found: str, expected: str, min_v: str | None, max_v: str | None) -> str:
    if found == expected:
        return "ok"
    # No version-comparison lib pulled in for the first cut — admins read the
    # numbers and decide. The table distinguishes warn vs block so the UI can
    # color on "has min/max been violated" rather than guess.
    if (min_v and found < min_v) or (max_v and found > max_v):
        return "block"
    return "warn"


@celery_app.task(name="meridian.jobs.upgrade.check_drift")
def check_drift() -> dict[str, Any]:
    with session_scope() as db:
        debian_major = _detect_debian_major()
        now = datetime.now(timezone.utc)

        manifest = db.execute(text("""
            SELECT component_name, category, pinned_version, min_version, max_version
              FROM version_manifest
             WHERE tested_on_debian = :d OR tested_on_debian LIKE '%' || :d || '%'
        """), {"d": debian_major}).all()

        dpkg_map = _dpkg_versions()
        pip_map = _pip_versions()

        added = 0
        resolved = 0
        for comp, category, pinned, min_v, max_v in manifest:
            found: str | None = None
            if category == "os_package":
                found = dpkg_map.get(comp)
            elif category == "python":
                found = pip_map.get(comp.lower())
            else:
                continue

            if found is None:
                continue  # not installed — outside the drift model for now

            sev = _severity(found, pinned, min_v, max_v)

            existing = db.execute(text("""
                SELECT id, severity, resolved_at FROM version_drift
                 WHERE component_name = :c AND category = :cat AND resolved_at IS NULL
                 ORDER BY detected_at DESC LIMIT 1
            """), {"c": comp, "cat": category}).first()

            if sev == "ok":
                if existing is not None:
                    db.execute(text("""
                        UPDATE version_drift SET resolved_at = :t WHERE id = :id
                    """), {"t": now, "id": existing.id})
                    resolved += 1
                continue

            if existing is not None and existing.severity == sev:
                continue  # still drifting at the same severity — skip insert

            if existing is not None:
                db.execute(text("""
                    UPDATE version_drift SET resolved_at = :t WHERE id = :id
                """), {"t": now, "id": existing.id})

            db.execute(text("""
                INSERT INTO version_drift (component_name, category, found_version,
                                           expected_version, severity, detected_at)
                VALUES (:c, :cat, :found, :exp, :sev, :t)
            """), {
                "c": comp, "cat": category, "found": found,
                "exp": pinned, "sev": sev, "t": now,
            })
            added += 1

        audit(db, action="updates.drift.scan",
              payload={"debian_major": debian_major,
                       "manifest_rows": len(manifest),
                       "drift_added": added, "drift_resolved": resolved})
        return {"debian_major": debian_major, "manifest_rows": len(manifest),
                "drift_added": added, "drift_resolved": resolved}


# ============================================================================
# Pre-upgrade snapshot (wraps scripts/backup.sh)
# ============================================================================
@celery_app.task(name="meridian.jobs.upgrade.pre_snapshot")
def pre_snapshot(reason: str = "pre-upgrade", created_by: str | None = None) -> dict[str, Any]:
    backup_sh = get_settings().install_root / "scripts" / "backup.sh"
    if not backup_sh.is_file():
        return {"error": f"backup.sh missing at {backup_sh}", "ok": False}

    try:
        r = subprocess.run(
            ["sudo", "-n", str(backup_sh)],
            capture_output=True, text=True, timeout=600, check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return {"error": f"backup.sh failed to launch: {e}", "ok": False}

    # backup.sh announces its output on the "Backup complete:" line.
    path = None
    for line in (r.stdout or "").splitlines():
        if "Backup complete:" in line:
            # Strip ANSI color codes and pull out the path up to the size.
            cleaned = re.sub(r"\x1b\[[0-9;]*m", "", line)
            m = re.search(r"Backup complete:\s+(\S+)", cleaned)
            if m:
                path = m.group(1)
                break

    if r.returncode != 0 or path is None:
        return {
            "ok": False,
            "returncode": r.returncode,
            "stderr_tail": (r.stderr or "").strip().splitlines()[-12:],
        }

    p = Path(path)
    size = p.stat().st_size if p.is_file() else None

    with session_scope() as db:
        row = db.execute(text("""
            INSERT INTO update_snapshots (reason, storage_path, size_bytes,
                                          db_included, config_included, files_included,
                                          created_at, created_by)
            VALUES (:r, :path, :size, TRUE, TRUE, FALSE, :t, :by)
            RETURNING id
        """), {
            "r": reason, "path": str(p), "size": size,
            "t": datetime.now(timezone.utc),
            "by": created_by,
        }).first()
        audit(db, action="updates.snapshot.create",
              target_type="update_snapshot", target_key=str(row.id),
              payload={"reason": reason, "path": str(p), "size_bytes": size})
        return {"ok": True, "snapshot_id": str(row.id), "path": str(p),
                "size_bytes": size}


# ============================================================================
# System update + reboot runner.
#
# A privileged helper script at scripts/system-update.sh runs apt + reboot.
# Meridian shells out via `sudo` — a file at /etc/sudoers.d/meridian-updates
# grants the `meridian` user passwordless NOPASSWD access to that one
# script (and nothing else). The installer ships that sudoers drop-in.
# ============================================================================
_UPDATE_SCRIPT = "/opt/meridian/scripts/system-update.sh"
_OUTPUT_TAIL_BYTES = 8 * 1024


def _update_row(db, run_id: str, **fields) -> None:
    setters = ", ".join(f"{k} = :{k}" for k in fields)
    if not setters:
        return
    db.execute(text(
        f"UPDATE system_update_runs SET {setters} WHERE id = :run_id"
    ), {**fields, "run_id": run_id})


@celery_app.task(name="meridian.jobs.upgrade.run_update", bind=True)
def run_update(self, run_id: str) -> dict[str, Any]:
    """Execute scripts/system-update.sh for a system_update_runs row.

    Pulls `reboot` out of the row, marks running, shells out, captures
    exit code + last 8 KB of output, and marks ok/failed. If reboot=True
    the script schedules a detached `systemctl reboot` 10 s after exit —
    so this task typically completes cleanly before the host goes down.
    """
    with session_scope() as db:
        row = db.execute(text(
            "SELECT reboot, status FROM system_update_runs WHERE id = :id"
        ), {"id": run_id}).first()
        if row is None:
            return {"error": "run not found"}
        if row.status not in ("pending", "running"):
            return {"error": f"run already {row.status}"}
        reboot = bool(row.reboot)

        now = datetime.now(timezone.utc)
        _update_row(db, run_id, status="running", started_at=now)
        audit(db, action="admin.update.start",
              target_type="system_update_run", target_key=run_id,
              payload={"reboot": reboot})

    args = ["sudo", "-n", _UPDATE_SCRIPT]
    if reboot:
        args.append("--reboot")
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=30 * 60, check=False)
        rc = proc.returncode
        output = (proc.stdout + "\n---stderr---\n" + proc.stderr)
    except subprocess.TimeoutExpired as e:
        rc = 124
        output = f"timeout after 30 min\nstdout so far:\n{e.stdout or ''}\nstderr so far:\n{e.stderr or ''}"
    except OSError as e:
        rc = 127
        output = f"could not invoke {_UPDATE_SCRIPT}: {e}"

    tail = output[-_OUTPUT_TAIL_BYTES:]
    reboot_required = Path("/var/run/reboot-required").exists()

    with session_scope() as db:
        now = datetime.now(timezone.utc)
        status = "ok" if rc == 0 else "failed"
        _update_row(db, run_id, status=status, completed_at=now,
                    exit_code=rc, output_tail=tail,
                    reboot_required=reboot_required)
        audit(db, action="admin.update.complete",
              target_type="system_update_run", target_key=run_id,
              payload={"exit_code": rc, "reboot_scheduled": reboot,
                       "reboot_required_after": reboot_required},
              outcome="ok" if status == "ok" else "error")
    return {"ok": rc == 0, "exit_code": rc, "reboot_scheduled": reboot}


@celery_app.task(name="meridian.jobs.upgrade.fire_scheduled")
def fire_scheduled() -> dict[str, Any]:
    """Beat-triggered every minute. Fires any pending system_update_runs
    whose scheduled_for has elapsed. Enqueues run_update for each."""
    now = datetime.now(timezone.utc)
    fired: list[str] = []
    with session_scope() as db:
        rows = db.execute(text("""
            SELECT id FROM system_update_runs
             WHERE status = 'pending'
               AND scheduled_for IS NOT NULL
               AND scheduled_for <= :now
             ORDER BY scheduled_for ASC
             LIMIT 5
        """), {"now": now}).fetchall()
        for r in rows:
            fired.append(str(r.id))
    for rid in fired:
        run_update.delay(rid)
    return {"fired": len(fired), "run_ids": fired}

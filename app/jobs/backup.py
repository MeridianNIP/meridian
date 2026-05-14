"""Scheduled backup + WAL shipping.

These thin Celery tasks wrap the operator-authored shell scripts under
scripts/ so behaviour stays consistent between `meridian-nip backup` run
manually and the scheduled beat trigger. If a script is missing (custom
install path, airgapped tarball without them), the task returns an error
dict rather than raising — so the schedule keeps ticking.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.config import get_settings
from app.db import session_scope


def _script_path(name: str) -> Path:
    return get_settings().install_root / "scripts" / name


def _run_script(script: Path, args: list[str] | None = None,
                timeout_s: int = 900) -> tuple[int, str, str]:
    if not script.is_file():
        return 127, "", f"script missing: {script}"
    argv = ["sudo", "-n", str(script), *(args or [])]
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout_s, check=False)
        return r.returncode, r.stdout or "", r.stderr or ""
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", f"{type(e).__name__}: {e}"


_BACKUP_COMPLETE = re.compile(r"Backup complete:\s+(\S+)")


def _parse_backup_output(stdout: str) -> str | None:
    for line in stdout.splitlines():
        cleaned = re.sub(r"\x1b\[[0-9;]*m", "", line)
        m = _BACKUP_COMPLETE.search(cleaned)
        if m:
            return m.group(1)
    return None


# ============================================================================
# full_db — pg_dump + /etc/meridian + uploads, invoked via scripts/backup.sh
# ============================================================================
@celery_app.task(name="meridian.jobs.backup.full_db")
def full_db() -> dict[str, Any]:
    script = _script_path("backup.sh")
    rc, stdout, stderr = _run_script(script, timeout_s=1800)
    path = _parse_backup_output(stdout) if rc == 0 else None

    ok = rc == 0 and path is not None
    with session_scope() as db:
        audit(db, action="backup.full_db",
              payload={"ok": ok, "returncode": rc, "path": path,
                       "stderr_tail": (stderr or "").strip().splitlines()[-6:]},
              outcome="ok" if ok else "error")
    return {"ok": ok, "returncode": rc, "path": path,
            "stderr_tail": (stderr or "").splitlines()[-6:]}


# ============================================================================
# rotate — keep 7 daily / 4 weekly / 3 monthly per the schema seed description
# ============================================================================
def _by_mtime(paths: list[Path]) -> list[Path]:
    return sorted(paths, key=lambda p: p.stat().st_mtime, reverse=True)


@celery_app.task(name="meridian.jobs.backup.rotate")
def rotate() -> dict[str, Any]:
    root = get_settings().data_root / "backups" / "full"
    if not root.is_dir():
        with session_scope() as db:
            audit(db, action="backup.rotate",
                  payload={"skipped": f"{root} not found"})
        return {"skipped": f"{root} not found"}

    now = datetime.now(timezone.utc)
    dailies: list[Path] = []
    weeklies: list[Path] = []
    monthlies: list[Path] = []

    for p in root.glob("meridian-backup-*.tar.zst"):
        mtime = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc)
        age = now - mtime
        if age <= timedelta(days=7):
            dailies.append(p)
        elif age <= timedelta(days=30):
            weeklies.append(p)
        else:
            monthlies.append(p)

    deleted: list[str] = []
    # Keep: 7 newest daily, 4 newest weekly, 3 newest monthly. Everything else goes.
    for bucket, keep in ((dailies, 7), (weeklies, 4), (monthlies, 3)):
        victims = _by_mtime(bucket)[keep:]
        for v in victims:
            try:
                v.unlink()
                deleted.append(v.name)
            except OSError:
                pass

    with session_scope() as db:
        audit(db, action="backup.rotate",
              payload={"kept_daily": min(len(dailies), 7),
                       "kept_weekly": min(len(weeklies), 4),
                       "kept_monthly": min(len(monthlies), 3),
                       "deleted": len(deleted)})
    return {"kept": {"daily": min(len(dailies), 7),
                     "weekly": min(len(weeklies), 4),
                     "monthly": min(len(monthlies), 3)},
            "deleted": deleted}


# ============================================================================
# wal_ship — archive WAL segments for PITR (wraps scripts/wal_archive.sh)
# ============================================================================
@celery_app.task(name="meridian.jobs.backup.wal_ship")
def wal_ship() -> dict[str, Any]:
    script = _script_path("wal_archive.sh")
    rc, stdout, stderr = _run_script(script, timeout_s=60)
    ok = rc == 0
    with session_scope() as db:
        audit(db, action="backup.wal_ship",
              payload={"ok": ok, "returncode": rc,
                       "stdout_tail": (stdout or "").splitlines()[-3:],
                       "stderr_tail": (stderr or "").splitlines()[-3:]},
              outcome="ok" if ok else "error")
    return {"ok": ok, "returncode": rc}

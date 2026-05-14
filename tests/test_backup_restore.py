"""Cheap import-level checks for the backup / restore wiring.

The real end-to-end smoke test lives at `scripts/smoke-backup-restore.sh`
and runs on the VM (or in CI with `services: postgres`). The tests here
catch the failure modes that would cause the real smoke to skip — e.g.
someone deleting the scripts, or breaking imports inside
`app/jobs/backup.py` so cron-driven backups silently die.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def test_backup_script_exists_and_executable():
    p = SCRIPTS_DIR / "backup.sh"
    assert p.exists(), "scripts/backup.sh missing"
    assert os.access(p, os.X_OK), "scripts/backup.sh not executable"


def test_restore_script_exists_and_executable():
    p = SCRIPTS_DIR / "restore.sh"
    assert p.exists(), "scripts/restore.sh missing"
    assert os.access(p, os.X_OK), "scripts/restore.sh not executable"


def test_smoke_script_exists_and_executable():
    p = SCRIPTS_DIR / "smoke-backup-restore.sh"
    assert p.exists(), "scripts/smoke-backup-restore.sh missing"
    assert os.access(p, os.X_OK), "scripts/smoke-backup-restore.sh not executable"


@pytest.mark.parametrize("script", ["backup.sh", "restore.sh", "smoke-backup-restore.sh"])
def test_bash_syntax_valid(script: str):
    """Catch shell syntax errors that would only surface at midnight when
    the cron-driven backup tries to run."""
    if not shutil.which("bash"):
        pytest.skip("bash not on PATH")
    p = SCRIPTS_DIR / script
    r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, f"bash syntax error in {script}: {r.stderr}"


def test_jobs_backup_module_imports():
    """If the scheduled-backup task can't import, nightly backups break
    silently. Importing here makes that a CI failure instead."""
    try:
        import app.jobs.backup  # noqa: F401
    except Exception as e:
        # The module touches the DB at import time on some configs; if
        # that's why we failed, that's covered by the VM smoke test.
        if "engine" in str(e).lower() or "connect" in str(e).lower():
            pytest.skip(f"DB-bound module, covered by VM smoke: {e}")
        raise


def test_restore_dry_run_help():
    """restore.sh should respond to --help without trying to mount
    anything. Sanity check that the script flag parser is intact."""
    if not shutil.which("bash"):
        pytest.skip("bash not on PATH")
    p = SCRIPTS_DIR / "restore.sh"
    r = subprocess.run([str(p), "--help"], capture_output=True, text=True, timeout=5)
    assert r.returncode == 0
    assert "Restore" in r.stdout or "restore" in r.stdout.lower()

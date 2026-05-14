"""Walks every Python module under app/ and imports it.

Catches: syntax errors, missing imports, top-level NameErrors, circular
imports. Does NOT touch the DB — module import time must remain side-effect
free (the codebase already follows that convention; this test enforces it).

Modules that depend on system libraries unavailable in some dev sandboxes
(LDAP wheels need libldap2-dev / libsasl2-dev) get skipped rather than
failed — CI installs the full requirements and exercises them there.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import app


# If the ImportError chain references one of these top-level packages, the
# test gets skipped (missing system-level dep, not a bug in our code).
_OPTIONAL_DEPS = {
    "ldap", "ldap3",            # python-ldap, ldap3
    "msgraph", "azure",         # msgraph-sdk
    "infoblox_client",          # infoblox-client
    "paramiko", "netmiko",      # netmiko / paramiko
    "pyshark",                  # pyshark
    "celery",                   # celery only present in prod venv
    "redbeat",
    "whois",                    # python-whois
    "acme", "josepy",           # ACME
    "aiosmtplib",
    "pip_audit", "cyclonedx", "spdx_tools",
    "structlog",
    "infoblox",
}


def _iter_modules():
    # Walk the filesystem rather than pkgutil.walk_packages — the latter
    # imports every package __init__.py during collection, which fails
    # in a sandbox without PostgreSQL listening.
    pkg_path = Path(app.__file__).parent
    for py in pkg_path.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        if py.name == "__main__.py":
            continue
        rel = py.relative_to(pkg_path.parent)
        # e.g. app/auth/deps.py → app.auth.deps;  app/__init__.py → app
        dotted = ".".join(rel.with_suffix("").parts)
        if dotted.endswith(".__init__"):
            dotted = dotted[: -len(".__init__")]
        yield dotted


# Modules that intentionally touch the DB at import time (e.g. celery_app
# loads the beat schedule from the jobs table on startup). They get
# imported successfully on the VM where Postgres is up; the smoke sandbox
# skips them rather than try to start a database.
# Modules that intentionally touch the DB at import time (e.g. celery_app
# loads the beat schedule from the jobs table on startup). They get
# imported successfully on the VM where Postgres is up; the smoke sandbox
# skips them rather than try to start a database. The whole app.jobs
# package and app.celery_app fall into this bucket because importing any
# job module pulls in scheduler.load_schedule_from_db() via celery_app.
_DB_AT_IMPORT_PREFIXES = (
    "app.celery_app",
    "app.jobs",
    "app.logging.shipper",
    "app.monitors.collector",
)


@pytest.mark.parametrize("module_name", list(_iter_modules()))
def test_module_imports(module_name: str) -> None:
    if any(module_name == p or module_name.startswith(p + ".") for p in _DB_AT_IMPORT_PREFIXES):
        pytest.skip(f"{module_name} touches DB at import time; covered by VM smoke")
    try:
        importlib.import_module(module_name)
    except ImportError as e:
        missing = (e.name or "").split(".", 1)[0]
        if missing in _OPTIONAL_DEPS:
            pytest.skip(f"optional dep missing: {missing}")
        raise

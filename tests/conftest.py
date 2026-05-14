from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Defaults that let pure-Python tests run without /etc/meridian/* present.
# DB-touching tests opt in by setting MERIDIAN_DB_DSN and marking themselves
# with @pytest.mark.slow.
os.environ.setdefault("MERIDIAN_PORTAL_DOMAIN", "test.invalid")
os.environ.setdefault("MERIDIAN_INSTALL_ROOT", str(REPO_ROOT))
os.environ.setdefault("MERIDIAN_DATA_ROOT", str(REPO_ROOT / ".tmp" / "data"))
os.environ.setdefault("MERIDIAN_LOG_ROOT", str(REPO_ROOT / ".tmp" / "log"))


def _have_db() -> bool:
    # A test that wants a real DB declares it. We don't open a connection
    # here — that would fail before the test gets to skip itself.
    return bool(os.environ.get("MERIDIAN_DB_DSN"))


@pytest.fixture(scope="session")
def db_required():
    if not _have_db():
        pytest.skip("MERIDIAN_DB_DSN not set; skipping DB-touching test")

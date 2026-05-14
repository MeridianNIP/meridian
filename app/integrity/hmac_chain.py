from __future__ import annotations

import hmac
import json
from functools import lru_cache
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings, load_key


TAMPER_EVIDENT_TABLES = (
    "audit_events",
    "license",
    "license_activations",
    "license_verifications",
    "cert_events",
    "approvals",
    "impersonations",
    "update_history",
)


@lru_cache(maxsize=1)
def _hmac_key() -> bytes:
    return load_key(get_settings().row_hmac_key_path)


def canonicalize(fields: dict[str, Any]) -> bytes:
    # Stable, deterministic encoding: sorted keys, no whitespace, UTC iso for datetimes.
    # CRITICAL: timezone-aware datetimes MUST be normalized to UTC before
    # isoformat — otherwise a row hashed with `+00:00` at INSERT time and
    # read back with the session's local offset (`-05:00`) yields two
    # different serializations for the same instant, breaking the chain.
    import datetime as _dt

    def default(o: Any) -> Any:
        if isinstance(o, _dt.datetime) and o.tzinfo is not None:
            return o.astimezone(_dt.timezone.utc).isoformat()
        if hasattr(o, "isoformat"):
            return o.isoformat()
        if isinstance(o, (bytes, bytearray)):
            return o.hex()
        return str(o)
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=default).encode()


def row_hash(canonical: bytes, prev_hash: bytes | None) -> bytes:
    prev = (prev_hash or b"\x00").hex().encode()
    return hmac.new(_hmac_key(), canonical + prev, "sha256").digest()


def prev_row_hash(db: OrmSession, table: str) -> bytes | None:
    if table not in TAMPER_EVIDENT_TABLES:
        raise ValueError(f"{table} is not a tamper-evident table")
    # Order by the serial PK `id` — NOT ctid. ctid is the physical heap
    # location; after any UPDATE (e.g. the integrity:rebaseline repair
    # action) it no longer reflects insertion order, so ctid DESC would
    # pick an arbitrary row's hash as the chain tail and break every
    # subsequent audit event's row_hash. Every tamper-evident table has
    # a BIGSERIAL `id` column.
    row = db.execute(
        text(f"SELECT row_hash FROM {table} "
             f"WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
    ).scalar_one_or_none()
    # psycopg2 returns BYTEA as memoryview; cast so downstream callers
    # (row_hash, equality checks) see bytes. On Python 3.13 the two types
    # don't compare equal even when byte-identical.
    return bytes(row) if row is not None else None


def verify_chain(db: OrmSession, table: str) -> list[int]:
    if table not in TAMPER_EVIDENT_TABLES:
        raise ValueError(f"{table} is not a tamper-evident table")
    mismatches: list[int] = []
    # App-defined canonical field lists live in jobs/integrity.py; we only walk PKs here
    # to prove the chain has been initialized. Full verification is a job.
    rows = db.execute(text(f"SELECT row_hash IS NULL FROM {table}")).fetchall()
    for idx, (is_null,) in enumerate(rows):
        if is_null:
            mismatches.append(idx)
    return mismatches

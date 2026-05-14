#!/usr/bin/env python3
"""One-shot backfill: populate NULL `row_hash` on tamper-evident tables.

Runs through each table in insertion order, computes the HMAC-chained
hash the app would have written at insert time, and UPDATEs rows whose
row_hash is NULL. Rows that already have a row_hash are left alone.

Run with:
  cd /opt/meridian
  sudo -u meridian env MERIDIAN_CONFIG=/etc/meridian/meridian.conf \\
      /opt/meridian/venv/bin/python scripts/backfill-row-hashes.py

After running, the integrity scan should report zero mismatches for
rows that existed before this backfill (rows added after the backfill
will have hashes set at insert time by the app code).
"""
from __future__ import annotations

import sys
sys.path.insert(0, "/opt/meridian")

from sqlalchemy import text

from app.db import session_scope
from app.integrity.hmac_chain import (
    TAMPER_EVIDENT_TABLES, canonicalize, row_hash,
)
from app.jobs.integrity import _CANONICAL_COLUMNS


def main() -> int:
    total_updated = 0
    with session_scope() as db:
        for table in TAMPER_EVIDENT_TABLES:
            cols = _CANONICAL_COLUMNS.get(table)
            if cols is None:
                print(f"skip {table}: no canonical-column recipe")
                continue

            order_col = "id" if "id" in cols else "ts"
            col_list = ", ".join(cols) + ", row_hash"
            rows = db.execute(
                text(f"SELECT {col_list} FROM {table} ORDER BY {order_col}")
            ).fetchall()

            prev_hash = None
            updates = 0
            # We have to walk every row even if most have a hash already,
            # because the chain depends on prev_hash — if an early row is
            # missing, later rows were computed against a gap.
            pk_value_col = "id" if "id" in cols else None
            for r in rows:
                values = dict(zip(cols, r[:-1]))
                stored_hash = r[-1]
                # Exclude `id` from canonical input — the original hash
                # was computed at INSERT time before the DB assigned a PK.
                canonical_values = {k: v for k, v in values.items() if k != "id"}
                expected = row_hash(canonicalize(canonical_values), prev_hash)
                if stored_hash is None and pk_value_col:
                    db.execute(
                        text(f"UPDATE {table} SET row_hash = :h WHERE {pk_value_col} = :pk"),
                        {"h": expected, "pk": values[pk_value_col]},
                    )
                    updates += 1
                    prev_hash = expected
                else:
                    prev_hash = stored_hash or expected
            db.commit()
            print(f"  {table}: {updates} row(s) backfilled "
                  f"(of {len(rows)} total)")
            total_updated += updates

    print(f"\nDone. {total_updated} row(s) updated across all tables.")
    return 0 if total_updated >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

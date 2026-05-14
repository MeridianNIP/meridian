"""Active Directory housekeeping tasks.

stale_accounts — weekly report of user accounts where lastLogonTimestamp is
older than 90 days. Writes a findings row per enabled AD integration; the
admin sees them in the directory UI and can decide what to do.

The LDAP search uses a FILETIME cutoff so the heavy lifting happens on the
DC, not in our process — iterating every user in a big forest is a
non-starter.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.db import session_scope
from app.directory.ldap_client import _USER_ATTRS, client_for
from app.models.directory import DirectoryIntegration

# FILETIME = 100-nanosecond intervals since 1601-01-01 UTC.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _to_filetime(dt: datetime) -> int:
    delta = dt.astimezone(UTC) - _FILETIME_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def _filetime_to_dt(ft: int | None) -> datetime | None:
    if not ft or ft <= 0 or ft > 2**62:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=ft // 10)


def _table_exists(db, name: str) -> bool:
    return (
        db.execute(
            text("SELECT 1 FROM information_schema.tables " "WHERE table_schema='public' AND table_name=:n"),
            {"n": name},
        ).first()
        is not None
    )


@celery_app.task(name="meridian.jobs.ad.stale_accounts")
def stale_accounts(days: int = 90, limit_per_integration: int = 1000) -> dict[str, Any]:
    cutoff = datetime.now(UTC) - timedelta(days=days)
    cutoff_ft = _to_filetime(cutoff)

    results: list[dict[str, Any]] = []
    with session_scope() as db:
        integrations = (
            db.execute(
                select(DirectoryIntegration).where(
                    DirectoryIntegration.enabled.is_(True), DirectoryIntegration.kind == "active_directory"
                )
            )
            .scalars()
            .all()
        )

        has_table = _table_exists(db, "ad_stale_reports")

        for integ in integrations:
            try:
                client = client_for(db, integ)
            except Exception as e:
                results.append({"integration": integ.name, "error": str(e)[:200], "stale_found": 0})
                continue

            filt = (
                "(&(objectClass=user)(!(objectClass=computer))"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # not disabled
                f"(lastLogonTimestamp<={cutoff_ft}))"
            )
            stale: list[dict[str, Any]] = []
            try:
                with client._connect() as conn:
                    conn.search(
                        search_base=integ.base_dn,
                        search_filter=filt,
                        attributes=_USER_ATTRS,
                        size_limit=limit_per_integration,
                    )
                    for e in conn.entries:
                        last_logon_raw = e["lastLogonTimestamp"].value if "lastLogonTimestamp" in e else None
                        ll_dt: datetime | None
                        if isinstance(last_logon_raw, int):
                            ll_dt = _filetime_to_dt(last_logon_raw)
                        elif isinstance(last_logon_raw, datetime):
                            ll_dt = last_logon_raw
                        else:
                            ll_dt = None
                        stale.append(
                            {
                                "sam": getattr(e, "sAMAccountName", {}).value
                                if hasattr(e, "sAMAccountName")
                                else None,
                                "upn": getattr(e, "userPrincipalName", {}).value
                                if hasattr(e, "userPrincipalName")
                                else None,
                                "dn": str(e.entry_dn),
                                "last_logon": ll_dt.isoformat() if ll_dt else None,
                            }
                        )
            except Exception as e:
                results.append({"integration": integ.name, "error": str(e)[:200], "stale_found": 0})
                continue

            if has_table:
                db.execute(
                    text("""
                    INSERT INTO ad_stale_reports
                        (ts, integration_id, days_threshold, stale_count, sample_accounts)
                    VALUES (:t, :i, :d, :n, CAST(:s AS jsonb))
                """),
                    {
                        "t": datetime.now(UTC),
                        "i": integ.id,
                        "d": days,
                        "n": len(stale),
                        "s": __import__("json").dumps(stale[:50]),
                    },
                )

            results.append({"integration": integ.name, "stale_found": len(stale), "sample": stale[:5]})

        audit(
            db,
            action="ad.stale_accounts",
            payload={"days_threshold": days, "integrations_scanned": len(integrations), "results": results},
        )

    return {"days_threshold": days, "results": results}

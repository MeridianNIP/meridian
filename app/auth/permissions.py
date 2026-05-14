from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.models.user import User


class PermissionDenied(Exception):
    pass


def effective_permissions(db: OrmSession, user: User) -> set[str]:
    rows = db.execute(
        text("SELECT permission FROM v_user_effective_permissions WHERE user_id = :uid"),
        {"uid": user.id},
    ).fetchall()
    return {r[0] for r in rows}


def require(db: OrmSession, user: User, *permissions: str) -> None:
    have = effective_permissions(db, user)
    missing = [p for p in permissions if p not in have]
    if missing:
        raise PermissionDenied(f"missing: {', '.join(missing)}")


def has_any(db: OrmSession, user: User, permissions: Iterable[str]) -> bool:
    have = effective_permissions(db, user)
    return any(p in have for p in permissions)


def permission_requires_two_person(db: OrmSession, permission: str) -> bool:
    row = db.execute(
        text("SELECT requires_two_person FROM permissions WHERE key = :k"),
        {"k": permission},
    ).scalar_one_or_none()
    return bool(row)

"""Translate an AD user's `memberOf` list into a Meridian role via the
per-integration `group_role_map` JSONB column.

Stored shape:
    integration.config = {
        "group_role_map": {
            "CN=MeridianAdmin,OU=Groups,DC=corp,DC=example,DC=com": "admin",
            "CN=MeridianAnalyst,OU=Groups,DC=corp,DC=example,DC=com": "analyst",
            "CN=MeridianAudit,OU=Groups,DC=corp,DC=example,DC=com": "auditor",
            "CN=MeridianViewer,OU=Groups,DC=corp,DC=example,DC=com": "viewer",
        },
        "auto_create": true   # mint a Meridian user on first AD login
    }

Matching is case-insensitive (AD is) and picks the highest-privilege
role when a user is in multiple mapped groups. "Highest" ranks as
super_admin > admin > auditor > analyst > viewer > api_service.
"""
from __future__ import annotations

from typing import Iterable


_ROLE_RANK = {
    "super_admin": 60, "admin": 50, "auditor": 40,
    "analyst": 30, "viewer": 20, "api_service": 10,
}
_VALID_ROLES = set(_ROLE_RANK)


def resolve_role(group_role_map: dict, member_of: Iterable[str]) -> str | None:
    """Pick the strongest role the user qualifies for via AD groups.
    Returns None if no mapping matches (caller decides: keep existing
    role, deny access, or default to viewer).
    """
    if not group_role_map or not member_of:
        return None

    map_lower = {k.lower().strip(): v for k, v in (group_role_map or {}).items()}

    best: str | None = None
    best_rank = -1
    for dn in member_of:
        key = (dn or "").lower().strip()
        role = map_lower.get(key)
        if role is None:
            continue
        if role not in _VALID_ROLES:
            continue
        rank = _ROLE_RANK.get(role, -1)
        if rank > best_rank:
            best = role
            best_rank = rank
    return best

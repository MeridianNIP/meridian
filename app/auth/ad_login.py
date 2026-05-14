"""AD-side authentication helper invoked by /api/v1/auth/login when
local credentials don't match.

For each enabled DirectoryIntegration:
  1. Service-bind with the stored bind account + password.
  2. Search for the submitted username against sAMAccountName / UPN /
     mail — if the user doesn't exist in this directory, continue to
     the next integration.
  3. Re-bind as the user with the submitted password to verify it.
  4. If the bind succeeds, resolve the Meridian role from memberOf via
     the integration's `config.group_role_map`. Fall back to the
     integration's `config.default_role` (or existing local role, or
     `viewer`) if no group matches.
  5. Locate the matching Meridian user — by username, email, or UPN. If
     none, and the integration's `config.auto_create` is true, mint a
     new row. Otherwise deny access.
  6. Sync the role if it changed, bump last_login_at, and return the
     User row to the caller.

Returns None if no enabled integration accepts the credential.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.directory.ldap_client import client_for
from app.directory.role_map import resolve_role
from app.models.directory import DirectoryIntegration
from app.models.user import User


_VALID_ROLES = {
    "super_admin", "admin", "auditor", "analyst", "viewer", "api_service",
}


def try_ad_authenticate(
    db: OrmSession, username: str, password: str, *,
    ip: str | None, user_agent: str | None,
) -> User | None:
    if not username or not password:
        return None

    integs = db.execute(
        select(DirectoryIntegration).where(DirectoryIntegration.enabled.is_(True))
    ).scalars().all()

    for integ in integs:
        try:
            client = client_for(db, integ)
        except Exception:  # noqa: BLE001
            continue
        try:
            result: dict[str, Any] | None = client.authenticate_user(username, password)
        except Exception:  # noqa: BLE001
            result = None
        if not result:
            continue

        config = integ.config or {}
        # Role assignment: group map first, then default_role, then
        # keep whatever the pre-existing local row has, else viewer.
        mapped_role = resolve_role(
            config.get("group_role_map") or {},
            result.get("memberOf") or [],
        )

        # Locate (or mint) the Meridian user by sAMAccountName / UPN / mail.
        sam  = (result.get("sAMAccountName") or "").lower().strip()
        upn  = (result.get("userPrincipalName") or "").lower().strip()
        mail = (result.get("mail") or "").lower().strip()
        email = mail or upn
        candidate_usernames = {u for u in (sam, upn, username.lower().strip()) if u}

        user = db.execute(
            select(User).where(or_(
                User.username.in_(candidate_usernames),
                User.email == email,
            ))
        ).scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if user is None:
            # No local row yet. Access gate: the user MUST be in at
            # least one mapped AD group (or the integration has a
            # default_role set) — otherwise AD-authenticated but
            # unmapped users would silently get viewer access.
            if not mapped_role and not config.get("default_role"):
                audit(db, action="auth.ad.denied_no_group_match",
                      payload={"username": username,
                               "integration": integ.name,
                               "reason": "no mapped AD group matches user's memberOf"},
                      ip=ip, user_agent=user_agent, outcome="denied")
                continue
            effective_role = mapped_role or config.get("default_role") or "viewer"
            if effective_role not in _VALID_ROLES:
                effective_role = "viewer"
            # Mint an internal shadow record — no local password,
            # primary_auth=ldap — so we can anchor sessions, audit
            # trail, preferences, last-login. The role is re-read from
            # AD on every subsequent login, so this row is just a cache.
            user = User(
                id=uuid.uuid4(),
                username=sam or username.lower().strip(),
                email=email or f"{sam}@{integ.fqdn or 'ad.local'}",
                display_name=result.get("displayName") or result.get("cn"),
                password_hash=None,
                primary_auth="ldap",
                role=effective_role,
                enabled=True,
                locked=False,
                external_id=result.get("objectSid") or result.get("dn"),
                last_login_at=now,
            )
            db.add(user)
            db.flush()
            audit(db, user_id=user.id, action="auth.ad.user_provisioned",
                  target_type="user", target_key=user.username,
                  payload={"integration": integ.name,
                           "role": effective_role,
                           "mapped_from_group": bool(mapped_role),
                           "dn": result.get("dn")},
                  ip=ip, user_agent=user_agent)
        else:
            if not user.enabled or user.locked or user.deleted_at is not None:
                audit(db, user_id=user.id, action="auth.login.failed",
                      payload={"reason": "account_disabled",
                               "integration": integ.name},
                      ip=ip, user_agent=user_agent, outcome="denied")
                continue
            # Sync role on every login so AD group membership changes
            # take effect immediately. Preserve existing if AD map has
            # nothing to say AND no default_role configured.
            new_role = mapped_role or config.get("default_role") or user.role
            if new_role in _VALID_ROLES and new_role != user.role:
                audit(db, user_id=user.id, action="auth.ad.role_synced",
                      target_type="user", target_key=user.username,
                      payload={"from": user.role, "to": new_role,
                               "integration": integ.name},
                      ip=ip, user_agent=user_agent)
                user.role = new_role
            user.last_login_at = now
            user.failed_login_count = 0

        audit(db, user_id=user.id, action="auth.login.ok",
              payload={"method": "ldap", "integration": integ.name,
                       "groups_matched": bool(mapped_role)},
              ip=ip, user_agent=user_agent)
        return user

    return None

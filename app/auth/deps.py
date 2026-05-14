from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session as OrmSession

from app.auth.permissions import PermissionDenied, require
from app.auth.session_manager import (
    enforce_idle_timeout, resolve_api_token, resolve_session,
    touch_api_token, touch_session,
)
from app.db import session_scope
from app.models.user import User


SESSION_COOKIE = "meridian_session"


async def current_user(
    request: Request,
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    # Two auth paths:
    # 1. Browser session cookie (UI flow) — resolves against `sessions`
    # 2. Bearer API token (integrations / scripts) — "mrd_..." prefix,
    #    resolves against `api_tokens`; scopes are later intersected in
    #    require_permission()
    # The cookie is preferred if present so browser tabs keep working even
    # when some script also sends a stale bearer header.
    bearer_token: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        bearer_token = authorization.split(None, 1)[1]

    if session_cookie:
        token, is_api = session_cookie, False
    elif bearer_token and bearer_token.startswith("mrd_"):
        token, is_api = bearer_token, True
    elif bearer_token:
        # Pre-existing behaviour: bare bearer tokens are treated as session
        # IDs (some tests / oauth flows use this). Keep it working.
        token, is_api = bearer_token, False
    else:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")

    with session_scope() as db:
        if is_api:
            tok = resolve_api_token(db, token)
            if tok is None:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                    "API token invalid, expired, or revoked")
            user = db.get(User, tok.user_id)
            if user is None or not user.enabled or user.locked:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account disabled")
            touch_api_token(db, tok.id)
            request.state.api_token_id = tok.id
            request.state.api_token_scopes = list(tok.scopes or [])
            db.expunge(user)
        else:
            sess = resolve_session(db, token)
            if sess is None:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                    "session invalid or expired")
            user = db.get(User, sess.user_id)
            if user is None or not user.enabled or user.locked:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account disabled")
            from app.config import get_settings
            idle_min = user.idle_timeout_override_min or get_settings().idle_timeout_default_min
            if enforce_idle_timeout(sess, idle_min):
                from app.auth.session_manager import revoke_session
                revoke_session(db, sess.id, reason="idle_timeout", by=None)
                raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                    f"signed out after {idle_min}m idle")
            touch_session(db, sess.id)
            request.state.session_id = sess.id
            db.expunge(user)
    request.state.user = user
    return user


def require_permission(*perms: str):
    async def _dep(
        request: Request,
        user: User = Depends(current_user),
    ) -> User:
        with session_scope() as db:
            try:
                require(db, user, *perms)
            except PermissionDenied as e:
                raise HTTPException(status.HTTP_403_FORBIDDEN, str(e)) from e
        # If this request is API-token authenticated, also check that every
        # required permission is within the token's stored scopes. Tokens
        # are minted as a subset of their owner's permissions — a leaked
        # token must not expand beyond what it was granted at mint time.
        scopes = getattr(request.state, "api_token_scopes", None)
        if scopes is not None:
            missing = [p for p in perms if p not in scopes]
            if missing:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "API token is missing required scope(s): "
                    + ", ".join(missing),
                )
        return user
    return _dep


def client_ip(request: Request) -> str | None:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",", 1)[0].strip()
    return request.client.host if request.client else None


def require_approval(action: str):
    """Return a FastAPI dependency that blocks a handler unless the current user
    has an approved, unexpired approval row for (`action`, `target_key`).

    Pass the target_key via the request header `X-Meridian-Target`, or via the
    first path parameter inferred by FastAPI for routes like `/users/{target}`.
    The approval must have been filed by the same user who is now executing it
    (so the approver explicitly blessed THIS user's action, not just anyone's).
    """
    async def _dep(
        request: Request,
        user: User = Depends(current_user),
    ) -> "Approval":
        from app.approvals.engine import get_approved_for
        from app.models.audit import Approval

        target_key = request.headers.get("x-meridian-target")
        if target_key is None:
            # Fall back to path params — the last one is typically the target.
            path_params = list(request.path_params.values())
            target_key = path_params[-1] if path_params else None
        if not target_key:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "target required (path param or X-Meridian-Target header)",
            )

        with session_scope() as db:
            appr: Approval | None = get_approved_for(
                db, action=action, target_key=str(target_key), requester=user,
            )
            if appr is None:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    f"no approved approval for action={action!r} target={target_key!r}. "
                    f"POST /api/v1/approvals/request first.",
                )
            approval_id = appr.id
            db.expunge(appr)
        request.state.approval_id = approval_id
        return appr
    return _dep

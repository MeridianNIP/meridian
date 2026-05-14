"""CSRF protection — double-submit cookie pattern.

Why double-submit and not a synchronizer token: our session cookie is
HttpOnly (attacker JS can't read it), but the CSRF cookie is deliberately
readable by our own page JS. A legitimate fetch sends the cookie value in
both the Cookie header (by virtue of being cookied) and an explicit
X-CSRF-Token header; an attacker site can cause the browser to send the
Cookie header but cannot read the cookie value to populate the custom
header → cross-origin POSTs fail.

Applies only when a session cookie is present. API-token auth bypasses
the check (the bearer already proves intent).
"""

from __future__ import annotations

import hmac
import secrets as _secrets

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

CSRF_COOKIE = "meridian_csrf"
CSRF_HEADER = "X-CSRF-Token"
SESSION_COOKIE = "meridian_session"  # set by app.auth.session_manager

# Endpoints that should never require a CSRF header — strictly the ones that
# have no session cookie flow (public inbound webhooks authenticate via HMAC)
# or are the actual login POST (which creates the session in the first place).
_EXEMPT_PATH_PREFIXES: tuple[str, ...] = (
    "/api/v1/webhooks/inbound/",  # HMAC-signed, own authz
    "/ui/login",  # creating the session; no prior cookie
    "/api/v1/auth/login",  # same
    "/api/v1/auth/recovery/challenge",  # unauth — forgot-password flow
    "/api/v1/auth/recovery/verify",  # unauth — same
    "/api/v1/auth/recovery/reset",  # unauth — same
    "/api/v1/auth/lockout-appeal",  # unauth — locked-user appeal form
    "/healthz",
)

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _issue_token() -> str:
    return _secrets.token_urlsafe(32)


def _is_exempt_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in _EXEMPT_PATH_PREFIXES)


def _bearer_authed(request: Request) -> bool:
    """API-token requests skip CSRF — the bearer proves intent."""
    auth = request.headers.get("Authorization") or ""
    return auth.lower().startswith("bearer ")


class CsrfMiddleware(BaseHTTPMiddleware):
    """Issue a CSRF cookie on first GET; enforce header match on unsafe methods
    when a session cookie is present."""

    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()
        path = request.url.path

        # Enforcement — only for unsafe methods, only when we have a session
        # cookie (= cookie-authed flow), and only for non-exempt paths.
        if (
            method in _UNSAFE_METHODS
            and request.cookies.get(SESSION_COOKIE)
            and not _bearer_authed(request)
            and not _is_exempt_path(path)
        ):
            cookie_val = request.cookies.get(CSRF_COOKIE) or ""
            presented = request.headers.get(CSRF_HEADER) or ""
            # Fallback: accept a `_csrf` form field for vanilla <form method=post>
            # submits. Only read the body when the content-type is form-encoded so
            # we don't consume a JSON request stream.
            if not presented:
                ctype = (request.headers.get("content-type") or "").lower()
                if ctype.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
                    try:
                        form = await request.form()
                        presented = form.get("_csrf") or ""
                    except Exception:
                        presented = ""
            if not cookie_val or not presented or not hmac.compare_digest(cookie_val, presented):
                return Response(
                    content='{"error":"CSRF token missing or mismatched"}',
                    status_code=403,
                    media_type="application/json",
                )

        response = await call_next(request)

        # Issue a CSRF cookie if one isn't set. Readable by JS on purpose —
        # the whole point is that our own page JS can echo it into a header.
        if not request.cookies.get(CSRF_COOKIE):
            response.set_cookie(
                CSRF_COOKIE,
                _issue_token(),
                max_age=60 * 60 * 24 * 30,  # 30 days
                secure=True,
                httponly=False,
                samesite="lax",
                path="/",
            )
        return response

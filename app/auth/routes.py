from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import SESSION_COOKIE, client_ip, current_user
from app.config import get_settings
from app.auth.mfa import decrypt_totp_secret, verify_totp
from app.auth.password import needs_rehash, verify_password, hash_password
from app.auth.session_manager import mint_session, revoke_session
from app.db import fastapi_dep_db
from app.models.user import User


router = APIRouter(prefix="/auth", tags=["auth"])


class LoginResponse(BaseModel):
    user_id: uuid.UUID
    username: str
    role: str
    mfa_required: bool
    force_change_password: bool


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    response: Response,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    mfa_code: Annotated[str | None, Form()] = None,
    db: OrmSession = Depends(fastapi_dep_db),
) -> LoginResponse:
    ip = client_ip(request)
    ua = request.headers.get("user-agent")

    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()

    # Local credentials first — fast-path for admin/service accounts that
    # never hit AD. Only fall through to AD auth when the local credential
    # check fails (or when the user has no local password hash at all).
    local_ok = False
    if user is not None and user.enabled and not user.locked and user.deleted_at is None \
            and user.password_hash is not None \
            and verify_password(password, user.password_hash):
        local_ok = True

    if not local_ok:
        # Try each enabled directory integration. If any validates the
        # credential, either load the existing local user (matched by
        # username/email/UPN) or create a new one if the integration
        # allows auto_create. Group → role mapping applies on every
        # successful login so AD membership changes take effect
        # immediately without an admin touching Meridian.
        from app.auth.ad_login import try_ad_authenticate
        ad_result = try_ad_authenticate(db, username, password,
                                        ip=ip, user_agent=ua)
        if ad_result is not None:
            user = ad_result   # fall through to session mint below
        else:
            # Neither local nor AD accepted. Bump fail counter if we had
            # a matching local user, then reject.
            if user is not None:
                user.failed_login_count = (user.failed_login_count or 0) + 1
                audit(db, user_id=user.id, action="auth.login.failed",
                      payload={"reason": "bad_password", "src": ip or "-"},
                      ip=ip, user_agent=ua, outcome="denied")
            else:
                audit(db, action="auth.login.failed",
                      payload={"username": username,
                               "reason": "no_such_user_or_disabled",
                               "src": ip or "-"},
                      ip=ip, user_agent=ua, outcome="denied")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    if user.mfa_enrolled:
        if not mfa_code:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "mfa_required")
        if user.mfa_secret_enc is None or not verify_totp(
            decrypt_totp_secret(user.mfa_secret_enc), mfa_code
        ):
            audit(db, user_id=user.id, action="auth.login.failed",
                  payload={"reason": "bad_mfa", "src": ip or "-"},
                  ip=ip, user_agent=ua, outcome="denied")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid mfa code")

    # Opportunistic password-hash upgrade (argon2 parameter drift).
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    _, token = mint_session(
        db, user,
        auth_method="credential",
        ip=ip, user_agent=ua,
        idle_timeout_min=user.idle_timeout_override_min or 30,
    )

    response.set_cookie(
        SESSION_COOKIE, token,
        httponly=True, secure=True, samesite="lax",
        max_age=60 * 60 * 24,
        path="/",
    )
    return LoginResponse(
        user_id=user.id, username=user.username, role=user.role,
        mfa_required=user.mfa_enrolled,
        force_change_password=bool((user.preferences or {}).get("force_change_password")),
    )


@router.post("/logout", status_code=204, response_model=None)
async def logout(
    request: Request,
    response: Response,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> Response:
    sid = getattr(request.state, "session_id", None)
    if sid:
        revoke_session(db, sid, reason="user_logout", by=user.id)
    audit(db, user_id=user.id, action="auth.logout",
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.status_code = 204
    return response


class MeResponse(BaseModel):
    user_id: uuid.UUID
    username: str
    email: str
    role: str
    mfa_enrolled: bool
    timezone: str


@router.get("/me", response_model=MeResponse)
async def me(user: User = Depends(current_user)) -> MeResponse:
    return MeResponse(
        user_id=user.id, username=user.username, email=user.email,
        role=user.role, mfa_enrolled=user.mfa_enrolled, timezone=user.timezone,
    )


# ============================================================================
# MFA enrollment (TOTP, RFC 6238).
# A pending secret is stashed in the user record with mfa_enrolled=False; the
# confirmation step flips the flag only after the user proves they can
# generate a correct code (so a half-enrolled state can't lock them out).
# ============================================================================
class MfaBeginResponse(BaseModel):
    secret: str
    provisioning_uri: str   # otpauth:// — any authenticator app can parse this
    qr_svg: str             # inline SVG containing the otpauth URI as text


class MfaConfirmBody(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


class MfaDisableBody(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


@router.post("/mfa/begin", response_model=MfaBeginResponse)
async def mfa_begin(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> MfaBeginResponse:
    from app.auth.mfa import encrypt_totp_secret, generate_totp_secret, provisioning_uri
    if user.mfa_enrolled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "already enrolled — disable first to re-enroll")
    secret = generate_totp_secret()
    # Stash encrypted; mfa_enrolled stays False until confirm() succeeds.
    u = db.get(User, user.id)
    u.mfa_secret_enc = encrypt_totp_secret(secret)
    db.flush()
    uri = provisioning_uri(user.username, secret,
                           issuer=get_settings().portal_name or "Meridian")
    # Minimal "QR code": we embed the URI as text in an SVG so the client
    # doesn't need a QR library. Any authenticator app accepts either the
    # URI string or a scanned QR — serving both keeps the page keyless.
    qr_svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="240" height="80" '
        'viewBox="0 0 240 80">'
        '<rect width="240" height="80" fill="#0e1116"/>'
        f'<text x="8" y="40" fill="#20c896" font-family="monospace" font-size="9">'
        f'Scan with any authenticator:</text>'
        f'<text x="8" y="58" fill="#e6edf3" font-family="monospace" font-size="7">'
        f'{uri[:120]}…</text></svg>'
    )
    return MfaBeginResponse(secret=secret, provisioning_uri=uri, qr_svg=qr_svg)


@router.post("/mfa/confirm")
async def mfa_confirm(
    body: MfaConfirmBody,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    from app.auth.mfa import decrypt_totp_secret, generate_backup_codes, verify_totp
    u = db.get(User, user.id)
    if not u.mfa_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "call /mfa/begin first")
    secret = decrypt_totp_secret(u.mfa_secret_enc)
    if not verify_totp(secret, body.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "code did not match")
    u.mfa_enrolled = True
    backup = generate_backup_codes()
    # Backup codes: we return them ONCE; the user must save them. Persisting
    # them in the DB is on the roadmap (schema has no backup-code table yet).
    db.flush()
    return {"ok": True, "backup_codes": backup,
            "note": "Save these backup codes now — they won't be shown again."}


@router.post("/mfa/disable", status_code=204, response_model=None)
async def mfa_disable(
    body: MfaDisableBody,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    from app.auth.mfa import decrypt_totp_secret, verify_totp
    u = db.get(User, user.id)
    if not u.mfa_enrolled or not u.mfa_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is not enrolled")
    if not verify_totp(decrypt_totp_secret(u.mfa_secret_enc), body.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "code did not match")
    u.mfa_enrolled = False
    u.mfa_secret_enc = None


# ============================================================================
# Account recovery (5 security questions, 3 random must match).
# ============================================================================
from app.auth import recovery as _rec  # noqa: E402


@router.get("/recovery/questions/library")
async def recovery_library(_: User = Depends(current_user)) -> dict:
    """Catalog of suggested questions. Users can also write custom ones."""
    return {"questions": list(_rec.QUESTION_LIBRARY)}


@router.get("/recovery/status")
async def recovery_status(
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    return {
        "enrolled": _rec.is_enrolled(db, user.id),
        "questions": [q["question"] for q in _rec.list_questions(db, user.id)],
    }


class RecoverySetupItem(BaseModel):
    question: str = Field(..., min_length=1, max_length=200)
    answer:   str = Field(..., min_length=2, max_length=200)


class RecoverySetupBody(BaseModel):
    items: list[RecoverySetupItem] = Field(..., min_length=5, max_length=5)


@router.post("/recovery/setup")
async def recovery_setup(
    request: Request,
    body: RecoverySetupBody,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        _rec.save_questions(db, user.id, [(i.question, i.answer) for i in body.items])
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    audit(db, user_id=user.id, action="recovery.questions.setup",
          target_type="user", target_key=str(user.id),
          payload={"count": 5},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))
    return {"ok": True}


# --- Unauthenticated: forgot-password flow ---------------------------------
# To frustrate account enumeration, every endpoint returns the same shape
# whether or not the username exists. The challenge always renders 3 generic
# question texts even for unknown users (we mint throwaways), and the verify
# step always pauses ~same-length before responding.
import secrets as _sec          # noqa: E402
import time as _time            # noqa: E402
from app.models.user import User as _UserModel  # noqa: E402


class ChallengeRequestBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)


@router.post("/recovery/challenge")
async def recovery_challenge(
    body: ChallengeRequestBody,
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    # Lookup by username.
    user = db.execute(
        __import__("sqlalchemy").select(_UserModel).where(
            _UserModel.username == body.username
        )
    ).scalar_one_or_none()
    # Decoy challenge for unknown / not-enrolled users so an attacker can't
    # enumerate which accounts have recovery set up.
    if user is None or not _rec.is_enrolled(db, user.id):
        return {
            "challenge_id": _sec.token_urlsafe(16),
            "questions": [
                {"position": 1, "question": "Security question 1 (we will verify 3 of 5)"},
                {"position": 2, "question": "Security question 2"},
                {"position": 3, "question": "Security question 3"},
            ],
        }
    if _rec.recent_failures(db, user.id) >= 5:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many recovery attempts recently; try again in 15 minutes",
        )
    picks = _rec.pick_challenge(db, user.id)
    return {
        # The challenge_id is cosmetic — we re-pick positions on verify based
        # on whatever the client sends back; rate-limiting is by user_id.
        "challenge_id": _sec.token_urlsafe(16),
        "questions":    picks,
    }


class ChallengeAnswer(BaseModel):
    position: int = Field(..., ge=1, le=5)
    answer:   str = Field(..., min_length=1, max_length=200)


class ChallengeVerifyBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    answers:  list[ChallengeAnswer] = Field(..., min_length=3, max_length=5)


@router.post("/recovery/verify")
async def recovery_verify(
    request: Request,
    body: ChallengeVerifyBody,
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    _t0 = _time.monotonic()
    user = db.execute(
        __import__("sqlalchemy").select(_UserModel).where(
            _UserModel.username == body.username
        )
    ).scalar_one_or_none()
    failed = True
    token: str | None = None
    if user is not None and _rec.is_enrolled(db, user.id):
        if _rec.recent_failures(db, user.id) < 5:
            answers = {a.position: a.answer for a in body.answers}
            if _rec.verify_challenge(db, user.id, answers):
                failed = False
                token = _rec.mint_reset_token(
                    db, user.id,
                    ip=client_ip(request),
                    user_agent=request.headers.get("user-agent"),
                )
                _rec.record_attempt(db, user.id, outcome="ok",
                                    ip=client_ip(request))
                audit(db, user_id=user.id, action="recovery.challenge.ok",
                      target_type="user", target_key=str(user.id),
                      payload={"positions": sorted(answers.keys())},
                      ip=client_ip(request),
                      user_agent=request.headers.get("user-agent"))
    if failed:
        if user is not None:
            _rec.record_attempt(db, user.id, outcome="fail",
                                ip=client_ip(request))
            audit(db, user_id=user.id, action="recovery.challenge.fail",
                  target_type="user", target_key=str(user.id),
                  payload={"supplied_positions": [a.position for a in body.answers]},
                  ip=client_ip(request),
                  user_agent=request.headers.get("user-agent"),
                  outcome="warn")
        # Constant-time-ish: at least 250ms so timing doesn't leak whether
        # the user exists + answers matched.
        _remaining = 0.25 - (_time.monotonic() - _t0)
        if _remaining > 0:
            await __import__("asyncio").sleep(_remaining)
        return {"ok": False, "reset_token": None}
    return {"ok": True, "reset_token": token,
            "expires_in_minutes": _rec.RESET_TOKEN_TTL_MIN}


class ResetPasswordBody(BaseModel):
    reset_token:  str = Field(..., min_length=8, max_length=200)
    new_password: str = Field(..., min_length=12, max_length=200)


@router.post("/recovery/reset", status_code=204, response_model=None)
async def recovery_reset(
    request: Request,
    body: ResetPasswordBody,
    db: OrmSession = Depends(fastapi_dep_db),
) -> None:
    from app.auth.password import hash_password
    user_id = _rec.consume_reset_token(db, body.reset_token)
    if user_id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "reset token is invalid, used, or expired")
    u = db.get(_UserModel, user_id)
    if u is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "user no longer exists")
    u.password_hash = hash_password(body.new_password)
    u.locked = False
    u.failed_login_count = 0
    # Revoke any existing sessions so the attacker (if that's who's resetting)
    # doesn't piggyback on a live session.
    from sqlalchemy import text as _sql_text
    db.execute(
        _sql_text("""
            UPDATE sessions SET revoked_at = now(),
                                revoked_reason = 'password_reset'
             WHERE user_id = :u AND revoked_at IS NULL
        """),
        {"u": user_id},
    )
    audit(db, user_id=user_id, action="recovery.password.reset",
          target_type="user", target_key=str(user_id),
          payload={"sessions_revoked": True},
          ip=client_ip(request),
          user_agent=request.headers.get("user-agent"))

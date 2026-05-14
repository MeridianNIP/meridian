from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
import uuid as _uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import recent as recent_audit
from app.audit.logger import record as audit
from app.auth.deps import SESSION_COOKIE, client_ip, current_user, require_permission
from app.auth.mfa import decrypt_totp_secret, verify_totp
from app.auth.password import hash_password, needs_rehash, verify_password
from app.auth.session_manager import mint_session, revoke_session
from app.config import get_settings
from app.db import fastapi_dep_db
from app.models.session import Session as SessionModel
from app.models.user import User

router = APIRouter(prefix="/ui", tags=["ui"])
_templates: Jinja2Templates | None = None


def templates() -> Jinja2Templates:
    global _templates
    if _templates is None:
        _templates = Jinja2Templates(directory=str(get_settings().install_root / "app" / "templates"))
        # Teach `| tojson` and json.dumps about the types we pass through
        # contexts: UUID → str, datetime → isoformat. Without this every
        # `{{ row.id | tojson }}` on a UUID column 500s.
        import datetime
        import json
        import uuid

        class _Enc(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, uuid.UUID):
                    return str(o)
                if isinstance(o, (datetime.datetime, datetime.date)):
                    return o.isoformat()
                return super().default(o)

        _templates.env.policies["json.dumps_kwargs"] = {"cls": _Enc, "sort_keys": True}
    return _templates


def _base_ctx(
    request: Request,
    user: User | None = None,
    **extra: Any,
) -> dict[str, Any]:
    settings = get_settings()
    # Load the live branding row. Falls back to install-time defaults if the
    # DB is unavailable (e.g. during the /healthz probe before install.sh
    # finishes seeding). Templates access values via the `branding` context key.
    branding: dict[str, Any] = {
        "display_name": settings.portal_name,
        "logo_click_url": "https://meridiannip.com",
        "logo_click_target": "_blank",
        "pre_login_warning": None,
        "login_banner_text": "RESTRICTED ACCESS SYSTEM",
        "accent_hex": "#20c896",
        "aup_show_footer_link": True,
    }
    try:
        from app.db import (
            fastapi_dep_db,  # noqa: F401  (ensures engine init)
            session_scope,
        )
        from app.models.branding import load as load_branding

        with session_scope() as ro:
            b = load_branding(ro)
            branding.update(
                {
                    "display_name": b.display_name,
                    "short_name": b.short_name,
                    "support_email": b.support_email,
                    "support_url": b.support_url,
                    "privacy_url": b.privacy_url,
                    "imprint_url": b.imprint_url,
                    "logo_click_url": b.logo_click_url,
                    "logo_click_target": b.logo_click_target,
                    "pre_login_warning": b.pre_login_warning,
                    "aup_show_footer_link": b.aup_show_footer_link,
                    "theme": b.theme,
                    "accent_hex": b.accent_hex,
                    "vendor_attribution_hidden": b.vendor_attribution_hidden,
                }
            )
    except (KeyError, Exception):
        # During startup races / dry runs, fall back to the hardcoded defaults.
        pass
    # Effective idle timeout (in minutes) for the current user -- used by
    # the topbar countdown + auto-logout-on-expiry. 0 means "never expire".
    idle_min: int | None = None
    if user is not None:
        idle_min = getattr(user, "idle_timeout_override_min", None) or settings.idle_timeout_default_min

    # Effective display timezone. Precedence:
    #   user.timezone → branding.timezone → settings.timezone → 'UTC'
    # The browser-side `fmt.ts()` helper picks this up from `<body data-tz=...>`.
    tz = ""
    if user is not None:
        tz = (getattr(user, "timezone", None) or "").strip()
    if not tz:
        branding_tz = branding.get("timezone") if isinstance(branding, dict) else None
        tz = branding_tz or settings.timezone or "UTC"

    return {
        "request": request,
        "user": user,
        "branding": branding,
        "version": settings.manifest_version,
        "idle_timeout_min": idle_min,
        "effective_tz": tz,
        **extra,
    }


@router.get("/", response_class=HTMLResponse)
async def ui_root(request: Request):
    return RedirectResponse(url="/ui/dashboard", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str | None = None):
    session = request.cookies.get(SESSION_COOKIE)
    if session:
        return RedirectResponse(url=next or "/ui/dashboard", status_code=303)
    ctx = _base_ctx(request, error=None, username=None, next=next)
    return templates().TemplateResponse("login.html", ctx)


@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    ctx = _base_ctx(request, user=None)
    return templates().TemplateResponse("forgot_password.html", ctx)


@router.get("/locked-out", response_class=HTMLResponse)
async def locked_out_page(request: Request):
    # Public, no auth required — the whole point is the user can't log in.
    # POST handler is at /api/v1/auth/lockout-appeal with per-IP rate limit.
    ctx = _base_ctx(request, user=None)
    return templates().TemplateResponse("locked_out.html", ctx)


@router.get("/admin/appeals", response_class=HTMLResponse)
async def admin_appeals_page(
    request: Request,
    user: User = Depends(require_permission("admin.users.manage")),
):
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_appeals.html", ctx)


@router.get("/admin/queues", response_class=HTMLResponse)
async def admin_queues_page(
    request: Request,
    user: User = Depends(require_permission("admin.system.health.read")),
):
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_queues.html", ctx)


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    mfa_code: Annotated[str | None, Form()] = None,
    next: Annotated[str | None, Form()] = None,
    db: OrmSession = Depends(fastapi_dep_db),
):
    ip = client_ip(request)
    ua = request.headers.get("user-agent")
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()

    def _fail(reason: str, msg: str, ctx_user: User | None = None) -> Response:
        audit(
            db,
            user_id=ctx_user.id if ctx_user else None,
            action="auth.login.failed",
            payload={"username": username, "reason": reason, "src": ip or "-"},
            ip=ip,
            user_agent=ua,
            outcome="denied",
        )
        ctx = _base_ctx(request, error=msg, username=username, next=next)
        return templates().TemplateResponse("login.html", ctx, status_code=401)

    if user is None or not user.enabled or user.locked or user.deleted_at is not None:
        return _fail("no_such_user_or_disabled", "Invalid credentials.")
    if user.password_hash is None or not verify_password(password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        return _fail("bad_password", "Invalid credentials.", user)
    if user.mfa_enrolled:
        if (
            not mfa_code
            or user.mfa_secret_enc is None
            or not verify_totp(decrypt_totp_secret(user.mfa_secret_enc), mfa_code)
        ):
            return _fail("bad_mfa", "Invalid MFA code.", user)

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    idle_min = user.idle_timeout_override_min or get_settings().idle_timeout_default_min
    _, token = mint_session(
        db,
        user,
        auth_method="credential",
        ip=ip,
        user_agent=ua,
        idle_timeout_min=idle_min,
    )

    # If the account was created with force_change_password (new local
    # user OR admin reset), bounce them to Settings with a flag so the
    # page scrolls to the password card. They can't skip this — every
    # protected page checks the flag and redirects back if still set.
    force_change = bool((user.preferences or {}).get("force_change_password"))
    target = "/ui/settings?force_change_password=1" if force_change else (next or "/ui/dashboard")
    response = RedirectResponse(url=target, status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 60 * 24,
        path="/",
    )
    return response


@router.post("/logout")
async def logout(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    sid = getattr(request.state, "session_id", None)
    if sid:
        revoke_session(db, sid, reason="user_logout", by=user.id)
    audit(
        db,
        user_id=user.id,
        action="auth.logout",
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    r = RedirectResponse(url="/ui/login", status_code=303)
    r.delete_cookie(SESSION_COOKIE, path="/")
    return r


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    # Minimal stats for the first cut; full metrics come in the monitors module.
    active_sessions = db.execute(
        select(func.count())
        .select_from(SessionModel)
        .where(SessionModel.user_id == user.id, SessionModel.revoked_at.is_(None))
    ).scalar_one()
    stats = {
        "queries_today": 0,  # populated in the next pass from query_history
        "query_delta": "—",
        "sessions": active_sessions,
        "alerts": 0,  # populated from monitor_incidents later
    }

    # Dashboard recent-activity feed. Raw audit rows store UUIDs for actor
    # (user_id) and for user-type targets (target_key), which renders as
    # "auth.login · 81b79f88-..." -- useless to admins. Enrich each row with
    # the actor's username and, when target_type='user', the target's
    # username, so the dashboard shows "alice · auth.login" / "admin ·
    # user.delete · bob".
    audit_rows = recent_audit(db, limit=8)
    uids: set[_uuid.UUID] = set()
    for ev in audit_rows:
        if ev.user_id:
            uids.add(ev.user_id)
        if ev.target_type == "user" and ev.target_key:
            try:
                uids.add(_uuid.UUID(ev.target_key))
            except ValueError:
                pass
    user_map: dict[_uuid.UUID, User] = {}
    if uids:
        for u in db.execute(select(User).where(User.id.in_(uids))).scalars():
            user_map[u.id] = u

    recent_activity = []
    for ev in audit_rows:
        actor = user_map.get(ev.user_id) if ev.user_id else None
        target_display: str | None = None
        if ev.target_type == "user" and ev.target_key:
            try:
                tu = user_map.get(_uuid.UUID(ev.target_key))
                target_display = tu.username if tu else ev.target_key[:8]
            except ValueError:
                target_display = ev.target_key
        elif ev.target_key:
            # Non-user target. Hide UUID-shaped keys (session IDs, job IDs
            # etc. are meaningless to end-users reading the dashboard feed);
            # show readable keys like domain names / hostnames / zone names.
            try:
                _uuid.UUID(ev.target_key)
                target_display = None
            except ValueError:
                target_display = ev.target_key
        recent_activity.append(
            {
                "ts": ev.ts,
                "actor": actor.username if actor else "system",
                "action": ev.action,
                "target": target_display,
                "target_type": ev.target_type,
                "outcome": ev.outcome,
            }
        )

    # MFA backup-code low-water check. If the user enrolled TOTP but has
    # burned through most of their backup codes, surface a banner so they
    # regenerate before the next phone wipe leaves them locked out.
    backup_codes_remaining = 0
    if user.mfa_enrolled:
        backup_codes_remaining = (
            db.execute(
                text("SELECT COUNT(*) FROM mfa_backup_codes " "WHERE user_id = :u AND used_at IS NULL"),
                {"u": user.id},
            ).scalar_one()
            or 0
        )

    ctx = _base_ctx(
        request,
        user=user,
        stats=stats,
        recent_audit=recent_activity,
        now_local=datetime.now().strftime("%A · %b %d · %H:%M"),
        backup_codes_remaining=backup_codes_remaining,
        backup_codes_low=user.mfa_enrolled and backup_codes_remaining < 3,
    )
    return templates().TemplateResponse("dashboard.html", ctx)


@router.get("/dns-tools", response_class=HTMLResponse)
async def dns_tools(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    # Dropdowns are fed from the resolvers table -- house entries + this
    # user's private entries -- grouped by scope so the UI renders
    # <optgroup>House / <optgroup>Mine. Falls back gracefully to the
    # in-code PUBLIC_RESOLVERS tuple if the table is empty (fresh install
    # before the seed runs, or a DB blip).
    from sqlalchemy import func

    from app.models.resolver import Resolver as _Resolver

    try:
        # Alphabetical (case-insensitive) -- keeps Dig/Propagation/Reverse
        # dropdowns in a stable order regardless of add/edit sequence.
        house_rows = (
            db.execute(
                select(_Resolver)
                .where(_Resolver.owner_user_id.is_(None))
                .order_by(func.lower(_Resolver.name))
            )
            .scalars()
            .all()
        )
        mine_rows = (
            db.execute(
                select(_Resolver)
                .where(_Resolver.owner_user_id == user.id)
                .order_by(func.lower(_Resolver.name))
            )
            .scalars()
            .all()
        )
    except Exception:
        house_rows, mine_rows = [], []

    if not house_rows:
        from app.dns.propagation import PUBLIC_RESOLVERS

        house_resolvers = [
            {"name": n, "ip": ip, "region": None, "group_tag": None} for n, ip in PUBLIC_RESOLVERS
        ]
    else:
        house_resolvers = [
            {"name": r.name, "ip": str(r.ip), "region": r.region, "group_tag": r.group_tag}
            for r in house_rows
        ]
    my_resolvers = [
        {"name": r.name, "ip": str(r.ip), "region": r.region, "group_tag": r.group_tag} for r in mine_rows
    ]
    # Distinct group_tag values — fed to the Hop Trace + Propagation
    # "Limit to group" selector.
    resolver_groups = sorted({r.group_tag for r in (house_rows + mine_rows) if r.group_tag}, key=str.lower)
    ctx = _base_ctx(
        request,
        user=user,
        house_resolvers=house_resolvers,
        my_resolvers=my_resolvers,
        resolver_groups=resolver_groups,
    )
    return templates().TemplateResponse("dns_tools.html", ctx)


@router.get("/network-tools", response_class=HTMLResponse)
async def network_tools(
    request: Request,
    user: User = Depends(current_user),
):
    ctx = _base_ctx(request, user=user, scope=get_settings().scope_of_use)
    return templates().TemplateResponse("network_tools.html", ctx)


@router.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel(
    request: Request,
    user: User = Depends(current_user),
):
    from app.db import session_scope
    from app.models.threat_intel_source import ThreatIntelSource

    with session_scope() as db:
        rows = db.execute(select(ThreatIntelSource)).scalars().all()
        enabled = {r.source_key: bool(r.enabled) for r in rows}

    # If the sources table hasn't been seeded (fresh migration, etc.),
    # default every source to enabled so the page still works.
    def on(key: str) -> bool:
        return enabled.get(key, True)

    ctx = _base_ctx(request, user=user, scope=get_settings().scope_of_use, ti_sources=enabled, ti_on=on)
    return templates().TemplateResponse("threat_intel.html", ctx)


_WIZARD_CATALOG: list[tuple[str, dict[str, str]]] = [
    (
        "dns.resolve_fail",
        {
            "name": "Why isn't my domain resolving?",
            "category": "ddi",
            "description": "Registrar → delegation → SOA → authoritative → cache → DNSSEC → propagation",
        },
    ),
    (
        "mail.delivery",
        {
            "name": "Why isn't my mail being delivered?",
            "category": "ddi",
            "description": "MX → A/AAAA → PTR → SPF → DMARC → MTA-STS → TLS-RPT",
        },
    ),
    (
        "ssl.deep_inspect",
        {
            "name": "SSL/TLS deep inspect",
            "category": "ddi",
            "description": "Chain · hostname · expiry · key type · issuer · self-signed check",
        },
    ),
    (
        "dnssec.chain",
        {
            "name": "DNSSEC chain walker",
            "category": "ddi",
            "description": "Root → TLD → zone trust chain · flags the exact broken link",
        },
    ),
    (
        "zone.health",
        {
            "name": "Zone health check",
            "category": "ddi",
            "description": "SOA drift, NSEC integrity, dangling CNAMEs, missing glue",
        },
    ),
    (
        "registrar.mismatch",
        {
            "name": "Registrar vs authoritative mismatch",
            "category": "ddi",
            "description": "Compares registrar-side NS list with live authoritative NS",
        },
    ),
    (
        "domain.bringup",
        {
            "name": "New domain bring-up checklist",
            "category": "ddi",
            "description": "Green / yellow / red scorecard across core records",
        },
    ),
    (
        "cloudflare.validator",
        {
            "name": "Cloudflare / CDN config validator",
            "category": "ddi",
            "description": "NS delegation, DNSSEC compat, origin A records",
        },
    ),
    (
        "typosquat.sweep",
        {
            "name": "Typosquat sweep + threat hunt",
            "category": "ddi",
            "description": "IDN/homograph/typo variants; which are registered + live",
        },
    ),
    (
        "dmarc.tuning",
        {
            "name": "DMARC tuning guide",
            "category": "ddi",
            "description": "Walks p=none → quarantine → reject based on current policy",
        },
    ),
    (
        "axfr.audit",
        {
            "name": "Zone transfer (AXFR) audit",
            "category": "ddi",
            "description": "Tests every authoritative NS for exposed zone transfers",
        },
    ),
    (
        "ip.reputation",
        {
            "name": "IP reputation deep dive",
            "category": "ddi",
            "description": "ASN/WHOIS + Shodan InternetDB (open ports, known CVEs)",
        },
    ),
    (
        "infoblox.drift",
        {
            "name": "Infoblox drift detector",
            "category": "ddi",
            "description": "Live DNS vs Infoblox Grid expected state diff",
        },
    ),
    (
        "network.reachability",
        {
            "name": "Why can't I reach X?",
            "category": "network",
            "description": "DNS → ping → trace → TCP → HTTP · stops + explains first failure",
        },
    ),
    (
        "network.up_for_everyone",
        {
            "name": "Is this site down for me or everyone?",
            "category": "network",
            "description": "Local probe vs public-resolver probe, side-by-side",
        },
    ),
    (
        "mail.flow_validator",
        {
            "name": "Mail-flow validator",
            "category": "network",
            "description": "End-to-end mail stack: MX, SMTP ports, SPF, DMARC, PTR",
        },
    ),
]


@router.get("/runbooks", response_class=HTMLResponse)
async def runbooks_page(
    request: Request,
    user: User = Depends(current_user),
):
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("runbooks.html", ctx)


@router.get("/wizards", response_class=HTMLResponse)
async def wizards_page(
    request: Request,
    user: User = Depends(current_user),
):
    # Show only wizards whose implementation is registered. The engine's
    # list_wizards() returns keys; we pair each with the catalog entry above.
    from app.wizards.engine import list_wizards as registered

    keys = set(registered())
    catalog = [(k, meta) for k, meta in _WIZARD_CATALOG if k in keys]
    ctx = _base_ctx(request, user=user, catalog=catalog)
    return templates().TemplateResponse("wizards.html", ctx)


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")

    from app.admin.routes import SERVICE_DESCRIPTIONS, _svc_status

    services = [_svc_status(n) for n in SERVICE_DESCRIPTIONS.keys()]

    from sqlalchemy import text as _text

    jobs_rows = db.execute(
        _text(
            "SELECT name, description, cron_expression, enabled, last_run_status "
            "FROM jobs ORDER BY name LIMIT 40"
        )
    ).fetchall()
    jobs = [dict(r._mapping) for r in jobs_rows]

    audit_rows = db.execute(
        _text("SELECT ts, action, target_key, outcome FROM audit_events " "ORDER BY ts DESC LIMIT 20")
    ).fetchall()
    audit_ev = [dict(r._mapping) for r in audit_rows]

    from datetime import datetime, timedelta

    day_ago = datetime.now(UTC) - timedelta(days=1)
    stats = {
        "users_enabled": db.execute(
            _text("SELECT count(*) FROM users WHERE enabled AND deleted_at IS NULL")
        ).scalar_one(),
        "sessions_active": db.execute(
            _text("SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()")
        ).scalar_one(),
        "monitors_enabled": db.execute(_text("SELECT count(*) FROM monitors WHERE enabled")).scalar_one(),
        "audit_24h": db.execute(
            _text("SELECT count(*) FROM audit_events WHERE ts > :t"), {"t": day_ago}
        ).scalar_one(),
        "integrity_last_scan": db.execute(
            _text("SELECT started_at, mismatches FROM db_integrity_scans " "ORDER BY started_at DESC LIMIT 1")
        ).first(),
    }
    ctx = _base_ctx(request, user=user, services=services, jobs=jobs, audit=audit_ev, stats=stats)
    return templates().TemplateResponse("admin.html", ctx)


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    sessions = (
        db.execute(
            select(SessionModel)
            .where(
                SessionModel.user_id == user.id,
                SessionModel.revoked_at.is_(None),
            )
            .order_by(SessionModel.last_active_at.desc())
        )
        .scalars()
        .all()
    )
    current_sid = getattr(request.state, "session_id", None)
    ctx = _base_ctx(request, user=user, sessions=sessions, current_session_id=current_sid)
    return templates().TemplateResponse("settings.html", ctx)


@router.get("/monitors", response_class=HTMLResponse)
async def monitors_page(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    from sqlalchemy import or_

    from app.models.monitor import Monitor as _M

    rows = (
        db.execute(select(_M).where(or_(_M.owner_id == user.id, _M.owner_id.is_(None))).order_by(_M.name))
        .scalars()
        .all()
    )
    ctx = _base_ctx(request, user=user, monitors=rows)
    return templates().TemplateResponse("monitors.html", ctx)


@router.get("/files", response_class=HTMLResponse)
async def files_page(
    request: Request,
    user: User = Depends(current_user),
):
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("files.html", ctx)


@router.get("/links", response_class=HTMLResponse)
async def links_page(
    request: Request,
    user: User = Depends(current_user),
):
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("links.html", ctx)


@router.get("/messages", response_class=HTMLResponse)
async def messages_page(
    request: Request,
    user: User = Depends(current_user),
):
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("messages.html", ctx)


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(
    request: Request,
    user: User = Depends(current_user),
):
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("reports.html", ctx)


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_users.html", ctx)


@router.get("/admin/settings", response_class=HTMLResponse)
async def global_settings_page(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    """Super-admin-only Global Settings: the portal's policy root.
    Gathers session/idle, password, MFA, lockout, audit retention, and
    role-management surfaces in one place so compliance audits (SOC 2 /
    HIPAA / ISO 27001) have a single page to point at."""
    if user.role != "super_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "super_admin role required")
    # Pull the live branding row -- most policy fields live there today.
    # Wrap in a SAVEPOINT so a failure inside `load_branding` (e.g. the
    # branding table is missing on a fresh install) doesn't poison the
    # outer transaction. Without this, the next db.execute() below fails
    # with "current transaction is aborted, commands ignored until end
    # of transaction block".
    branding_row = None
    try:
        with db.begin_nested():
            from app.models.branding import load as load_branding

            branding_row = load_branding(db)
    except Exception:
        pass
    # Distinct role names currently in use (used to seed the role list
    # until a proper roles table exists). User.role is a Postgres enum
    # (user_role) so lower() doesn't apply -- cast to text first, and
    # normalise to strings for the template since enum values would
    # otherwise carry the enum class reference.
    # SELECT DISTINCT requires ORDER BY expressions to appear in the
    # select list, so we order in Python instead of SQL. Cast the enum
    # to TEXT since `lower(user_role)` isn't defined in Postgres.
    from sqlalchemy import Text, cast, distinct

    roles_raw = db.execute(select(distinct(cast(User.role, Text)))).scalars().all()
    roles_in_use = sorted([str(r) for r in roles_raw if r], key=str.lower)
    ctx = _base_ctx(
        request,
        user=user,
        branding_row=branding_row,
        roles_in_use=list(roles_in_use),
        active="global-settings",
    )
    return templates().TemplateResponse("admin_settings.html", ctx)


@router.get("/admin/scope", response_class=HTMLResponse)
async def admin_scope_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    ctx = _base_ctx(request, user=user, scope_of_use=get_settings().scope_of_use)
    return templates().TemplateResponse("admin_scope.html", ctx)


@router.get("/admin/integrations", response_class=HTMLResponse)
async def admin_integrations_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_integrations.html", ctx)


@router.get("/admin/vuln", response_class=HTMLResponse)
async def admin_vuln_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_vuln.html", ctx)


@router.get("/admin/health", response_class=HTMLResponse)
async def admin_health_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_health.html", ctx)


@router.get("/admin/network", response_class=HTMLResponse)
async def admin_network_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role != "super_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "super_admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_network.html", ctx)


@router.get("/admin/credentials", response_class=HTMLResponse)
async def admin_credentials_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role != "super_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "super_admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_credentials.html", ctx)


@router.get("/admin/updates", response_class=HTMLResponse)
async def admin_updates_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_updates.html", ctx)


@router.get("/admin/devices", response_class=HTMLResponse)
async def admin_devices_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_devices.html", ctx)


@router.get("/admin/webhooks", response_class=HTMLResponse)
async def admin_webhooks_page(
    request: Request,
    user: User = Depends(current_user),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    ctx = _base_ctx(request, user=user)
    return templates().TemplateResponse("admin_webhooks.html", ctx)


@router.get("/admin/branding", response_class=HTMLResponse)
async def admin_branding_page(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    from app.models.branding import load as load_branding

    b = load_branding(db)
    ctx = _base_ctx(request, user=user, b=b)
    return templates().TemplateResponse("admin_branding.html", ctx)


@router.get("/approvals", response_class=HTMLResponse)
async def approvals_page(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    from app.approvals.engine import list_mine, list_pending

    ctx = _base_ctx(
        request,
        user=user,
        pending=list_pending(db),
        mine=list_mine(db, user=user),
    )
    return templates().TemplateResponse("approvals.html", ctx)


@router.get("/directory", response_class=HTMLResponse)
async def directory_page(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    from app.models.directory import DirectoryIntegration

    integ = (
        db.execute(
            select(DirectoryIntegration)
            .where(DirectoryIntegration.enabled.is_(True))
            .order_by(DirectoryIntegration.created_at.asc())
        )
        .scalars()
        .first()
    )
    ctx = _base_ctx(request, user=user, integration=integ)
    return templates().TemplateResponse("directory.html", ctx)


@router.get("/certificates", response_class=HTMLResponse)
async def certs_page(
    request: Request,
    user: User = Depends(current_user),
    db: OrmSession = Depends(fastapi_dep_db),
):
    from datetime import datetime

    from app.models.cert import Certificate

    rows = (
        db.execute(select(Certificate).order_by(Certificate.valid_until.asc().nulls_last())).scalars().all()
    )
    now = datetime.now(UTC)
    certs: list[dict] = []
    for c in rows:
        days = None
        if c.valid_until:
            # SQLAlchemy returns aware datetimes from TIMESTAMPTZ, but be defensive.
            vu = c.valid_until if c.valid_until.tzinfo else c.valid_until.replace(tzinfo=UTC)
            days = max(0, (vu - now).days)
        certs.append(
            {
                "id": c.id,
                "common_name": c.common_name,
                "sans": list(c.sans or []),
                "cert_type": c.cert_type,
                "issuer": c.issuer,
                "valid_until": c.valid_until,
                "days_remaining": days,
                "key_type": c.key_type,
                "auto_renew": c.auto_renew,
            }
        )
    ctx = _base_ctx(request, user=user, certs=certs)
    return templates().TemplateResponse("certificates.html", ctx)

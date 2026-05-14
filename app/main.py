from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as OrmSession

from app.api.v1 import api_v1
from app.auth.csrf import CsrfMiddleware
from app.auth.deps import require_permission
from app.config import get_settings
from app.db import fastapi_dep_db, get_engine
from app.metrics import PrometheusMiddleware, render_metrics
from app.models.user import User
from app.ui.routes import router as ui_router


settings = get_settings()
app = FastAPI(
    title=f"{settings.portal_name} — Network Intelligence Platform",
    version=settings.manifest_version,
    docs_url=None if not settings.airgapped else "/api-docs",
    redoc_url=None,
)

templates = Jinja2Templates(directory=str(settings.install_root / "app" / "templates"))
try:
    app.mount(
        "/static",
        StaticFiles(directory=str(settings.install_root / "app" / "static")),
        name="static",
    )
except RuntimeError:
    # Static dir absent during tests/dev; fine to skip.
    pass

try:
    app.mount(
        "/docs",
        StaticFiles(
            directory=str(settings.install_root / "docs"),
            html=True,
        ),
        name="docs",
    )
except RuntimeError:
    pass

app.add_middleware(CsrfMiddleware)
app.add_middleware(PrometheusMiddleware)

app.include_router(api_v1)
app.include_router(ui_router)


@app.get("/metrics", include_in_schema=False)
def metrics(_: User = Depends(require_permission("admin.system.metrics"))):
    # Prometheus-format exposition. Scraper authenticates with a bearer API
    # token whose scopes include admin.system.metrics. Restrict to the
    # scraper's IP in nginx for defence in depth.
    return render_metrics()


@app.get("/healthz", include_in_schema=False)
def healthz() -> JSONResponse:
    # Per-component probes (DB, broker, BIND9, license, certs). DB + broker
    # are critical — any "down" there flips the response to 503. BIND9 /
    # license / certs are warn-only because the portal serves correctly
    # without them; flagging 503 there would have oncall paging on stale
    # cert expiries.
    from app.system.health_probes import gather
    body, code = gather()
    return JSONResponse(body, status_code=code)


@app.get("/", include_in_schema=False)
def root() -> "RedirectResponse":
    # Land on the UI. Unauthenticated users bounce to /ui/login via the
    # current_user dependency on /ui/dashboard.
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/ui/dashboard", status_code=303)


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    # Browser hitting a /ui/* page unauthenticated → bounce to login with
    # a next= so we return them here post-auth. API callers still get JSON.
    # Also clear the session cookie — without this, a stale cookie loops
    # login_page → dashboard → 401 → login_page because login_page only
    # checks for cookie existence, not validity.
    if exc.status_code == 401 and request.url.path.startswith("/ui/"):
        from urllib.parse import quote
        from app.auth.csrf import SESSION_COOKIE
        resp = RedirectResponse(
            url=f"/ui/login?next={quote(request.url.path)}",
            status_code=303,
        )
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp
    return JSONResponse(
        {"error": exc.detail, "status": exc.status_code},
        status_code=exc.status_code,
    )


@app.exception_handler(Exception)
async def unhandled_exc_handler(request: Request, exc: Exception):
    # Anything that isn't an HTTPException or RequestValidationError ends up here.
    # Surface the type + message so the UI can render it instead of "HTTP 500: )".
    # Full traceback still goes to app-error.log via the worker.
    import logging
    logging.getLogger("meridian").exception("unhandled in %s %s", request.method, request.url.path)
    return JSONResponse(
        {"error": f"{type(exc).__name__}: {exc}", "status": 500},
        status_code=500,
    )


@app.exception_handler(RequestValidationError)
async def validation_exc_handler(request: Request, exc: RequestValidationError):
    # FastAPI's default is {"detail": [{...}, ...]} — the frontend renders that
    # as "[object Object]". Flatten to a single human-readable string.
    parts = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", []) if x not in ("body",))
        msg = err.get("msg", "invalid value")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return JSONResponse(
        {"error": "; ".join(parts) or "validation error", "status": 422},
        status_code=422,
    )

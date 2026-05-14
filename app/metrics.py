from __future__ import annotations

import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

REGISTRY = CollectorRegistry()

HTTP_REQUESTS = Counter(
    "meridian_http_requests_total",
    "HTTP requests processed, labelled by method, path template, and status class.",
    ["method", "route", "status"],
    registry=REGISTRY,
)

HTTP_LATENCY = Histogram(
    "meridian_http_request_seconds",
    "HTTP request duration in seconds, labelled by method and path template.",
    ["method", "route"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=REGISTRY,
)

DB_UP = Gauge(
    "meridian_db_up",
    "1 if the last /metrics scrape could SELECT 1 from PostgreSQL, else 0.",
    registry=REGISTRY,
)


def _route_template(request: Request) -> str:
    # Use the matched route's path template (e.g. "/api/v1/devices/{id}")
    # rather than the raw URL — otherwise cardinality explodes per UUID.
    route = request.scope.get("route")
    if route is not None and getattr(route, "path", None):
        return route.path
    return request.url.path


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/metrics":
            return await call_next(request)
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        route = _route_template(request)
        status_class = f"{response.status_code // 100}xx"
        HTTP_REQUESTS.labels(request.method, route, status_class).inc()
        HTTP_LATENCY.labels(request.method, route).observe(elapsed)
        return response


def render_metrics() -> Response:
    from app.db import get_engine

    try:
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        DB_UP.set(1)
    except Exception:
        DB_UP.set(0)

    payload = generate_latest(REGISTRY)
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)

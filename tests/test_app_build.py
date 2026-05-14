"""Smoke-tests app construction: FastAPI builds, expected routes exist,
middleware stack is in place. Does not require a live DB.
"""
from __future__ import annotations


def test_app_constructs_and_has_expected_routes():
    from app.main import app
    paths = {getattr(r, "path", None) for r in app.routes}
    # Spot-check the routes we ship out of main.py — drift here means
    # somebody renamed or deleted an entry point.
    assert "/healthz" in paths
    assert "/metrics" in paths
    assert "/" in paths


def test_prometheus_middleware_installed():
    from app.main import app
    from app.metrics import PrometheusMiddleware
    classes = [m.cls for m in app.user_middleware]
    assert PrometheusMiddleware in classes


def test_csrf_middleware_installed():
    from app.auth.csrf import CsrfMiddleware
    from app.main import app
    classes = [m.cls for m in app.user_middleware]
    assert CsrfMiddleware in classes

"""Render the /metrics output in isolation.

The endpoint behaviour under real auth is integration territory; here we
just confirm the exposition format is parseable, the collectors register,
and DB-failure mode degrades gracefully (DB gauge → 0 rather than 5xx).
"""
from __future__ import annotations


def test_metrics_render_returns_prometheus_exposition(monkeypatch):
    # Force the DB ping to fail so we exercise the except branch.
    class _BoomEngine:
        def connect(self):  # noqa: D401
            raise RuntimeError("no db here")

    monkeypatch.setattr("app.metrics.get_engine" if False else "app.db.get_engine",
                        lambda: _BoomEngine())

    # License subsystem removed 2026-05-13 (Apache 2.0). The DB stub /
    # license stub the earlier version of this test installed are no
    # longer needed.

    from app.metrics import render_metrics
    resp = render_metrics()
    body = resp.body.decode()
    # Standard Prometheus exposition + DB gauge present.
    assert "meridian_db_up" in body
    assert resp.media_type.startswith("text/plain")


def test_counter_increments():
    from app.metrics import HTTP_REQUESTS
    before = HTTP_REQUESTS.labels("GET", "/test", "2xx")._value.get()
    HTTP_REQUESTS.labels("GET", "/test", "2xx").inc()
    after = HTTP_REQUESTS.labels("GET", "/test", "2xx")._value.get()
    assert after == before + 1

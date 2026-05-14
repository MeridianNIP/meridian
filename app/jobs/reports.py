"""Celery beat task — ticks every minute, fires due report schedules."""

from __future__ import annotations

from app.celery_app import celery_app
from app.db import session_scope
from app.reports.runner import claim_and_run_due


@celery_app.task(name="meridian.jobs.reports.tick")
def tick() -> dict:
    with session_scope() as db:
        n = claim_and_run_due(db)
    return {"executed": n}

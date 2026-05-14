from __future__ import annotations

from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "meridian",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.jobs.ad",
        "app.jobs.backup",
        "app.jobs.cert",
        "app.jobs.db",
        "app.jobs.devices",
        "app.jobs.health",
        "app.jobs.integrity",
        "app.jobs.oss",
        "app.jobs.retention",
        "app.jobs.upgrade",
        "app.jobs.vuln",
        "app.logging.shipper",
        "app.jobs.password",
        "app.jobs.reports",
        "app.monitors.collector",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone=settings.timezone,
    enable_utc=True,
    worker_prefetch_multiplier=4,
    task_acks_late=True,
    # redbeat reads schedules from the jobs table — the actual beat schedule
    # is loaded at startup by app.jobs.scheduler.load_from_db().
    beat_scheduler="redbeat.RedBeatScheduler",
    redbeat_redis_url=settings.redis_url,
)

# Importing the scheduler module runs `load_schedule_from_db()` and assigns
# the result to `celery_app.conf.beat_schedule`. Without this import the
# `celery -A app.celery_app beat` process never sees the job table entries,
# so redbeat starts with an empty schedule (monitors never sample, cleanup
# jobs never run, etc).
from app.jobs import scheduler as _scheduler  # noqa: F401

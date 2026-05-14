"""Centralised safety limits — no networking bombs.

This file is the single place to look up "how aggressively is X allowed
to hammer something?" Every poll, monitor, fan-out, scan, or scheduled
job that does outbound work should pull its floor / ceiling / fan-out
constant from here, NOT define one locally.

Why centralised:

  - One file to audit when the maintainer worries about defaults.
  - When an admin asks "what's the floor on monitors?" we can answer
    by pointing at one line.
  - Diffs against this file are easy to security-review.

Two helper functions:

  - clamp(value, floor, ceiling)            — runtime safety clamp
  - bounded_gather(awaitables, max_workers) — asyncio.gather with a
                                              Semaphore so a 5000-item
                                              fan-out can't open 5000
                                              concurrent sockets.

The principle (per `project_meridian_safety_caps.md` memory):
defaults must be safe. An admin who raises a cap intentionally is
responsible for the consequences, but the OUT-OF-THE-BOX deployment
cannot become a DDoS source.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Iterable
from typing import TypeVar

# ============================================================================
# Floors / ceilings — alphabetical by feature area.
# ============================================================================

# --- Background scheduled jobs --------------------------------------------
# Refresh intervals for periodic jobs (Celery beat / redbeat).
CERT_REFRESH_INTERVAL_S = 6 * 3600  # cert expiry sweep: 4x per day
THREAT_FEED_REFRESH_S = 6 * 3600  # threat-intel refresh: 4x per day
INTEGRITY_SCAN_INTERVAL_S = 24 * 3600  # audit-row HMAC scan: once per day

# --- DNS tools ------------------------------------------------------------
PROPAGATION_MAX_RESOLVERS = 32  # cap fan-out even if user adds 200 to panel
PROPAGATION_PER_RESOLVER_TIMEOUT_S = 3
PROPAGATION_CONCURRENCY = 16  # max simultaneous dig sockets

REVERSE_DNS_MAX_HOSTS = 1024  # per-request ceiling for batch PTR
REVERSE_DNS_CONCURRENCY = 16

WHOIS_BULK_MAX = 200  # already enforced in routes; mirrored here
WHOIS_CONCURRENCY = 4  # WHOIS servers hate concurrency

TYPOSQUAT_MAX_VARIANTS = 500
TYPOSQUAT_CONCURRENCY = 16

# --- Network tools --------------------------------------------------------
PING_COUNT_MAX = 100
PING_INTERVAL_FLOOR_S = 0.2
PING_INTERVAL_CEILING_S = 30.0

TRACEROUTE_MAX_HOPS = 64
TRACEROUTE_PROBES_MAX = 5

PORT_SCAN_MAX_PORTS = 1024
PORT_SCAN_CONCURRENCY_MAX = 256

HTTP_TEST_MAX_REDIRECTS = 10
HTTP_TEST_TIMEOUT_CEILING_S = 60  # don't let a user pin a worker for hours

# --- Monitors -------------------------------------------------------------
MONITOR_INTERVAL_FLOOR_S = 30  # never poll faster than every 30s
MONITOR_INTERVAL_CEILING_S = 3600  # never queue a check less often than 1/hr
MONITOR_PER_CHECK_TIMEOUT_S = 30  # any single probe wall-clock cap

# --- Cert portfolio sweep --------------------------------------------------
CERT_REFRESH_CONCURRENCY = 10  # parallel TLS handshakes / OCSP probes

# --- External API integrations (per-process, in-memory rate limit) ---------
# Each external integration gets a token bucket with this many tokens per
# minute. If a user hammers the endpoint, requests beyond the budget queue
# briefly and then 429. Defends against a buggy retry loop in user code.
EXTERNAL_API_TOKENS_PER_MIN = {
    "censys": 30,
    "shodan": 30,
    "virustotal": 30,
    "ripestat": 60,  # public, generous
    "team_cymru": 60,
    "ipapi": 30,
    "bgpview": 30,
    "crtsh": 60,
    "default": 30,  # fallback for any integration not listed
}


# ============================================================================
# Helpers
# ============================================================================


def clamp(value: float | int, *, floor: float | int, ceiling: float | int) -> float | int:
    """Runtime clamp — survives a malicious admin editing the DB row.

    Use this at the point where a user-supplied interval / count / timeout
    is about to drive actual work, NOT just at the form validator. A clamp
    in two places is worth ten in one.
    """
    if value < floor:
        return floor
    if value > ceiling:
        return ceiling
    return value


T = TypeVar("T")


async def bounded_gather(
    awaitables: Iterable[Awaitable[T]],
    *,
    max_workers: int,
    return_exceptions: bool = False,
) -> list[T]:
    """asyncio.gather() with a Semaphore — prevents a 5000-item fan-out
    from opening 5000 concurrent sockets. The semaphore is created
    per-call so it's safe to use across event loops.
    """
    sem = asyncio.Semaphore(max_workers)

    async def _run(aw: Awaitable[T]) -> T:
        async with sem:
            return await aw

    return await asyncio.gather(
        *(_run(a) for a in awaitables),
        return_exceptions=return_exceptions,
    )


# ============================================================================
# Per-API token-bucket rate limiter (process-local)
# ============================================================================
# Lightweight token bucket — one bucket per (api_name). Used by external
# integration wrappers to throttle outbound calls so a buggy loop in the
# UI can't escape via direct API hits.

import time


class _Bucket:
    __slots__ = ("tokens", "last_refill", "rate", "capacity")

    def __init__(self, rate_per_minute: int):
        self.rate = rate_per_minute / 60.0  # tokens per second
        self.capacity = float(rate_per_minute)  # burst = 1 minute's worth
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def try_acquire(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


_BUCKETS: dict[str, _Bucket] = {}


def acquire_token(api_name: str) -> bool:
    """Try to take one token from the named API's bucket. Returns True on
    success, False if the bucket is empty (caller should respond 429 or
    queue + retry). The bucket is process-local — for multi-worker
    deployments this is per-worker; still good enough to defeat the
    "user clicks button 1000 times" class of misuse."""
    rate = EXTERNAL_API_TOKENS_PER_MIN.get(api_name, EXTERNAL_API_TOKENS_PER_MIN["default"])
    b = _BUCKETS.get(api_name)
    if b is None or b.rate != rate / 60.0:
        b = _Bucket(rate)
        _BUCKETS[api_name] = b
    return b.try_acquire()


def require_token(api_name: str) -> None:
    """Raise HTTPException(429) if the bucket is empty. Import-late so
    this module stays usable from non-FastAPI contexts (Celery workers,
    CLI scripts) where HTTPException isn't appropriate."""
    if acquire_token(api_name):
        return
    from fastapi import HTTPException, status

    raise HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        f"rate limit exceeded for {api_name}; default budget "
        f"{EXTERNAL_API_TOKENS_PER_MIN.get(api_name, EXTERNAL_API_TOKENS_PER_MIN['default'])} req/min",
    )

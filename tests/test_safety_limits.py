"""Unit tests for app.safety.limits — verify the token bucket actually
rate-limits and the bounded_gather actually caps concurrency."""
import asyncio

import pytest

from app.safety import limits


def test_clamp_floors():
    assert limits.clamp(5, floor=10, ceiling=100) == 10


def test_clamp_ceilings():
    assert limits.clamp(500, floor=10, ceiling=100) == 100


def test_clamp_passes_through_in_range():
    assert limits.clamp(50, floor=10, ceiling=100) == 50


def test_token_bucket_admits_burst():
    # Reset the bucket for this api name
    limits._BUCKETS.pop("test_burst", None)
    limits.EXTERNAL_API_TOKENS_PER_MIN["test_burst"] = 60   # 1/sec, burst 60
    # Burst of 60 should pass; the 61st should fail.
    admits = [limits.acquire_token("test_burst") for _ in range(60)]
    assert all(admits)
    assert not limits.acquire_token("test_burst")


def test_token_bucket_refills():
    limits._BUCKETS.pop("test_refill", None)
    limits.EXTERNAL_API_TOKENS_PER_MIN["test_refill"] = 600   # 10/sec
    # Drain the bucket
    for _ in range(600):
        limits.acquire_token("test_refill")
    assert not limits.acquire_token("test_refill")
    # Now jam the bucket forward in time so it refills
    bucket = limits._BUCKETS["test_refill"]
    bucket.last_refill -= 1.0   # pretend 1 second passed
    assert limits.acquire_token("test_refill")


@pytest.mark.asyncio
async def test_bounded_gather_caps_concurrency():
    high_water = 0
    in_flight = 0

    async def work(i):
        nonlocal in_flight, high_water
        in_flight += 1
        high_water = max(high_water, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return i

    # 50 tasks, max_workers=5 → high water mark should be 5, not 50.
    results = await limits.bounded_gather(
        [work(i) for i in range(50)],
        max_workers=5,
    )
    assert results == list(range(50))
    assert high_water == 5


def test_known_apis_have_explicit_budgets():
    # Regression — if someone removes a key, fall back to "default".
    for k in ("censys", "shodan", "virustotal", "ripestat", "team_cymru"):
        assert k in limits.EXTERNAL_API_TOKENS_PER_MIN

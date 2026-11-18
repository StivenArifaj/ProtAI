"""Tests for the distributed rate limiter (post-v1 additive foundation).

Verifies shared-store accounting, all-or-nothing charging, fail-closed behavior on
store errors, and local fallback. No Redis dependency; the store client is injected.
"""

from __future__ import annotations

import asyncio

from ai_security.soc.distributed_rate_limiter import (
    DistributedRateLimiter,
    RedisRateLimiterStore,
)


def _run(coro) -> object:
    return asyncio.run(coro)


class InMemoryStore:
    """Simulates an atomic shared counter store."""

    def __init__(self) -> None:
        self.counters: dict[str, int] = {}
        self.fail = False

    async def increment(
        self, key: str, window_seconds: int, *, amount: int = 1, limit: int | None = None
    ) -> int | None:
        if self.fail:
            raise RuntimeError("store unavailable")
        current = self.counters.get(key, 0)
        if limit is not None and current + amount > limit:
            return None  # all-or-nothing: reject, do not increment
        self.counters[key] = current + amount
        return self.counters[key]


class LocalLimiter:
    """Stand-in for the v1 per-process limiter (all-or-nothing)."""

    def __init__(self) -> None:
        self.count = 0

    def allow_many(self, bucket: str, identity: str, limit: int, count: int) -> bool:
        if self.count + count > limit:
            return False
        self.count += count
        return True


def test_shared_store_counts_across_instances() -> None:
    """Two limiter instances sharing one store share the limit."""
    store = InMemoryStore()
    l1 = DistributedRateLimiter(store=store, clock=lambda: 0.0)
    l2 = DistributedRateLimiter(store=store, clock=lambda: 0.0)

    r1 = _run(l1.allow("requests", "principal-1", 3))
    r2 = _run(l2.allow("requests", "principal-1", 3))
    r3 = _run(l1.allow("requests", "principal-1", 3))
    r4 = _run(l2.allow("requests", "principal-1", 3))

    assert r1.allowed is True
    assert r2.allowed is True
    assert r3.allowed is True
    assert r4.allowed is False  # 4th call across two instances exceeds limit=3


def test_all_or_nothing_charging() -> None:
    store = InMemoryStore()
    limiter = DistributedRateLimiter(store=store, clock=lambda: 0.0)

    r1 = _run(limiter.allow_many("tool_calls", "p1", 5, 3))
    r2 = _run(limiter.allow_many("tool_calls", "p1", 5, 2))
    r3 = _run(limiter.allow_many("tool_calls", "p1", 5, 1))

    assert r1.allowed is True
    assert r2.allowed is True
    assert r3.allowed is False
    # The failed attempt did not advance the counter (store total is 5, not 6)
    assert store.counters[next(iter(store.counters))] == 5


def test_store_failure_fails_closed_without_fallback() -> None:
    store = InMemoryStore()
    store.fail = True
    limiter = DistributedRateLimiter(store=store, clock=lambda: 0.0)

    decision = _run(limiter.allow("requests", "p1", 10))
    assert decision.allowed is False  # deny, never fail-open


def test_store_failure_with_local_fallback() -> None:
    store = InMemoryStore()
    store.fail = True
    local = LocalLimiter()
    limiter = DistributedRateLimiter(store=store, local_limiter=local, clock=lambda: 0.0)

    decision = _run(limiter.allow("requests", "p1", 10))
    assert decision.allowed is True  # local per-process fallback applied


def test_no_store_uses_local_fallback() -> None:
    local = LocalLimiter()
    limiter = DistributedRateLimiter(store=None, local_limiter=local, clock=lambda: 0.0)

    assert _run(limiter.allow("requests", "p1", 2)).allowed is True
    assert _run(limiter.allow("requests", "p1", 2)).allowed is True
    assert _run(limiter.allow("requests", "p1", 2)).allowed is False


def test_no_store_no_fallback_fails_closed() -> None:
    limiter = DistributedRateLimiter(store=None, local_limiter=None, clock=lambda: 0.0)
    assert _run(limiter.allow("requests", "p1", 10)).allowed is False


def test_window_rollover_via_key() -> None:
    """Different clock windows produce different keys (fixed-window semantics)."""
    store = InMemoryStore()
    l1 = DistributedRateLimiter(store=store, window_seconds=60, clock=lambda: 30.0)
    l2 = DistributedRateLimiter(store=store, window_seconds=60, clock=lambda: 90.0)

    assert _run(l1.allow("requests", "p1", 1)).allowed is True
    assert _run(l2.allow("requests", "p1", 1)).allowed is True  # new window, new key
    assert len(store.counters) == 2


def test_identity_and_bucket_isolation() -> None:
    store = InMemoryStore()
    limiter = DistributedRateLimiter(store=store, clock=lambda: 0.0)

    assert _run(limiter.allow("requests", "p1", 1)).allowed is True
    assert _run(limiter.allow("tool_calls", "p1", 1)).allowed is True  # different bucket
    assert _run(limiter.allow("requests", "p2", 1)).allowed is True  # different identity
    assert (
        _run(limiter.allow("requests", "p1", 1)).allowed is False
    )  # same bucket+identity exhausted


def test_invalid_inputs_rejected() -> None:
    store = InMemoryStore()
    limiter = DistributedRateLimiter(store=store, clock=lambda: 0.0)

    for args in [
        ("", "p1", 1, 1),
        ("bucket", "", 1, 1),
        ("bucket", "p1", 0, 1),
        ("bucket", "p1", 1, 0),
    ]:
        try:
            _run(limiter.allow_many(*args))
            raise AssertionError(f"expected ValueError for {args}")
        except ValueError:
            pass


def test_redis_store_without_client_returns_none() -> None:
    store = RedisRateLimiterStore(None)
    result = _run(store.increment("key", 60))
    assert result is None


def test_decision_fields_are_populated() -> None:
    store = InMemoryStore()
    limiter = DistributedRateLimiter(store=store, clock=lambda: 0.0)
    decision = _run(limiter.allow_many("requests", "p1", 10, 3))

    assert decision.allowed is True
    assert decision.consumed == 3
    assert decision.remaining == 7
    assert decision.limit == 10
    assert decision.window_seconds == 60
    assert decision.reset_at == 60.0

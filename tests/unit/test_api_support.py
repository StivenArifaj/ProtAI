"""Unit tests for the Phase 8 ingress helpers (ADR-015)."""

from __future__ import annotations

import pytest

from ai_security.api.rate_limit import FixedWindowRateLimiter


def test_allow_many_reserves_atomically() -> None:
    limiter = FixedWindowRateLimiter(window_seconds=60, clock=lambda: 100.0)
    assert limiter.allow_many("tool_calls", "tenant:user", 3, 2) is True
    # Only one slot remains: a two-slot reservation must not partially consume it.
    assert limiter.allow_many("tool_calls", "tenant:user", 3, 2) is False
    assert limiter.allow("tool_calls", "tenant:user", 3) is True
    assert limiter.allow("tool_calls", "tenant:user", 3) is False


def test_buckets_and_identities_are_isolated() -> None:
    limiter = FixedWindowRateLimiter(window_seconds=60, clock=lambda: 100.0)
    assert limiter.allow("a", "one", 1) is True
    assert limiter.allow("a", "one", 1) is False
    assert limiter.allow("b", "one", 1) is True
    assert limiter.allow("a", "two", 1) is True


def test_window_rollover_resets_the_counter() -> None:
    now = [0.0]
    limiter = FixedWindowRateLimiter(window_seconds=60, clock=lambda: now[0])
    assert limiter.allow("requests", "one", 1) is True
    assert limiter.allow("requests", "one", 1) is False
    now[0] = 60.0
    assert limiter.allow("requests", "one", 1) is True


@pytest.mark.parametrize(
    ("bucket", "identity", "limit", "count"),
    (
        ("", "one", 1, 1),
        ("a", "", 1, 1),
        ("a", "one", 0, 1),
        ("a", "one", 1, 0),
        ("a", "one", True, 1),
        ("a", "one", 1, True),
    ),
)
def test_invalid_arguments_are_rejected(bucket: str, identity: str, limit: int, count: int) -> None:
    limiter = FixedWindowRateLimiter()
    with pytest.raises(ValueError):
        limiter.allow_many(bucket, identity, limit, count)

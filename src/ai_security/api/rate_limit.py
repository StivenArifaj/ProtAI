"""Per-process fixed-window rate limiting for the Phase 8 ingress (ADR-015).

The limiter is deliberately small and in-memory. It is *not* distributed: a
multi-worker deployment needs a shared store, which is documented as a limitation.
Identities are derived only from verified principals or verified host keys; request
bodies cannot choose a bucket. Nothing here executes a tool or changes policy — a
denial simply prevents the request from reaching the ingress pipeline.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_WINDOW_SECONDS = 60
DEFAULT_MAX_ENTRIES = 50_000
_PRUNE_EVERY = 1_024


@dataclass
class _Window:
    index: int
    count: int


class FixedWindowRateLimiter:
    """A deterministic fixed-window counter keyed by ``(bucket, identity)``."""

    def __init__(
        self,
        *,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(window_seconds, int) or window_seconds < 1:
            raise ValueError("window_seconds must be a positive integer")
        if not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        self._window_seconds = window_seconds
        self._max_entries = max_entries
        self._clock = clock if clock is not None else time.monotonic
        self._windows: dict[tuple[str, str], _Window] = {}
        self._calls = 0

    def allow(self, bucket: str, identity: str, limit: int) -> bool:
        """Consume one slot; return ``False`` when the bucket is exhausted."""
        return self.allow_many(bucket, identity, limit, 1)

    def allow_many(self, bucket: str, identity: str, limit: int, count: int) -> bool:
        """Atomically consume ``count`` slots; all-or-nothing per window.

        A multi-tool request reserves every planned slot before it executes anything, so
        a partially available bucket never permits an unbounded first step.
        """
        if not bucket or not identity:
            raise ValueError("bucket and identity must be non-empty")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("limit must be a positive integer")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise ValueError("count must be a positive integer")

        now = self._clock()
        index = int(now // self._window_seconds)
        key = (bucket, identity)
        window = self._windows.get(key)
        if window is None or window.index != index:
            if count > limit:
                return False
            self._windows[key] = _Window(index=index, count=count)
            self._calls += 1
            if self._calls % _PRUNE_EVERY == 0:
                self._prune(index)
            return True
        if window.count + count > limit:
            return False
        window.count += count
        return True

    def _prune(self, current_index: int) -> None:
        stale = [key for key, window in self._windows.items() if window.index < current_index]
        for key in stale:
            del self._windows[key]
        # A principal explosion is not expected (identities come from verified host
        # assertions), but the limiter must not become an unbounded memory sink. Drop
        # the oldest insertion-order windows rather than failing open for new callers.
        while len(self._windows) > self._max_entries:
            oldest = next(iter(self._windows))
            del self._windows[oldest]


__all__ = ["DEFAULT_MAX_ENTRIES", "DEFAULT_WINDOW_SECONDS", "FixedWindowRateLimiter"]

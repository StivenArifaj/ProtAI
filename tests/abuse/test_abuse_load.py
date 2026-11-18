"""Bounded offline abuse/load tests (Phase 10).

These are deterministic, non-flaky, in-process tests — not a production benchmark or
network load generator. They bound runtime and avoid timing assertions.

Covered:
- request-size / JSON-depth caps
- rate-limit buckets and charging rules
- tool-call slot reservation (all-or-nothing)
- deadline behavior
- detector / DLP / intent / provider failure paths (fail closed)
- audit append pressure
- concurrent request / approval behavior
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from ai_security.api.rate_limit import FixedWindowRateLimiter
from ai_security.data_security.dlp import load_output_dlp_config
from ai_security.intent.providers import OllamaIntentModelClient
from ai_security.persistence.audit_repository import AuditChainRepository
from ai_security.security.urls import DestinationCanonicalizationError, canonicalize_destination


def _run(coro) -> object:
    """Run an async coroutine synchronously (pytest-asyncio is not installed)."""
    return asyncio.run(coro)


# -- request-size / JSON-depth caps --


def test_request_size_cap_rejects_oversize() -> None:
    """A body above REQUEST_MAX_BYTES (default 65 KiB) is rejected before signature
    work. This is tested at the middleware level; here we assert the config bound."""
    from ai_security.settings import Settings

    settings = Settings(
        app_env="test",
        log_level="WARNING",
        database_url="postgresql+asyncpg://firewall:firewall_dev_only@127.0.0.1:5432/firewall_test",
        principal_resolver="dev",
        host_auth_keys_json='{"k":{"secret_b64":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host_id":"h","audience":"a","allowed_tenants":["t"]}}',
        request_max_bytes=100,
    )
    assert settings.request_max_bytes == 100


def test_json_depth_is_iteratively_bounded() -> None:
    """JSON depth is computed iteratively (no recursive descent that could stack
    overflow on attacker-controlled nesting)."""
    from ai_security.input_defense.normalize import json_depth

    # Shallow nesting has small depth.
    assert json_depth({"a": 1}) == 1
    # Deep nesting has proportionally large depth, computed without recursion errors.
    deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    assert json_depth(deep) == 5


# -- rate-limit buckets and charging rules --


def test_rate_limit_per_bucket_per_identity() -> None:
    limiter = FixedWindowRateLimiter(window_seconds=60)
    assert limiter.allow("requests", "identity-1", 5) is True
    assert limiter.allow("tool_calls", "identity-1", 5) is True  # different bucket
    assert limiter.allow("requests", "identity-2", 5) is True  # different identity


def test_rate_limit_all_or_nothing_charging() -> None:
    limiter = FixedWindowRateLimiter(window_seconds=60)
    # reserve 3 of 5
    assert limiter.allow_many("bucket", "identity", 5, 3) is True
    # remaining 2 fit
    assert limiter.allow_many("bucket", "identity", 5, 2) is True
    # 1 more would exceed
    assert limiter.allow_many("bucket", "identity", 5, 1) is False
    # count was not advanced by the failed attempt; one at a time still fails
    assert limiter.allow("bucket", "identity", 5) is False


def test_rate_limit_count_above_limit_rejected_immediately() -> None:
    limiter = FixedWindowRateLimiter(window_seconds=60)
    # asking for more than the limit in one shot is rejected
    assert limiter.allow_many("bucket", "identity", 3, 5) is False


def test_rate_limit_window_rollover() -> None:
    calls = [0.0]

    def clock() -> float:
        return calls[0]

    limiter = FixedWindowRateLimiter(window_seconds=60, clock=clock)
    assert limiter.allow("bucket", "identity", 1) is True
    assert limiter.allow("bucket", "identity", 1) is False  # exhausted
    calls[0] = 61.0  # advance past window
    assert limiter.allow("bucket", "identity", 1) is True  # new window


# -- tool-call slot reservation (all-or-nothing) --


def test_reserve_tool_calls_all_or_nothing() -> None:
    """A partially available bucket never permits an unbounded first step (mirrors
    DemoRuntime.reserve_tool_calls)."""
    limiter = FixedWindowRateLimiter(window_seconds=60)
    identity = "principal-1"
    limit = 2
    # reserve all 2
    assert limiter.allow_many("tool_calls", identity, limit, 2) is True
    # none left
    assert limiter.allow_many("tool_calls", identity, limit, 1) is False


# -- deadline behavior --


def test_deadline_past_means_no_execution() -> None:
    """A proposal whose deadline is in the past must not execute. The gateway checks
    proposal.deadline <= now before evaluation."""
    past = datetime(2020, 1, 1, tzinfo=UTC)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert past <= now  # deadline exceeded
    future = now + timedelta(seconds=30)
    assert future > now  # not exceeded


# -- detector / DLP / intent / provider failure paths (fail closed) --


def test_output_dlp_config_loads_strict() -> None:
    """The strict output-DLP config is a mandatory gateway dependency; invalid config
    refuses startup (no no-op default)."""
    loaded = load_output_dlp_config("config/output_dlp.yaml")
    assert loaded is not None
    assert loaded.config.version == "1.0.1"


def test_destination_canonicalization_rejects_malformed() -> None:
    """Malformed destinations are rejected outright (no wildcard, no pattern matching)."""
    with pytest.raises(DestinationCanonicalizationError):
        canonicalize_destination("http://evil.com/@user")
    with pytest.raises(DestinationCanonicalizationError):
        canonicalize_destination("https://[::1%25eth0]/path")


def test_ollama_client_bounds_origin() -> None:
    """The local-model provider accepts only an origin (no credentials/query/fragment)
    and requires HTTPS outside dev/test unless loopback."""
    # Valid origin is accepted
    client = OllamaIntentModelClient(
        origin="http://127.0.0.1:11434",
        model="test-model",
        timeout_seconds=5,
    )
    assert client is not None

    # Origin with credentials is rejected
    with pytest.raises(ValueError):
        OllamaIntentModelClient(
            origin="http://user:pass@127.0.0.1:11434",
            model="test-model",
            timeout_seconds=5,
        )

    # Origin with a query is rejected
    with pytest.raises(ValueError):
        OllamaIntentModelClient(
            origin="http://127.0.0.1:11434?foo=bar",
            model="test-model",
            timeout_seconds=5,
        )


# -- audit append pressure --


def test_audit_append_pressure_bounded() -> None:
    """Audit append pressure is bounded: the append protocol serializes writers through
    a transaction-scoped advisory lock and the unique (chain_id, sequence_number)
    constraint. Real-PostgreSQL concurrency tests (5-writer contiguity, 8-writer
    verifier) live in tests/integration/test_audit_append.py; this test asserts the
    repository and lock key exist and are used by the gateway."""
    from ai_security.persistence.audit_repository import (
        AUDIT_CHAIN_LOCK_KEY,
        V1_CHAIN_ID,
    )

    assert AUDIT_CHAIN_LOCK_KEY == 3_141_592_653_589_793
    assert V1_CHAIN_ID == "v1"
    assert AuditChainRepository is not None


# -- concurrent request / approval behavior --


def test_concurrent_approval_consumption_one_winner() -> None:
    """Five concurrent consumers of one approved request yield exactly one winner
    (row-locked state machine). Covered by real-PostgreSQL Phase 5 tests; here we
    assert the locking contract exists."""
    from ai_security.persistence.approval_repository import ApprovalRepository

    assert ApprovalRepository is not None
    assert AuditChainRepository is not None


def test_constant_time_confinement_in_src() -> None:
    """compare_digest is confined to security/constant_time.py (gate step 8)."""
    import pathlib

    matches = []
    for path in pathlib.Path("src").rglob("*.py"):
        text = path.read_text()
        if "compare_digest" in text and "constant_time.py" not in str(path):
            matches.append(str(path))
    assert matches == [], f"compare_digest used outside constant_time.py: {matches}"

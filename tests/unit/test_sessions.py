"""Session identifier and expiry math (blueprint section 7.4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ai_security.input_defense.sessions import (
    MAX_SIGNAL_COUNTER,
    SESSION_ID_BYTES,
    SESSION_MAX_AGE_SECONDS,
    SESSION_SIGNAL_TTL_SECONDS,
    SessionSecuritySnapshot,
    new_session_id,
    utc_now,
)


def snapshot(*, created_at: datetime, last_seen_at: datetime) -> SessionSecuritySnapshot:
    return SessionSecuritySnapshot(
        session_id="s",
        tenant_id="t",
        subject_id="u",
        created_at=created_at,
        last_seen_at=last_seen_at,
        override_attempts=0,
        privilege_escalation_signals=0,
        blocked_tool_proposals=0,
        threat_findings=0,
    )


def test_blueprint_defaults_match_the_required_windows() -> None:
    assert SESSION_SIGNAL_TTL_SECONDS == 86400
    assert SESSION_MAX_AGE_SECONDS == 604800
    assert MAX_SIGNAL_COUNTER == 1_000_000
    assert SESSION_ID_BYTES >= 16


def test_session_ids_are_opaque_url_safe_and_unique() -> None:
    identifiers = {new_session_id() for _ in range(64)}
    assert len(identifiers) == 64
    assert all(len(identifier) >= 43 for identifier in identifiers)
    assert all(identifier.replace("-", "").replace("_", "").isalnum() for identifier in identifiers)


def test_inactivity_beyond_ttl_expires() -> None:
    now = utc_now()
    state = snapshot(created_at=now, last_seen_at=now - timedelta(seconds=86401))
    assert state.is_expired(
        now=now, ttl_seconds=SESSION_SIGNAL_TTL_SECONDS, max_age_seconds=SESSION_MAX_AGE_SECONDS
    )


def test_absolute_max_age_expires_even_with_recent_activity() -> None:
    now = utc_now()
    state = snapshot(created_at=now - timedelta(seconds=604801), last_seen_at=now)
    assert state.is_expired(
        now=now, ttl_seconds=SESSION_SIGNAL_TTL_SECONDS, max_age_seconds=SESSION_MAX_AGE_SECONDS
    )


def test_active_recent_session_is_not_expired() -> None:
    now = datetime(2026, 10, 19, 12, tzinfo=UTC)
    state = snapshot(created_at=now - timedelta(hours=2), last_seen_at=now - timedelta(minutes=5))
    assert not state.is_expired(
        now=now, ttl_seconds=SESSION_SIGNAL_TTL_SECONDS, max_age_seconds=SESSION_MAX_AGE_SECONDS
    )

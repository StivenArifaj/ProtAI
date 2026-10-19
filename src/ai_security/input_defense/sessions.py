"""Session security metadata for multi-turn detection signals (blueprint section 7.4).

Session state is a *detection signal only*: it is never an authorization input, never
read by the policy engine, and never passed to the gateway. The internal session
identifier is generated with the platform CSPRNG; a client/host conversation reference
is never authoritative. Records store bounded counters and timestamps only — never raw
prompts or model context.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

SESSION_SIGNAL_TTL_SECONDS = 86400
SESSION_MAX_AGE_SECONDS = 604800
MAX_SIGNAL_COUNTER = 1_000_000
SESSION_ID_BYTES = 32


def new_session_id() -> str:
    """Opaque internal session id: 256 bits from the platform CSPRNG, URL-safe."""
    return secrets.token_urlsafe(SESSION_ID_BYTES)


@dataclass(frozen=True)
class SessionSecuritySnapshot:
    """Bounded session signals; counters are clamped at ``MAX_SIGNAL_COUNTER``."""

    session_id: str
    tenant_id: str
    subject_id: str
    created_at: datetime
    last_seen_at: datetime
    override_attempts: int
    privilege_escalation_signals: int
    blocked_tool_proposals: int
    threat_findings: int

    def is_expired(self, *, now: datetime, ttl_seconds: int, max_age_seconds: int) -> bool:
        """24 h inactivity TTL and 7 d absolute maximum lifetime (blueprint 7.4)."""
        return (now - self.last_seen_at).total_seconds() > ttl_seconds or (
            now - self.created_at
        ).total_seconds() > max_age_seconds


def utc_now() -> datetime:
    return datetime.now(UTC)

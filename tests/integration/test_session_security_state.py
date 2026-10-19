"""Session security state against real PostgreSQL (blueprint section 7.4).

Binding is re-checked on every access, expiry is enforced with lazy deletion, and
rotation creates a fresh session with no inherited signals. Only counters/timestamps
are stored.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from db_helpers import DatabaseHarness
from sqlalchemy import func, select

from ai_security.input_defense.sessions import MAX_SIGNAL_COUNTER, SessionSecuritySnapshot
from ai_security.persistence.models import SessionSecurityState
from ai_security.persistence.session_repository import SessionSecurityRepository

T0 = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
TTL = 86400
MAX_AGE = 604800


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


async def count_rows(database: DatabaseHarness, session_id: str) -> int:
    async with database.session_factory() as session:
        return int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(SessionSecurityState)
                    .where(SessionSecurityState.session_id == session_id)
                )
            ).scalar_one()
        )


def test_binding_is_checked_on_every_access(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(
                database.session_factory, ttl_seconds=TTL, max_age_seconds=MAX_AGE
            )
            tenant, subject = unique("tenant"), unique("user")
            created = await repository.create(tenant, subject, now=T0)

            assert await repository.read(created.session_id, tenant, subject, now=T0) == created
            assert await repository.read(created.session_id, tenant, unique("user"), now=T0) is None
            assert (
                await repository.read(created.session_id, unique("tenant"), subject, now=T0) is None
            )
            assert (
                await repository.record_signals(
                    created.session_id,
                    tenant,
                    unique("user"),
                    override_attempts=1,
                    now=T0,
                )
                is None
            )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_guessed_session_ids_cannot_create_or_read_state(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(
                database.session_factory, ttl_seconds=TTL, max_age_seconds=MAX_AGE
            )
            tenant, subject = unique("tenant"), unique("user")
            assert await repository.read(unique("guessed"), tenant, subject, now=T0) is None
            assert (
                await repository.record_signals(
                    unique("guessed"), tenant, subject, threat_findings=1, now=T0
                )
                is None
            )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_signal_counters_increment_and_clamp(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(
                database.session_factory, ttl_seconds=TTL, max_age_seconds=MAX_AGE
            )
            tenant, subject = unique("tenant"), unique("user")
            created = await repository.create(tenant, subject, now=T0)

            first = await repository.record_signals(
                created.session_id,
                tenant,
                subject,
                override_attempts=2,
                blocked_tool_proposals=1,
                now=T0 + timedelta(minutes=1),
            )
            assert isinstance(first, SessionSecuritySnapshot)
            assert first.override_attempts == 2
            assert first.blocked_tool_proposals == 1

            clamped = await repository.record_signals(
                created.session_id,
                tenant,
                subject,
                override_attempts=MAX_SIGNAL_COUNTER,
                now=T0 + timedelta(minutes=2),
            )
            assert clamped is not None
            assert clamped.override_attempts == MAX_SIGNAL_COUNTER
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_invalid_signal_delta_is_rejected(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(database.session_factory)
            tenant, subject = unique("tenant"), unique("user")
            created = await repository.create(tenant, subject, now=T0)
            with pytest.raises(ValueError):
                await repository.record_signals(
                    created.session_id, tenant, subject, threat_findings=-1, now=T0
                )
            with pytest.raises(ValueError):
                await repository.record_signals(
                    created.session_id,
                    tenant,
                    subject,
                    threat_findings=MAX_SIGNAL_COUNTER + 1,
                    now=T0,
                )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_rotation_creates_a_fresh_session_without_inherited_signals(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(
                database.session_factory, ttl_seconds=TTL, max_age_seconds=MAX_AGE
            )
            tenant, subject = unique("tenant"), unique("user")
            created = await repository.create(tenant, subject, now=T0)
            await repository.record_signals(
                created.session_id, tenant, subject, threat_findings=3, now=T0
            )

            rotated = await repository.rotate(created.session_id, tenant, subject, now=T0)
            assert rotated is not None
            assert rotated.session_id != created.session_id
            assert rotated.threat_findings == 0
            assert rotated.override_attempts == 0

            original = await repository.read(created.session_id, tenant, subject, now=T0)
            assert original is not None and original.threat_findings == 3
            assert (
                await repository.rotate(created.session_id, tenant, unique("user"), now=T0) is None
            )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_inactivity_ttl_expires_and_lazily_deletes(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(
                database.session_factory, ttl_seconds=TTL, max_age_seconds=MAX_AGE
            )
            tenant, subject = unique("tenant"), unique("user")
            created = await repository.create(tenant, subject, now=T0)

            assert (
                await repository.read(
                    created.session_id, tenant, subject, now=T0 + timedelta(seconds=TTL)
                )
                is not None
            )
            assert (
                await repository.read(
                    created.session_id,
                    tenant,
                    subject,
                    now=T0 + timedelta(seconds=TTL + 1),
                )
                is None
            )
            assert await count_rows(database, created.session_id) == 0
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_absolute_max_age_wins_over_recent_activity(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(
                database.session_factory, ttl_seconds=TTL, max_age_seconds=MAX_AGE
            )
            tenant, subject = unique("tenant"), unique("user")
            created = await repository.create(tenant, subject, now=T0)

            for day in range(1, 7):
                assert (
                    await repository.record_signals(
                        created.session_id,
                        tenant,
                        subject,
                        threat_findings=1,
                        now=T0 + timedelta(days=day),
                    )
                    is not None
                )

            near_limit = T0 + timedelta(seconds=MAX_AGE - 100)
            assert (
                await repository.record_signals(
                    created.session_id, tenant, subject, threat_findings=1, now=near_limit
                )
                is not None
            )
            beyond_limit = T0 + timedelta(seconds=MAX_AGE + 1)
            assert (
                await repository.read(created.session_id, tenant, subject, now=beyond_limit) is None
            )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_expired_session_is_not_extended_by_a_write(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(
                database.session_factory, ttl_seconds=TTL, max_age_seconds=MAX_AGE
            )
            tenant, subject = unique("tenant"), unique("user")
            created = await repository.create(tenant, subject, now=T0)

            late = T0 + timedelta(seconds=TTL + 1)
            assert (
                await repository.record_signals(
                    created.session_id, tenant, subject, threat_findings=1, now=late
                )
                is None
            )
            assert await count_rows(database, created.session_id) == 0
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_naive_timestamps_are_rejected(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SessionSecurityRepository(database.session_factory)
            with pytest.raises(ValueError):
                await repository.create(unique("tenant"), unique("user"), now=datetime(2026, 1, 1))
        finally:
            await database.dispose()

    asyncio.run(scenario())

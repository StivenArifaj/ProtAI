"""Replay-protection persistence tests (blueprint section 9.2).

Exercises the real PostgreSQL implementation: a fresh nonce registers, a duplicate
inside the window is reported as a replay, an expired nonce may be re-registered, and a
database failure raises ``NonceRegistrationError`` (the caller must reject the request).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from db_helpers import DatabaseHarness
from sqlalchemy import delete

from ai_security.persistence.models import HostRequestNonce
from ai_security.persistence.nonce_repository import (
    NonceRegistrationError,
    SqlAlchemyNonceRepository,
)

UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://firewall:irrelevant@127.0.0.1:59999/nope"


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def test_fresh_nonce_is_registered(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SqlAlchemyNonceRepository(database.session_factory)
            assert await repository.register(key_id=unique("k"), nonce=unique("n"), ttl_seconds=300)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_duplicate_nonce_within_window_is_a_replay(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SqlAlchemyNonceRepository(database.session_factory)
            key_id, nonce = unique("k"), unique("n")
            assert await repository.register(key_id=key_id, nonce=nonce, ttl_seconds=300) is True
            assert await repository.register(key_id=key_id, nonce=nonce, ttl_seconds=300) is False
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_same_nonce_on_different_keys_is_independent(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            repository = SqlAlchemyNonceRepository(database.session_factory)
            nonce = unique("n")
            assert await repository.register(key_id=unique("k"), nonce=nonce, ttl_seconds=300)
            assert await repository.register(key_id=unique("k"), nonce=nonce, ttl_seconds=300)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_expired_nonce_can_be_re_registered_once(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            key_id, nonce = unique("k"), unique("n")
            async with database.session_factory() as session:
                async with session.begin():
                    session.add(
                        HostRequestNonce(
                            key_id=key_id,
                            nonce=nonce,
                            expires_at=datetime.now(UTC) - timedelta(seconds=5),
                        )
                    )
            repository = SqlAlchemyNonceRepository(database.session_factory)
            # Expired row: the acceptance window has passed, re-registration is allowed.
            assert await repository.register(key_id=key_id, nonce=nonce, ttl_seconds=300) is True
            # The re-registered row is now active: a second attempt is a replay.
            assert await repository.register(key_id=key_id, nonce=nonce, ttl_seconds=300) is False
        finally:
            async with database.session_factory() as session:
                async with session.begin():
                    await session.execute(
                        delete(HostRequestNonce).where(HostRequestNonce.key_id == key_id)
                    )
            await database.dispose()

    asyncio.run(scenario())


def test_database_failure_raises_registration_error() -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(UNREACHABLE_DATABASE_URL, connect_args={"timeout": 0.5})
        try:
            repository = SqlAlchemyNonceRepository(database.session_factory)
            with pytest.raises(NonceRegistrationError):
                await repository.register(key_id="k", nonce="n", ttl_seconds=300)
        finally:
            await database.dispose()

    asyncio.run(scenario())

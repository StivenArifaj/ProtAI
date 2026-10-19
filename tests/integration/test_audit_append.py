"""Audit append scaffolding tests (blueprint section 16.2; ADR-002).

Proves the append protocol against real PostgreSQL: genesis handling, sequence
contiguity under concurrency, ``prev_hash`` linkage, exact stored canonical bytes, and
fail-closed behavior when the database is unavailable.

The full chain verifier and event taxonomy remain Phase 7; these tests assert the
scaffolding invariants the blueprint requires now.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from db_helpers import DatabaseHarness
from sqlalchemy import select

from ai_security.audit.hash_chain import (
    GENESIS_PREV_HASH,
    compute_event_hash,
    hash_to_hex,
)
from ai_security.persistence.audit_repository import (
    AuditAppendError,
    AuditChainRepository,
)
from ai_security.persistence.models import AuditEvent
from ai_security.security.canonical_json import canonical_json_bytes

UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://firewall:irrelevant@127.0.0.1:59999/nope"


def unique_chain() -> str:
    return f"test-chain-{uuid.uuid4().hex}"


async def stored_rows(database: DatabaseHarness, chain_id: str) -> list[AuditEvent]:
    async with database.session_factory() as session:
        result = await session.execute(
            select(AuditEvent)
            .where(AuditEvent.chain_id == chain_id)
            .order_by(AuditEvent.sequence_number)
        )
        return list(result.scalars().all())


def test_first_append_starts_from_genesis(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            repository = AuditChainRepository(database.session_factory, chain_id=chain_id)
            payload = {"a": 1, "event": "fixture"}
            appended = await repository.append(payload)
            assert appended.sequence_number == 1
            assert appended.previous_hash == hash_to_hex(GENESIS_PREV_HASH)

            (row,) = await stored_rows(database, chain_id)
            assert row.canonical_event_bytes == canonical_json_bytes(payload)
            expected = compute_event_hash(
                chain_id=chain_id,
                sequence_number=1,
                previous_hash=GENESIS_PREV_HASH,
                canonical_event_bytes=row.canonical_event_bytes,
            )
            assert row.event_hash == hash_to_hex(expected)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_appends_link_previous_hashes(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            repository = AuditChainRepository(database.session_factory, chain_id=chain_id)
            first = await repository.append({"event": "one"})
            second = await repository.append({"event": "two"})
            assert (first.sequence_number, second.sequence_number) == (1, 2)
            assert second.previous_hash == first.event_hash

            rows = await stored_rows(database, chain_id)
            previous = GENESIS_PREV_HASH
            for index, row in enumerate(rows, start=1):
                digest = compute_event_hash(
                    chain_id=chain_id,
                    sequence_number=index,
                    previous_hash=previous,
                    canonical_event_bytes=row.canonical_event_bytes,
                )
                assert row.sequence_number == index
                assert row.previous_hash == hash_to_hex(previous)
                assert row.event_hash == hash_to_hex(digest)
                previous = bytes.fromhex(row.event_hash)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_concurrent_appends_are_contiguous_and_linked(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            repository = AuditChainRepository(database.session_factory, chain_id=chain_id)
            appended = await asyncio.gather(
                *(repository.append({"index": index}) for index in range(5))
            )
            assert sorted(item.sequence_number for item in appended) == [1, 2, 3, 4, 5]

            rows = await stored_rows(database, chain_id)
            previous = GENESIS_PREV_HASH
            for index, row in enumerate(rows, start=1):
                assert row.sequence_number == index
                assert row.previous_hash == hash_to_hex(previous)
                digest = compute_event_hash(
                    chain_id=chain_id,
                    sequence_number=index,
                    previous_hash=previous,
                    canonical_event_bytes=row.canonical_event_bytes,
                )
                assert row.event_hash == hash_to_hex(digest)
                previous = bytes.fromhex(row.event_hash)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_stored_bytes_are_canonical_not_original_order(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            repository = AuditChainRepository(database.session_factory, chain_id=chain_id)
            # Unsorted keys: stored bytes must be the sorted-key canonical form.
            payload = {"z": 1, "a": "x"}
            await repository.append(payload)
            (row,) = await stored_rows(database, chain_id)
            assert row.canonical_event_bytes == b'{"a":"x","z":1}'
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_database_failure_raises_append_error() -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(UNREACHABLE_DATABASE_URL, connect_args={"timeout": 0.5})
        try:
            repository = AuditChainRepository(database.session_factory, chain_id="test-chain")
            with pytest.raises(AuditAppendError):
                await repository.append({"event": "fixture"})
        finally:
            await database.dispose()

    asyncio.run(scenario())

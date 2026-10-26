"""Audit hash-chain verifier tests against real PostgreSQL (section 16.2; ADR-002).

The verifier reads the exact bytes the append repository stored and checks sequence
contiguity, previous-hash linkage, the ADR-002 event hash, canonical JSON form, and the
derived metadata columns. These tests mutate stored rows directly with SQL to prove
each class of tampering is detected without trusting the ORM's serialization.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from db_helpers import DatabaseHarness
from sqlalchemy import delete, select, update

from ai_security.audit.hash_chain import compute_event_hash, hash_to_hex
from ai_security.audit.models import AuditEvent as AuditPayload
from ai_security.audit.models import AuditEventType
from ai_security.audit.verifier import (
    AuditVerificationFailureCode,
    AuditVerificationResult,
    verify_chain,
)
from ai_security.persistence.audit_repository import AuditChainRepository
from ai_security.persistence.models import AuditEvent as StoredAuditEvent
from ai_security.security.canonical_json import canonical_json_bytes

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
POLICY_HASH = "a" * 64


def unique_chain() -> str:
    return f"verifier-{uuid.uuid4().hex}"


async def append_events(database: DatabaseHarness, chain_id: str, count: int) -> None:
    repository = AuditChainRepository(database.session_factory, chain_id=chain_id)
    for index in range(count):
        await repository.append({"index": index})


async def rows(database: DatabaseHarness, chain_id: str) -> list[StoredAuditEvent]:
    async with database.session_factory() as session:
        result = await session.execute(
            select(StoredAuditEvent)
            .where(StoredAuditEvent.chain_id == chain_id)
            .order_by(StoredAuditEvent.sequence_number)
        )
        return list(result.scalars().all())


async def verify(
    database: DatabaseHarness, chain_id: str, *, max_failures: int = 100
) -> AuditVerificationResult:
    async with database.session_factory() as session:
        return await verify_chain(session, chain_id=chain_id, max_failures=max_failures)


def test_verifier_accepts_an_untampered_chain(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 4)
            result = await verify(database, chain_id)
            assert result.verified
            assert result.event_count == 4
            assert result.head_sequence == 4
            stored = await rows(database, chain_id)
            assert result.head_hash == stored[-1].event_hash
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_empty_chain_is_trivially_verified(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            result = await verify(database, unique_chain())
            assert result.verified
            assert result.event_count == 0
            assert result.head_sequence is None
            assert result.head_hash is None
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_payload_mutation_is_detected(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 3)
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(
                        StoredAuditEvent.chain_id == chain_id,
                        StoredAuditEvent.sequence_number == 2,
                    )
                    .values(canonical_event_bytes=canonical_json_bytes({"index": 999}))
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert [(failure.code, failure.sequence_number) for failure in result.failures] == [
                (AuditVerificationFailureCode.event_hash_mismatch, 2)
            ]
            assert result.failures[0].field == "event_hash"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_event_hash_mutation_breaks_its_own_row_and_the_next_link(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 2)
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(
                        StoredAuditEvent.chain_id == chain_id,
                        StoredAuditEvent.sequence_number == 1,
                    )
                    .values(event_hash="f" * 64)
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert {
                (failure.code, failure.sequence_number, failure.field)
                for failure in result.failures
            } == {
                (AuditVerificationFailureCode.event_hash_mismatch, 1, "event_hash"),
                (AuditVerificationFailureCode.previous_hash_mismatch, 2, "previous_hash"),
            }
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_reordered_events_break_the_previous_hash_chain(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 3)
            # Swap the stored sequence numbers of rows 2 and 3 using a temporary value
            # (the unique constraint forbids a direct two-row swap).
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(
                        StoredAuditEvent.chain_id == chain_id,
                        StoredAuditEvent.sequence_number == 2,
                    )
                    .values(sequence_number=-1)
                )
                await session.execute(
                    update(StoredAuditEvent)
                    .where(
                        StoredAuditEvent.chain_id == chain_id,
                        StoredAuditEvent.sequence_number == 3,
                    )
                    .values(sequence_number=2)
                )
                await session.execute(
                    update(StoredAuditEvent)
                    .where(
                        StoredAuditEvent.chain_id == chain_id,
                        StoredAuditEvent.sequence_number == -1,
                    )
                    .values(sequence_number=3)
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert {(failure.code, failure.sequence_number) for failure in result.failures} == {
                (AuditVerificationFailureCode.previous_hash_mismatch, 2),
                (AuditVerificationFailureCode.event_hash_mismatch, 2),
                (AuditVerificationFailureCode.previous_hash_mismatch, 3),
                (AuditVerificationFailureCode.event_hash_mismatch, 3),
            }
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_deleted_middle_event_is_detected(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 3)
            async with database.session_factory() as session:
                await session.execute(
                    delete(StoredAuditEvent).where(
                        StoredAuditEvent.chain_id == chain_id,
                        StoredAuditEvent.sequence_number == 2,
                    )
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert {(failure.code, failure.sequence_number) for failure in result.failures} == {
                (AuditVerificationFailureCode.sequence_discontinuity, 3),
                (AuditVerificationFailureCode.previous_hash_mismatch, 3),
            }
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_deleting_the_newest_event_is_undetectable_without_an_external_anchor(
    migrated_database: str,
) -> None:
    """Documents the honest limit of a plain local chain (ADR-014).

    A verifier that only reads the stored chain cannot distinguish "the last event was
    truncated" from "the chain legitimately ended earlier". Detecting that requires an
    externally anchored head hash/sequence checkpoint, which this phase does not
    deploy.
    """

    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 3)
            async with database.session_factory() as session:
                await session.execute(
                    delete(StoredAuditEvent).where(
                        StoredAuditEvent.chain_id == chain_id,
                        StoredAuditEvent.sequence_number == 3,
                    )
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert result.verified
            assert result.event_count == 2
            assert result.head_sequence == 2
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_non_canonical_payload_is_detected_even_with_a_valid_hash(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 1)
            stored = (await rows(database, chain_id))[0]
            non_canonical = b'{"index": 0}'
            digest = compute_event_hash(
                chain_id=chain_id,
                sequence_number=1,
                previous_hash=bytes.fromhex(stored.previous_hash),
                canonical_event_bytes=non_canonical,
            )
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(StoredAuditEvent.id == stored.id)
                    .values(
                        canonical_event_bytes=non_canonical,
                        event_hash=hash_to_hex(digest),
                    )
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert [(failure.code, failure.sequence_number) for failure in result.failures] == [
                (AuditVerificationFailureCode.non_canonical_payload, 1)
            ]
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_invalid_json_payload_is_detected_even_with_a_valid_hash(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 1)
            stored = (await rows(database, chain_id))[0]
            invalid = b"{not-json"
            digest = compute_event_hash(
                chain_id=chain_id,
                sequence_number=1,
                previous_hash=bytes.fromhex(stored.previous_hash),
                canonical_event_bytes=invalid,
            )
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(StoredAuditEvent.id == stored.id)
                    .values(canonical_event_bytes=invalid, event_hash=hash_to_hex(digest))
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert [(failure.code, failure.sequence_number) for failure in result.failures] == [
                (AuditVerificationFailureCode.invalid_payload, 1)
            ]
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_malformed_stored_hash_is_detected(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 1)
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(StoredAuditEvent.chain_id == chain_id)
                    .values(previous_hash="not-a-hash")
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert [
                (failure.code, failure.sequence_number, failure.field)
                for failure in result.failures
            ] == [(AuditVerificationFailureCode.malformed_hash, 1, "previous_hash")]
        finally:
            await database.dispose()

    asyncio.run(scenario())


async def append_request_event(database: DatabaseHarness, chain_id: str) -> AuditPayload:
    event = AuditPayload(
        event_id=uuid.uuid4().hex,
        event_type=AuditEventType.request_received,
        occurred_at=NOW,
        component_version="0.1.0",
        request_id="req-verifier",
        trace_id="trace-verifier",
        principal_subject_id="dev-user",
        call_id="call-1",
        policy_version="dev-1",
        policy_hash=POLICY_HASH,
    )
    repository = AuditChainRepository(database.session_factory, chain_id=chain_id)
    await repository.append(event.to_payload())
    return event


def test_append_projects_queryable_metadata_without_changing_the_hash(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            event = await append_request_event(database, chain_id)
            (stored,) = await rows(database, chain_id)
            assert stored.event_type == "REQUEST_RECEIVED"
            assert stored.request_id == "req-verifier"
            assert stored.trace_id == "trace-verifier"
            assert stored.call_id == "call-1"
            assert stored.component == "firewall.gateway"
            assert stored.occurred_at is not None
            assert stored.occurred_at.astimezone(UTC) == NOW
            assert stored.canonical_event_bytes == canonical_json_bytes(event.to_payload())

            result = await verify(database, chain_id)
            assert result.verified
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_metadata_column_tampering_is_detected(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_request_event(database, chain_id)
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(StoredAuditEvent.chain_id == chain_id)
                    .values(request_id="tampered-request")
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert [
                (failure.code, failure.sequence_number, failure.field)
                for failure in result.failures
            ] == [(AuditVerificationFailureCode.metadata_mismatch, 1, "request_id")]
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_occurred_at_metadata_tampering_is_detected(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_request_event(database, chain_id)
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(StoredAuditEvent.chain_id == chain_id)
                    .values(occurred_at=NOW + timedelta(seconds=1))
                )
                await session.commit()

            result = await verify(database, chain_id)
            assert not result.verified
            assert [
                (failure.code, failure.sequence_number, failure.field)
                for failure in result.failures
            ] == [(AuditVerificationFailureCode.metadata_mismatch, 1, "occurred_at")]
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_concurrent_writers_produce_a_verifiable_chain(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            repository = AuditChainRepository(database.session_factory, chain_id=chain_id)
            await asyncio.gather(*(repository.append({"index": index}) for index in range(8)))
            result = await verify(database, chain_id)
            assert result.verified
            assert result.event_count == 8
            assert result.head_sequence == 8
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_failure_report_is_bounded_and_flags_truncation(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            await append_events(database, chain_id, 3)
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(StoredAuditEvent.chain_id == chain_id)
                    .values(canonical_event_bytes=canonical_json_bytes({"index": 999}))
                )
                await session.commit()

            result = await verify(database, chain_id, max_failures=2)
            assert not result.verified
            assert len(result.failures) == 2
            assert result.failures_truncated is True
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_verification_is_scoped_to_one_chain(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            good_chain = unique_chain()
            bad_chain = unique_chain()
            await append_events(database, good_chain, 2)
            await append_events(database, bad_chain, 2)
            async with database.session_factory() as session:
                await session.execute(
                    update(StoredAuditEvent)
                    .where(StoredAuditEvent.chain_id == bad_chain)
                    .values(event_hash="0" * 64)
                )
                await session.commit()

            assert (await verify(database, good_chain)).verified
            assert not (await verify(database, bad_chain)).verified
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_verifier_rejects_invalid_arguments(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            async with database.session_factory() as session:
                try:
                    await verify_chain(session, chain_id="")
                except ValueError as exc:
                    assert "chain_id" in str(exc)
                else:  # pragma: no cover - the verifier must reject an empty chain id
                    raise AssertionError("empty chain_id was accepted")
                try:
                    await verify_chain(session, chain_id="v1", max_failures=0)
                except ValueError as exc:
                    assert "max_failures" in str(exc)
                else:  # pragma: no cover - the verifier must reject a zero failure cap
                    raise AssertionError("max_failures=0 was accepted")
        finally:
            await database.dispose()

    asyncio.run(scenario())

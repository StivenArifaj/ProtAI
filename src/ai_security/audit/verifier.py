"""Audit hash-chain verifier (blueprint section 16.2; ADR-002, ADR-014).

The verifier is deliberately independent of the append path's payload model. It reads
the rows stored by the single append repository and:

1. checks ``sequence_number`` starts at 1 and is contiguous;
2. checks each ``previous_hash`` equals the preceding event's stored ``event_hash``
   (the first event must use the 32-byte all-zero genesis hash);
3. recomputes the ADR-002 hash from the **exact stored** ``canonical_event_bytes`` and
   compares it with the stored ``event_hash``;
4. checks the stored bytes are the canonical JSON form of their parsed payload;
5. checks non-null queryable metadata columns agree with the canonical payload.

The hash formula and canonical-bytes contract live in their single implementations
(``audit/hash_chain.py`` and ``security/canonical_json.py``); this module must never
reimplement either.

Limitations are stated in ``docs/AUDIT_RETENTION_AND_DATA_HANDLING.md``: a plain local
chain is tamper-evident, not tamper-proof, and truncation of the newest events cannot
be detected without an externally anchored checkpoint. The verifier loads one chain in
a single statement (a consistent point-in-time snapshot) and is intended for the v1
single-chain deployment; it does not repair or rewrite rows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ai_security.audit.hash_chain import (
    GENESIS_PREV_HASH,
    HashChainError,
    compute_event_hash,
    hex_to_hash,
)
from ai_security.persistence.models import AuditEvent as StoredAuditEvent
from ai_security.security.canonical_json import CanonicalJSONError, canonical_json_bytes

#: Bound on retained failures so a wholly unrelated/corrupt table cannot exhaust memory.
DEFAULT_MAX_FAILURES = 100

_METADATA_STRING_FIELDS = ("event_type", "request_id", "trace_id", "call_id", "component")


class AuditVerificationFailureCode(StrEnum):
    """Stable, content-free failure reasons."""

    sequence_discontinuity = "SEQUENCE_DISCONTINUITY"
    malformed_hash = "MALFORMED_HASH"
    previous_hash_mismatch = "PREVIOUS_HASH_MISMATCH"
    event_hash_mismatch = "EVENT_HASH_MISMATCH"
    invalid_payload = "INVALID_PAYLOAD"
    non_canonical_payload = "NON_CANONICAL_PAYLOAD"
    metadata_mismatch = "METADATA_MISMATCH"


@dataclass(frozen=True)
class AuditVerificationFailure:
    """One verifier finding. Never contains raw event content."""

    code: AuditVerificationFailureCode
    sequence_number: int
    field: str | None = None


@dataclass(frozen=True)
class AuditVerificationResult:
    """Point-in-time verification result for one chain."""

    chain_id: str
    event_count: int
    head_sequence: int | None
    head_hash: str | None
    failures: tuple[AuditVerificationFailure, ...]
    failures_truncated: bool = False

    @property
    def verified(self) -> bool:
        """True only when every checked invariant held."""
        return not self.failures


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant {value!r} is not canonical")


class _InvalidTimestamp:
    """Sentinel distinguishing a malformed timestamp from an absent one."""


_INVALID_TIMESTAMP = _InvalidTimestamp()


def _parse_canonical_payload(raw: bytes) -> dict[str, Any] | None:
    """Return the payload if ``raw`` is its canonical form, else ``None``."""
    try:
        text = raw.decode("utf-8")
        parsed = json.loads(text, parse_constant=_reject_json_constant)
        if not isinstance(parsed, dict):
            return None
        if canonical_json_bytes(parsed) != raw:
            return None
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, CanonicalJSONError):
        return None
    return parsed


def _payload_timestamp(value: object) -> datetime | None | _InvalidTimestamp:
    if value is None:
        return None
    if not isinstance(value, str):
        return _INVALID_TIMESTAMP
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return _INVALID_TIMESTAMP
    if parsed.utcoffset() is None:
        return _INVALID_TIMESTAMP
    return parsed.astimezone(UTC)


def _metadata_mismatch(row: StoredAuditEvent, payload: dict[str, Any]) -> str | None:
    for field in _METADATA_STRING_FIELDS:
        expected = payload.get(field)
        actual = getattr(row, field)
        if expected is None:
            if actual is not None:
                return field
        elif not isinstance(expected, str) or expected != actual:
            return field
    expected_time = _payload_timestamp(payload.get("occurred_at"))
    if isinstance(expected_time, _InvalidTimestamp):
        return "occurred_at"
    if expected_time is None:
        return None if row.occurred_at is None else "occurred_at"
    if row.occurred_at is None:
        return "occurred_at"
    if row.occurred_at.utcoffset() is None:
        return "occurred_at"
    if row.occurred_at.astimezone(UTC) != expected_time:
        return "occurred_at"
    return None


def _decode_stored_hash(value: str) -> bytes | None:
    try:
        return hex_to_hash(value)
    except HashChainError:
        return None


async def verify_chain(
    session: AsyncSession,
    *,
    chain_id: str,
    max_failures: int = DEFAULT_MAX_FAILURES,
) -> AuditVerificationResult:
    """Verify one chain from its stored bytes and hash fields.

    The query is one statement, so the result describes a consistent snapshot even if a
    concurrent writer appends immediately after it starts. A verifier run that returns
    ``verified`` is a statement about the rows observed, not a guarantee that no future
    or concurrent append will be rejected later.
    """
    if not chain_id:
        raise ValueError("chain_id must be non-empty")
    if max_failures < 1:
        raise ValueError("max_failures must be at least 1")

    rows = list(
        (
            await session.execute(
                select(StoredAuditEvent)
                .where(StoredAuditEvent.chain_id == chain_id)
                .order_by(StoredAuditEvent.sequence_number)
            )
        )
        .scalars()
        .all()
    )

    failures: list[AuditVerificationFailure] = []
    failures_truncated = False

    def fail(
        code: AuditVerificationFailureCode, sequence_number: int, field: str | None = None
    ) -> None:
        nonlocal failures_truncated
        if len(failures) < max_failures:
            failures.append(AuditVerificationFailure(code, sequence_number, field))
        else:
            failures_truncated = True

    expected_sequence = 1
    previous_hash_bytes = GENESIS_PREV_HASH
    last_sequence: int | None = None
    last_event_hash: str | None = None

    for row in rows:
        sequence = row.sequence_number
        last_sequence = sequence
        last_event_hash = row.event_hash

        if sequence != expected_sequence:
            fail(AuditVerificationFailureCode.sequence_discontinuity, sequence)
        expected_sequence = sequence + 1

        stored_previous = _decode_stored_hash(row.previous_hash)
        if stored_previous is None:
            fail(AuditVerificationFailureCode.malformed_hash, sequence, "previous_hash")
        elif stored_previous != previous_hash_bytes:
            fail(AuditVerificationFailureCode.previous_hash_mismatch, sequence, "previous_hash")

        # The event hash is computed over the hash the row claims (or the genesis hash if
        # the stored previous hash is malformed). Linkage to the real preceding row is a
        # separate check, so one broken link does not mask an independently valid hash.
        hash_previous = stored_previous if stored_previous is not None else previous_hash_bytes
        recomputed = compute_event_hash(
            chain_id=chain_id,
            sequence_number=sequence,
            previous_hash=hash_previous,
            canonical_event_bytes=row.canonical_event_bytes,
        )
        stored_event = _decode_stored_hash(row.event_hash)
        if stored_event is None:
            fail(AuditVerificationFailureCode.malformed_hash, sequence, "event_hash")
        elif stored_event != recomputed:
            fail(AuditVerificationFailureCode.event_hash_mismatch, sequence, "event_hash")

        payload = _parse_canonical_payload(row.canonical_event_bytes)
        if payload is None:
            # Distinguish structurally invalid JSON from valid JSON that is not in
            # canonical form; neither exposes content in the failure record.
            try:
                decoded = json.loads(
                    row.canonical_event_bytes.decode("utf-8"),
                    parse_constant=_reject_json_constant,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                fail(AuditVerificationFailureCode.invalid_payload, sequence)
            else:
                if not isinstance(decoded, dict):
                    fail(AuditVerificationFailureCode.invalid_payload, sequence)
                else:
                    fail(AuditVerificationFailureCode.non_canonical_payload, sequence)
        else:
            field = _metadata_mismatch(row, payload)
            if field is not None:
                fail(AuditVerificationFailureCode.metadata_mismatch, sequence, field)

        # Use the stored event hash as the expected prior hash for the next row. A
        # missing/malformed hash has already been reported; the recomputed value keeps
        # subsequent checks meaningful.
        previous_hash_bytes = stored_event if stored_event is not None else recomputed

    return AuditVerificationResult(
        chain_id=chain_id,
        event_count=len(rows),
        head_sequence=last_sequence,
        head_hash=last_event_hash,
        failures=tuple(failures),
        failures_truncated=failures_truncated,
    )


__all__ = [
    "DEFAULT_MAX_FAILURES",
    "AuditVerificationFailure",
    "AuditVerificationFailureCode",
    "AuditVerificationResult",
    "verify_chain",
]

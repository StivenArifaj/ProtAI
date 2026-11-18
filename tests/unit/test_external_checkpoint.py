"""Tests for the external audit checkpoint (post-v1 additive foundation).

Verifies content-free checkpoints, seal integrity, tamper detection, and sink writing.
No raw audit content is ever included in a checkpoint.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from ai_security.soc.external_checkpoint import (
    Checkpoint,
    ExternalAuditCheckpointer,
    content_free_checkpoint_id,
)

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
SEAL_KEY = b"0" * 32


def _run(coro) -> object:
    return asyncio.run(coro)


class MemorySink:
    def __init__(self) -> None:
        self.writes: list[tuple[bytes, int]] = []

    async def write(self, payload: bytes, *, sequence: int) -> None:
        self.writes.append((payload, sequence))

    async def read_latest(self) -> bytes | None:
        return self.writes[-1][0] if self.writes else None


def test_checkpoint_is_content_free() -> None:
    """A checkpoint contains only hashes/sequence/seal — never raw event text."""
    sink = MemorySink()
    checkpointer = ExternalAuditCheckpointer(seal_key=SEAL_KEY, sink=sink)
    cp = checkpointer.build(
        sequence_number=1,
        head_hash="a" * 64,
        previous_seal=None,
        occurred_at=FIXED_NOW,
    )

    payload = {
        "sequence_number": cp.sequence_number,
        "head_hash": cp.head_hash,
        "previous_seal": cp.previous_seal,
        "seal": cp.seal,
    }
    serialized = json.dumps(payload)
    for forbidden in ("text", "user", "password", "secret", "arguments", "body"):
        assert forbidden not in serialized.lower()


def test_seal_verifies_for_valid_checkpoint() -> None:
    sink = MemorySink()
    checkpointer = ExternalAuditCheckpointer(seal_key=SEAL_KEY, sink=sink)
    cp = checkpointer.build(
        sequence_number=1,
        head_hash="a" * 64,
        previous_seal=None,
        occurred_at=FIXED_NOW,
    )

    assert _run(checkpointer.verify_seal(cp)) is True


def test_tampered_checkpoint_fails_verification() -> None:
    sink = MemorySink()
    checkpointer = ExternalAuditCheckpointer(seal_key=SEAL_KEY, sink=sink)
    cp = checkpointer.build(
        sequence_number=1,
        head_hash="a" * 64,
        previous_seal=None,
        occurred_at=FIXED_NOW,
    )
    tampered = Checkpoint(
        sequence_number=1,
        head_hash="b" * 64,  # tampered head hash
        previous_seal=None,
        seal=cp.seal,
        occurred_at=FIXED_NOW,
    )
    assert _run(checkpointer.verify_seal(tampered)) is False


def test_checkpoint_chain_references_previous_seal() -> None:
    sink = MemorySink()
    checkpointer = ExternalAuditCheckpointer(seal_key=SEAL_KEY, sink=sink)
    cp1 = checkpointer.build(
        sequence_number=1, head_hash="a" * 64, previous_seal=None, occurred_at=FIXED_NOW
    )
    cp2 = checkpointer.build(
        sequence_number=2,
        head_hash="b" * 64,
        previous_seal=cp1.seal,
        occurred_at=FIXED_NOW,
    )

    assert cp2.previous_seal == cp1.seal
    assert _run(checkpointer.verify_seal(cp2)) is True


def test_write_checkpoint_to_sink() -> None:
    sink = MemorySink()
    checkpointer = ExternalAuditCheckpointer(seal_key=SEAL_KEY, sink=sink)
    cp = checkpointer.build(
        sequence_number=1, head_hash="a" * 64, previous_seal=None, occurred_at=FIXED_NOW
    )

    _run(checkpointer.write_checkpoint(cp))
    assert len(sink.writes) == 1
    assert sink.writes[0][1] == 1
    parsed = json.loads(sink.writes[0][0])
    assert parsed["head_hash"] == "a" * 64


def test_short_seal_key_rejected() -> None:
    try:
        ExternalAuditCheckpointer(seal_key=b"short", sink=MemorySink())
        raise AssertionError("expected ValueError for short seal key")
    except ValueError:
        pass


def test_content_free_checkpoint_id_is_deterministic() -> None:
    id1 = content_free_checkpoint_id("a" * 64)
    id2 = content_free_checkpoint_id("a" * 64)
    assert id1 == id2
    assert content_free_checkpoint_id("a" * 64) != content_free_checkpoint_id("b" * 64)

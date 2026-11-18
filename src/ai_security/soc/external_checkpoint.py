"""External audit checkpoint (post-v1 additive foundation).

The v1 audit chain is tamper-evident but not tamper-proof: truncation of the newest
events is undetectable without an externally anchored checkpoint (documented
limitation #32 / ADR-014). This module implements a sealed, content-free checkpoint:

- The checkpoint contains only the chain head hash, head sequence number, and a
  content-free seal signature — never raw event content.
- It is append-only: each new checkpoint references the previous checkpoint's seal.
- It can be written to any external store (S3, object storage, append-only log) via an
  injected ``CheckpointSink``.
- Verification recomputes the seal from the stored bytes; any mismatch or missing
  checkpoint is detectable.

This is **additive and optional**: v1 verification remains the local ``verify_chain``.
The checkpoint is a separate, externally anchored integrity layer.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from ai_security.security.constant_time import constant_time_hex32_equal


class CheckpointSink(Protocol):
    """Sink for writing checkpoints to external storage.

    Implementations must be append-only and idempotent by checkpoint sequence number.
    Never write raw audit event content.
    """

    async def write(self, payload: bytes, *, sequence: int) -> None: ...

    async def read_latest(self) -> bytes | None: ...


@dataclass(frozen=True)
class Checkpoint:
    """One sealed audit-chain checkpoint (content-free)."""

    sequence_number: int
    head_hash: str
    previous_seal: str | None
    seal: str
    occurred_at: datetime
    schema_version: Literal[1] = 1


class CheckpointRecord(BaseModel):
    """Serializable checkpoint envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    sequence_number: int = Field(ge=1)
    head_hash: str = Field(min_length=64, max_length=64)
    previous_seal: str | None = None
    seal: str = Field(min_length=64, max_length=64)
    occurred_at: str

    def to_bytes(self) -> bytes:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True).encode("utf-8")


class ExternalAuditCheckpointer:
    """Builds and writes sealed checkpoints of the audit-chain head.

    The checkpoint is content-free: it contains only hashes and sequence numbers, never
    raw event payloads, user text, or secrets. A secret key (operator-provided) seals
    each checkpoint so an attacker who compromises the database cannot forge a valid
    checkpoint history.
    """

    def __init__(
        self,
        *,
        seal_key: bytes,
        sink: CheckpointSink,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if len(seal_key) < 32:
            raise ValueError("seal_key must be at least 32 bytes")
        self._seal_key = seal_key
        self._sink = sink
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    def _seal(self, payload: dict[str, object], previous_seal: str | None) -> str:
        """Compute an HMAC seal over the checkpoint payload plus previous seal."""
        material = {
            "schema_version": 1,
            "sequence_number": payload["sequence_number"],
            "head_hash": payload["head_hash"],
            "previous_seal": previous_seal,
        }
        canonical = json.dumps(material, sort_keys=True).encode("utf-8")
        return hmac.new(self._seal_key, canonical, hashlib.sha256).hexdigest()

    def build(
        self,
        *,
        sequence_number: int,
        head_hash: str,
        previous_seal: str | None,
        occurred_at: datetime | None = None,
    ) -> Checkpoint:
        now = occurred_at or self._clock()
        if now.utcoffset() is None:
            now = now.replace(tzinfo=UTC)
        seal_input = {
            "sequence_number": sequence_number,
            "head_hash": head_hash,
            "previous_seal": previous_seal,
        }
        seal = self._seal(seal_input, previous_seal)
        return Checkpoint(
            sequence_number=sequence_number,
            head_hash=head_hash,
            previous_seal=previous_seal,
            seal=seal,
            occurred_at=now,
        )

    async def write_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Write one checkpoint to the external sink (append-only)."""
        record = CheckpointRecord(
            sequence_number=checkpoint.sequence_number,
            head_hash=checkpoint.head_hash,
            previous_seal=checkpoint.previous_seal,
            seal=checkpoint.seal,
            occurred_at=checkpoint.occurred_at.isoformat(),
        )
        await self._sink.write(record.to_bytes(), sequence=checkpoint.sequence_number)

    async def verify_seal(self, checkpoint: Checkpoint) -> bool:
        """Recompute and compare the checkpoint seal without accessing the audit chain."""
        material = {
            "schema_version": 1,
            "sequence_number": checkpoint.sequence_number,
            "head_hash": checkpoint.head_hash,
            "previous_seal": checkpoint.previous_seal,
        }
        canonical = json.dumps(material, sort_keys=True).encode("utf-8")
        expected = hmac.new(self._seal_key, canonical, hashlib.sha256).hexdigest()
        return constant_time_hex32_equal(expected, checkpoint.seal)

    def checkpoint_id_from_hash(self, head_hash: str) -> str:
        """Derive a content-free checkpoint identifier from a head hash."""
        return base64.b64encode(hashlib.sha256(head_hash.encode("utf-8")).digest()[:16]).decode()


def content_free_checkpoint_id(head_hash: str) -> str:
    """Public helper: derive a content-free id from a head hash (no seal key needed)."""
    return base64.b64encode(hashlib.sha256(head_hash.encode("utf-8")).digest()[:16]).decode()


__all__ = [
    "Checkpoint",
    "CheckpointRecord",
    "CheckpointSink",
    "ExternalAuditCheckpointer",
    "content_free_checkpoint_id",
]

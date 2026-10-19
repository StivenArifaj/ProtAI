"""Audit hash-chain hash formula (blueprint v1.2 section 16.2, ADR-002).

The hash input is a fixed byte formula; it is implemented exactly once, here, and is
shared by the append scaffolding (Phase 0b) and the future verifier (Phase 7):

.. code-block:: text

    hash_input = (
        b"AIAS-AUDIT-V1\\x00"
        + len(chain_id_bytes).to_bytes(4, "big")
        + chain_id_bytes
        + sequence_number.to_bytes(8, "big")
        + previous_hash_bytes          # exactly 32 raw bytes, not 64 ASCII hex bytes
        + len(canonical_event_bytes).to_bytes(8, "big")
        + canonical_event_bytes
    )
    event_hash = sha256(hash_input).digest()

Hashes are persisted as lowercase 64-character hex strings for readability and decoded
to raw 32-byte form before hashing. The first event in a chain uses a 32-byte all-zero
genesis previous-hash.
"""

from __future__ import annotations

import hashlib
import re

HASH_PREFIX = b"AIAS-AUDIT-V1\x00"
GENESIS_PREV_HASH = b"\x00" * 32
HASH_BYTES = 32
HEX32 = re.compile(r"[0-9a-f]{64}")


class HashChainError(ValueError):
    """Raised for malformed hash-chain inputs (fail closed)."""


def compute_event_hash(
    *,
    chain_id: str,
    sequence_number: int,
    previous_hash: bytes,
    canonical_event_bytes: bytes,
) -> bytes:
    """Compute the raw 32-byte event hash for one audit event."""
    if not chain_id:
        raise HashChainError("chain_id must not be empty")
    if sequence_number < 1:
        raise HashChainError("sequence_number must start at 1")
    if len(previous_hash) != HASH_BYTES:
        raise HashChainError("previous_hash must be exactly 32 raw bytes")
    chain_id_bytes = chain_id.encode("utf-8")
    hash_input = (
        HASH_PREFIX
        + len(chain_id_bytes).to_bytes(4, "big")
        + chain_id_bytes
        + sequence_number.to_bytes(8, "big")
        + previous_hash
        + len(canonical_event_bytes).to_bytes(8, "big")
        + canonical_event_bytes
    )
    return hashlib.sha256(hash_input).digest()


def hash_to_hex(digest: bytes) -> str:
    """Persist hashes as lowercase 64-character hex strings."""
    if len(digest) != HASH_BYTES:
        raise HashChainError("event hash must be exactly 32 raw bytes")
    return digest.hex()


def hex_to_hash(hex_digest: str) -> bytes:
    """Decode a stored lowercase hex hash back to raw bytes before hashing."""
    if HEX32.fullmatch(hex_digest) is None:
        raise HashChainError("stored hash must be lowercase 64-character hex")
    return bytes.fromhex(hex_digest)

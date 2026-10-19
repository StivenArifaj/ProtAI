"""Audit hash-chain formula tests with frozen vectors (blueprint section 16.2).

The expected hashes below were computed independently from the blueprint formula
(counter-checked outside this codebase) and are frozen: changing the serialization or
hash input requires an ADR update and vector refresh.
"""

from __future__ import annotations

import pytest

from ai_security.audit.hash_chain import (
    GENESIS_PREV_HASH,
    HashChainError,
    compute_event_hash,
    hash_to_hex,
    hex_to_hash,
)

CHAIN_ID = "v1"
PAYLOAD = b'{"a":1,"event":"fixture"}'
FROZEN_SEQ1 = "5167253118cf2068a18670e60b2e83eaa22436ff1d17b1830bb3561a530b59d0"
FROZEN_SEQ2 = "8b5df3a3a29c205bfbc5dc4c64cd0fac066c03ae2388f1f3fd95c5ddeaedc03b"


def test_first_event_hash_matches_frozen_vector() -> None:
    digest = compute_event_hash(
        chain_id=CHAIN_ID,
        sequence_number=1,
        previous_hash=GENESIS_PREV_HASH,
        canonical_event_bytes=PAYLOAD,
    )
    assert hash_to_hex(digest) == FROZEN_SEQ1


def test_second_event_links_previous_hash_and_matches_frozen_vector() -> None:
    first = compute_event_hash(
        chain_id=CHAIN_ID,
        sequence_number=1,
        previous_hash=GENESIS_PREV_HASH,
        canonical_event_bytes=PAYLOAD,
    )
    second = compute_event_hash(
        chain_id=CHAIN_ID,
        sequence_number=2,
        previous_hash=first,
        canonical_event_bytes=PAYLOAD,
    )
    assert hash_to_hex(second) == FROZEN_SEQ2


def test_sequence_number_changes_the_hash() -> None:
    first = compute_event_hash(
        chain_id=CHAIN_ID,
        sequence_number=1,
        previous_hash=GENESIS_PREV_HASH,
        canonical_event_bytes=PAYLOAD,
    )
    other = compute_event_hash(
        chain_id=CHAIN_ID,
        sequence_number=2,
        previous_hash=GENESIS_PREV_HASH,
        canonical_event_bytes=PAYLOAD,
    )
    assert first != other


def test_chain_id_changes_the_hash() -> None:
    a = compute_event_hash(
        chain_id="v1",
        sequence_number=1,
        previous_hash=GENESIS_PREV_HASH,
        canonical_event_bytes=PAYLOAD,
    )
    b = compute_event_hash(
        chain_id="v2",
        sequence_number=1,
        previous_hash=GENESIS_PREV_HASH,
        canonical_event_bytes=PAYLOAD,
    )
    assert a != b


def test_payload_change_detected() -> None:
    a = compute_event_hash(
        chain_id=CHAIN_ID,
        sequence_number=1,
        previous_hash=GENESIS_PREV_HASH,
        canonical_event_bytes=b'{"a":1}',
    )
    b = compute_event_hash(
        chain_id=CHAIN_ID,
        sequence_number=1,
        previous_hash=GENESIS_PREV_HASH,
        canonical_event_bytes=b'{"a":2}',
    )
    assert a != b


@pytest.mark.parametrize(
    ("chain_id", "sequence_number", "previous_hash", "match"),
    [
        ("", 1, GENESIS_PREV_HASH, "chain_id"),
        (CHAIN_ID, 0, GENESIS_PREV_HASH, "sequence_number"),
        (CHAIN_ID, -1, GENESIS_PREV_HASH, "sequence_number"),
        (CHAIN_ID, 1, b"\x00" * 31, "previous_hash"),
        (CHAIN_ID, 1, b"\x00" * 33, "previous_hash"),
    ],
)
def test_malformed_inputs_fail_closed(
    chain_id: str, sequence_number: int, previous_hash: bytes, match: str
) -> None:
    with pytest.raises(HashChainError, match=match):
        compute_event_hash(
            chain_id=chain_id,
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            canonical_event_bytes=PAYLOAD,
        )


def test_hash_to_hex_rejects_wrong_length() -> None:
    with pytest.raises(HashChainError, match="32 raw bytes"):
        hash_to_hex(b"\x00" * 31)


@pytest.mark.parametrize("value", ["", "a" * 63, "A" * 64, "g" * 64, "a" * 64 + "00"])
def test_hex_to_hash_rejects_malformed(value: str) -> None:
    with pytest.raises(HashChainError, match="lowercase 64-character hex"):
        hex_to_hash(value)


def test_hex_round_trip() -> None:
    raw = bytes.fromhex(FROZEN_SEQ1)
    assert hex_to_hash(hash_to_hex(raw)) == raw

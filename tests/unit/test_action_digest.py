"""Canonical action-digest tests (blueprint sections 12.4, 13.2).

The digest is the binding between a gateway decision/approval and the exact action the
adapter executes: any material change must change the digest, and anything that cannot
be canonicalized must fail before execution.
"""

from __future__ import annotations

import pytest

from ai_security.security.canonical_json import CanonicalJSONError
from ai_security.tools.base import compute_action_digest

BASE: dict[str, object] = {
    "request_id": "req-1",
    "principal_subject_id": "dev-user",
    "tool_id": "mock_email.read",
    "action_id": "read",
    "arguments": {"email_id": "email-1"},
    "resource_ids": ("email-1",),
    "destination": None,
    "policy_hash": "a" * 64,
}


def digest(**overrides: object) -> str:
    payload = dict(BASE)
    payload.update(overrides)
    return compute_action_digest(**payload)  # type: ignore[arg-type]


def test_digest_is_lowercase_sha256_hex() -> None:
    value = digest()
    assert len(value) == 64
    assert value == value.lower()
    assert all(character in "0123456789abcdef" for character in value)


def test_digest_is_independent_of_argument_key_order() -> None:
    first = digest(arguments={"email_id": "email-1", "folder": "inbox"})
    second = digest(arguments={"folder": "inbox", "email_id": "email-1"})
    assert first == second


def test_digest_normalizes_unicode_like_canonical_json() -> None:
    composed = "caf\u00e9"
    decomposed = "cafe\u0301"
    assert digest(arguments={"text": composed}) == digest(arguments={"text": decomposed})


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "req-2"),
        ("principal_subject_id", "other-user"),
        ("tool_id", "mock_email.search"),
        ("action_id", "search"),
        ("arguments", {"email_id": "email-2"}),
        ("resource_ids", ("email-2",)),
        ("destination", "https://mock-sink.invalid/collect"),
        ("policy_hash", "b" * 64),
    ],
)
def test_any_material_change_changes_the_digest(field: str, value: object) -> None:
    assert digest(**{field: value}) != digest()


def test_digest_preserves_resource_order() -> None:
    assert digest(resource_ids=("email-1", "email-2")) != digest(
        resource_ids=("email-2", "email-1")
    )


def test_digest_rejects_non_canonicalizable_arguments() -> None:
    with pytest.raises(CanonicalJSONError):
        digest(arguments={"email_id": {"nested", "set"}})


def test_digest_rejects_floats() -> None:
    with pytest.raises(CanonicalJSONError):
        digest(arguments={"email_id": "email-1", "score": 1.5})

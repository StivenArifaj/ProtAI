"""Canonical JSON tests with fixed byte vectors (blueprint section 16.2, ADR-002)."""

from __future__ import annotations

import datetime

import pytest

from ai_security.security.canonical_json import (
    CanonicalJSONError,
    canonical_json_bytes,
    canonical_json_text,
)


def test_sorted_keys_no_whitespace_no_trailing_newline() -> None:
    assert canonical_json_text({"b": 1, "a": [True, None, "x"]}) == '{"a":[true,null,"x"],"b":1}'


def test_empty_object_vector() -> None:
    assert canonical_json_bytes({}) == b"{}"


def test_unicode_is_emitted_as_utf8_without_ascii_escapes() -> None:
    encoded = canonical_json_bytes({"message": "héllo"})
    assert encoded == '{"message":"héllo"}'.encode()
    assert b"\\u" not in encoded


def test_strings_are_nfc_normalized() -> None:
    # "e" + combining acute normalizes to the single code point U+00E9.
    assert canonical_json_bytes({"n": "e\u0301"}) == '{"n":"é"}'.encode()


def test_keys_are_nfc_normalized_too() -> None:
    assert canonical_json_bytes({"e\u0301": 1}) == '{"é":1}'.encode()


def test_nested_structures_are_canonicalized_recursively() -> None:
    payload = {"z": {"b": 2, "a": 1}, "y": [{"d": 4, "c": 3}]}
    assert canonical_json_text(payload) == '{"y":[{"c":3,"d":4}],"z":{"a":1,"b":2}}'


@pytest.mark.parametrize("value", [1.0, 0.5, float("nan"), float("inf"), float("-inf")])
def test_floats_are_rejected(value: float) -> None:
    with pytest.raises(CanonicalJSONError, match="floats are not permitted"):
        canonical_json_bytes({"risk": value})


@pytest.mark.parametrize(
    "value",
    [
        b"bytes",
        datetime.datetime(2026, 10, 19, tzinfo=datetime.UTC),
        {1, 2},
        object(),
    ],
)
def test_non_json_values_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalJSONError, match="not JSON-serializable"):
        canonical_json_bytes({"field": value})


def test_non_string_keys_are_rejected() -> None:
    with pytest.raises(CanonicalJSONError, match="keys must be strings"):
        canonical_json_bytes({1: "x"})  # type: ignore[dict-item]


def test_error_includes_path() -> None:
    with pytest.raises(CanonicalJSONError, match=r"\$\.outer\[0\]"):
        canonical_json_bytes({"outer": [1.5]})

"""Constant-time comparison helper tests (blueprint section 9.2)."""

from __future__ import annotations

from unittest import mock

import pytest

from ai_security.security import constant_time

VALID_HEX = "a" * 64


def test_equal_bytes_compare_true() -> None:
    assert constant_time.constant_time_bytes_equal(b"\x01\x02", b"\x01\x02") is True


def test_unequal_same_length_bytes_compare_false() -> None:
    assert constant_time.constant_time_bytes_equal(b"\x01\x02", b"\x01\x03") is False


def test_unequal_length_bytes_compare_false_without_comparison() -> None:
    with mock.patch.object(
        constant_time.hmac, "compare_digest", side_effect=AssertionError("must not compare")
    ) as spy:
        assert constant_time.constant_time_bytes_equal(b"\x01", b"\x01\x02") is False
    spy.assert_not_called()


def test_empty_bytes_are_rejected_without_comparison() -> None:
    with mock.patch.object(
        constant_time.hmac, "compare_digest", side_effect=AssertionError("must not compare")
    ) as spy:
        assert constant_time.constant_time_bytes_equal(b"", b"") is False
    spy.assert_not_called()


def test_hex32_equal_compares_true() -> None:
    assert constant_time.constant_time_hex32_equal(VALID_HEX, VALID_HEX) is True


def test_hex32_different_compares_false() -> None:
    assert constant_time.constant_time_hex32_equal("a" * 64, "b" * 64) is False


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ab",
        "a" * 63,
        "a" * 65,
        "A" * 64,  # uppercase is malformed: signatures are lowercase hex
        "g" * 64,  # not hex
        "0x" + "a" * 62,
        "a" * 64 + "\n",  # control characters are malformed
    ],
)
def test_malformed_hex_rejected_without_comparison(value: str) -> None:
    with mock.patch.object(
        constant_time.hmac, "compare_digest", side_effect=AssertionError("must not compare")
    ) as spy:
        assert constant_time.constant_time_hex32_equal(VALID_HEX, value) is False
        assert constant_time.constant_time_hex32_equal(value, VALID_HEX) is False
    spy.assert_not_called()


def test_valid_hex_inputs_use_compare_digest() -> None:
    real = constant_time.hmac.compare_digest
    with mock.patch.object(constant_time.hmac, "compare_digest", side_effect=real) as spy:
        assert constant_time.constant_time_hex32_equal(VALID_HEX, VALID_HEX) is True
    assert spy.call_count == 1


def test_no_compare_digest_usage_outside_constant_time_module() -> None:
    """Enforce the single-module rule at test time as a regression guard."""
    from pathlib import Path

    src_root = Path(constant_time.__file__).resolve().parents[2]
    offenders: list[str] = []
    for path in sorted(src_root.rglob("*.py")):
        if path.name == "constant_time.py":
            continue
        if "compare_digest" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(src_root)))
    assert offenders == []

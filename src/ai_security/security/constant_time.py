"""Constant-time comparison helpers (blueprint v1.2 section 9.2, ADR-001).

Every request-signature and approval nonce/action-digest comparison MUST go through
this module; nothing else in the codebase may call ``hmac.compare_digest`` directly
(enforced by the invariant check in ``scripts/check.sh``).

Rules enforced here:

- Malformed lengths are rejected *before* any comparison (no comparison is performed
  for inputs that are not 32-byte lowercase hex digests or byte strings of equal
  length).
- Comparisons use ``hmac.compare_digest`` exclusively.
- Bytes/str are never mixed implicitly; hex digests are validated as strict
  lowercase 64-character hex and compared as raw bytes.
"""

from __future__ import annotations

import hmac
import re

_HEX_32_BYTES = re.compile(r"[0-9a-f]{64}")

HEX32_BYTES = 32


def constant_time_bytes_equal(left: bytes, right: bytes) -> bool:
    """Compare two byte strings in constant time.

    Returns ``False`` for unequal lengths without invoking the comparison.
    """
    if len(left) != len(right) or not left:
        return False
    return hmac.compare_digest(left, right)


def constant_time_hex32_equal(expected_hex: str, candidate_hex: str) -> bool:
    """Compare two lowercase 64-character hex digests (32 raw bytes) in constant time.

    Both inputs are validated first; anything that is not strict lowercase hex of
    exactly 32 bytes returns ``False`` and never reaches the comparison.
    """
    if _HEX_32_BYTES.fullmatch(expected_hex) is None:
        return False
    if _HEX_32_BYTES.fullmatch(candidate_hex) is None:
        return False
    return hmac.compare_digest(bytes.fromhex(expected_hex), bytes.fromhex(candidate_hex))

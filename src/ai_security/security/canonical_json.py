"""Canonical JSON serialization for audited/hashed payloads (blueprint sections 6.2 and
16.2, ADR-002).

The canonical byte format is a stable contract: audit events store the exact
``canonical_event_bytes`` this module produces, and the Phase 7 verifier hashes those
stored bytes — never a reconstructed serialization. Any change to this format is a
breaking change to the audit chain and requires an ADR update and refreshed vectors.

Format rules (blueprint section 16.2, step 5):

- object keys sorted lexicographically; no insignificant whitespace;
- UTF-8 output with Unicode characters emitted directly (no ASCII escapes);
- every string is normalized to Unicode NFC during canonicalization only;
- integers, booleans, null, strings, arrays, and objects only: floats (including
  NaN/Infinity) are rejected because numeric fields on hashed payloads must be
  integers or explicitly-specified canonical decimal strings;
- non-JSON values (bytes, datetimes, sets, ...) are rejected;
- no trailing newline.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any

CanonicalJSONScalar = str | int | bool | None
CanonicalJSONValue = CanonicalJSONScalar | list["CanonicalJSONValue"] | dict[str, "CanonicalJSONValue"]


class CanonicalJSONError(ValueError):
    """Raised when a payload cannot be canonicalized (fail closed)."""


def _normalize(value: Any, path: str) -> CanonicalJSONValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalJSONError(
            f"{path}: floats are not permitted in canonical payloads (section 16.2); "
            "use an integer or an explicit canonical decimal string"
        )
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        normalized: dict[str, CanonicalJSONValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError(f"{path}: object keys must be strings, got {type(key).__name__}")
            normalized[unicodedata.normalize("NFC", key)] = _normalize(item, f"{path}.{key}")
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize(item, f"{path}[{index}]") for index, item in enumerate(value)]
    raise CanonicalJSONError(f"{path}: value of type {type(value).__name__} is not JSON-serializable")


def canonical_json_text(payload: dict[str, Any]) -> str:
    """Serialize a JSON object to its canonical text form (no trailing newline)."""
    normalized = _normalize(payload, "$")
    if not isinstance(normalized, dict):
        raise CanonicalJSONError("$: top-level canonical payload must be an object")
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize a JSON object to UTF-8 canonical bytes (stored in ``BYTEA``)."""
    return canonical_json_text(payload).encode("utf-8")

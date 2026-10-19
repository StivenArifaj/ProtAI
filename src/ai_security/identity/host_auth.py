"""Host-request verification (blueprint section 9.2; ADR-001).

This is the pure verification half of host authentication: it validates the signed
request target, the four authentication headers, the timestamp window, and the
HMAC-SHA256 signature against the configured keys. Replay protection (nonce
uniqueness/registration) is a separate, persistence-backed step performed by the API
middleware after this function returns; nothing here touches I/O.

Rejection codes are stable, machine-readable reasons. The HTTP status mapping is:

- 400 — malformed request target or authentication headers (the request is not a
  well-formed signed request);
- 401 — unknown key id, stale/future timestamp outside tolerance, or bad signature.

Fail-closed rules: any field that is absent, duplicated, non-ASCII, or not in the
exact canonical wire form is rejected before any cryptographic comparison.
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from ai_security.security.constant_time import constant_time_hex32_equal
from ai_security.settings import KEY_ID_PATTERN, HostAuthKey

from .signing import (
    HEADER_KEY_ID,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    SigningError,
    body_sha256_hex,
    build_signing_message,
    compute_signature,
)

_TIMESTAMP = re.compile(r"[0-9]{1,20}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,128}")
_SIGNATURE = re.compile(r"[0-9a-f]{64}")


class HostAuthRejection(StrEnum):
    """Stable rejection codes for host-authenticated requests."""

    missing_headers = "missing_headers"
    duplicated_headers = "duplicated_headers"
    malformed_key_id = "malformed_key_id"
    malformed_timestamp = "malformed_timestamp"
    malformed_nonce = "malformed_nonce"
    malformed_signature = "malformed_signature"
    invalid_request_target = "invalid_request_target"
    unknown_key_id = "unknown_key_id"
    stale_timestamp = "stale_timestamp"
    bad_signature = "bad_signature"


_REJECTION_STATUS = {
    HostAuthRejection.missing_headers: 400,
    HostAuthRejection.duplicated_headers: 400,
    HostAuthRejection.malformed_key_id: 400,
    HostAuthRejection.malformed_timestamp: 400,
    HostAuthRejection.malformed_nonce: 400,
    HostAuthRejection.malformed_signature: 400,
    HostAuthRejection.invalid_request_target: 400,
    HostAuthRejection.unknown_key_id: 401,
    HostAuthRejection.stale_timestamp: 401,
    HostAuthRejection.bad_signature: 401,
}


class HostAuthError(Exception):
    """Host authentication denied the request. The code never embeds secrets."""

    def __init__(self, code: HostAuthRejection) -> None:
        super().__init__(code.value)
        self.code = code
        self.http_status = _REJECTION_STATUS[code]


@dataclass(frozen=True)
class VerifiedHostContext:
    """The authenticated host assertion, before principal resolution."""

    key_id: str
    host_id: str
    audience: str
    allowed_tenants: tuple[str, ...]


def _decode_ascii(value: bytes, code: HostAuthRejection) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HostAuthError(code) from exc


def _single_header(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> bytes:
    """Return the unique value of a required header, rejecting absence/duplicates."""
    values = [value for header_name, value in headers if header_name.lower() == name]
    if not values:
        raise HostAuthError(HostAuthRejection.missing_headers)
    if len(values) > 1:
        raise HostAuthError(HostAuthRejection.duplicated_headers)
    return values[0]


def _validate_request_target(raw_path: bytes, query_string: bytes) -> str:
    """Validate the exact signed request target and return its ASCII text form.

    Signed routes carry no query string and canonical paths only: printable US-ASCII,
    no percent-encoding, no duplicate slashes, no dot segments, no fragment.
    """
    if query_string or not raw_path or not raw_path.startswith(b"/"):
        raise HostAuthError(HostAuthRejection.invalid_request_target)
    for byte in raw_path:
        if byte < 0x21 or byte > 0x7E or byte in (0x25, 0x23, 0x3F):  # % # ?
            raise HostAuthError(HostAuthRejection.invalid_request_target)
    if b"//" in raw_path:
        raise HostAuthError(HostAuthRejection.invalid_request_target)
    if any(segment in (b".", b"..") for segment in raw_path.split(b"/")):
        raise HostAuthError(HostAuthRejection.invalid_request_target)
    return raw_path.decode("ascii")


def verify_host_request(
    *,
    method: str,
    raw_path: bytes,
    query_string: bytes,
    headers: Sequence[tuple[bytes, bytes]],
    body: bytes,
    keys: Mapping[str, HostAuthKey],
    tolerance_seconds: int,
    now_seconds: int | None = None,
) -> VerifiedHostContext:
    """Verify the host signature. Raises ``HostAuthError`` on any rejection.

    ``now_seconds`` can be pinned by tests; production callers omit it.
    """
    path = _validate_request_target(raw_path, query_string)

    key_id = _decode_ascii(
        _single_header(headers, HEADER_KEY_ID.lower().encode("ascii")),
        HostAuthRejection.malformed_key_id,
    )
    if KEY_ID_PATTERN.fullmatch(key_id) is None:
        raise HostAuthError(HostAuthRejection.malformed_key_id)

    timestamp_text = _decode_ascii(
        _single_header(headers, HEADER_TIMESTAMP.lower().encode("ascii")),
        HostAuthRejection.malformed_timestamp,
    )
    if _TIMESTAMP.fullmatch(timestamp_text) is None:
        raise HostAuthError(HostAuthRejection.malformed_timestamp)

    nonce = _decode_ascii(
        _single_header(headers, HEADER_NONCE.lower().encode("ascii")),
        HostAuthRejection.malformed_nonce,
    )
    if _NONCE.fullmatch(nonce) is None:
        raise HostAuthError(HostAuthRejection.malformed_nonce)

    signature = _decode_ascii(
        _single_header(headers, HEADER_SIGNATURE.lower().encode("ascii")),
        HostAuthRejection.malformed_signature,
    )
    if _SIGNATURE.fullmatch(signature) is None:
        raise HostAuthError(HostAuthRejection.malformed_signature)

    record = keys.get(key_id)
    if record is None:
        raise HostAuthError(HostAuthRejection.unknown_key_id)

    now = int(time.time()) if now_seconds is None else now_seconds
    timestamp = int(timestamp_text)
    if abs(now - timestamp) > tolerance_seconds:
        raise HostAuthError(HostAuthRejection.stale_timestamp)

    try:
        message = build_signing_message(
            key_id=key_id,
            method=method,
            path=path,
            timestamp=timestamp_text,
            nonce=nonce,
            body_sha256=body_sha256_hex(body),
        )
    except SigningError as exc:
        raise HostAuthError(HostAuthRejection.invalid_request_target) from exc

    expected = compute_signature(record.secret_bytes, message)
    if not constant_time_hex32_equal(expected, signature):
        raise HostAuthError(HostAuthRejection.bad_signature)

    return VerifiedHostContext(
        key_id=key_id,
        host_id=record.host_id,
        audience=record.audience,
        allowed_tenants=tuple(record.allowed_tenants),
    )


def verified_nonce(headers: Sequence[tuple[bytes, bytes]]) -> str:
    """Extract the nonce header for replay registration.

    Callers hold a context returned by ``verify_host_request``, so the header has
    already been validated; this re-reads it to avoid duplicating header parsing in the
    middleware.
    """
    return _decode_ascii(
        _single_header(headers, HEADER_NONCE.lower().encode("ascii")),
        HostAuthRejection.malformed_nonce,
    )

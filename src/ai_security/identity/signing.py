"""Host-authentication signing (blueprint section 9.2, "Request authentication").

The signed message is newline-joined UTF-8, no trailing newline::

    v1
    <key_id>
    <METHOD>
    <PATH>
    <timestamp>
    <nonce>
    <sha256_hex(exact raw body)>

The signature is ``HMAC-SHA256(secret, message)`` rendered as lowercase hex. Timestamps
are Unix seconds; nonces are server-generated 128-bit values (32 hex characters happen
to fit the ``[A-Za-z0-9_-]{32,128}`` wire charset). This module is the signer used by
tests/tooling; the verifier in ``host_auth`` re-validates every field independently.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass

SIGNING_MESSAGE_VERSION = "v1"

HEADER_KEY_ID = "X-Gateway-Key-Id"
HEADER_TIMESTAMP = "X-Gateway-Timestamp"
HEADER_NONCE = "X-Gateway-Nonce"
HEADER_SIGNATURE = "X-Gateway-Signature"

NONCE_BYTES = 16  # 128-bit nonce (section 9.2)

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_METHOD = re.compile(r"[A-Z]{1,16}")
_TIMESTAMP = re.compile(r"[0-9]{1,20}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class SigningError(ValueError):
    """A signing-message field is not in the canonical wire form."""


def body_sha256_hex(body: bytes) -> str:
    """Lowercase hex SHA-256 of the exact raw request body."""
    return hashlib.sha256(body).hexdigest()


def build_signing_message(
    *,
    key_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body_sha256: str,
) -> bytes:
    """Build the exact signed message bytes (newline-joined, no trailing newline)."""
    normalized_method = method.upper()
    if not key_id or _CONTROL_CHARACTERS.search(key_id):
        raise SigningError("key_id must be non-empty and control-free")
    if _METHOD.fullmatch(normalized_method) is None:
        raise SigningError("method must be 1-16 ASCII letters")
    if not path.startswith("/") or _CONTROL_CHARACTERS.search(path):
        raise SigningError("path must be an absolute, control-free path")
    if _TIMESTAMP.fullmatch(timestamp) is None:
        raise SigningError("timestamp must be ASCII digits (Unix seconds)")
    if not nonce or _CONTROL_CHARACTERS.search(nonce):
        raise SigningError("nonce must be non-empty and control-free")
    if _SHA256_HEX.fullmatch(body_sha256) is None:
        raise SigningError("body_sha256 must be lowercase 64-character hex")
    return "\n".join(
        [SIGNING_MESSAGE_VERSION, key_id, normalized_method, path, timestamp, nonce, body_sha256]
    ).encode("utf-8")


def compute_signature(secret: bytes, message: bytes) -> str:
    """HMAC-SHA256 over the signing message, lowercase hex."""
    if not secret:
        raise SigningError("secret must be non-empty")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class RequestSignature:
    """Result of signing a request, ready for as-headers() emission."""

    key_id: str
    timestamp: str
    nonce: str
    signature: str

    def as_headers(self) -> dict[str, str]:
        return {
            HEADER_KEY_ID: self.key_id,
            HEADER_TIMESTAMP: self.timestamp,
            HEADER_NONCE: self.nonce,
            HEADER_SIGNATURE: self.signature,
        }


def sign_request(
    secret: bytes,
    *,
    key_id: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> RequestSignature:
    """Sign a request for test/tooling use.

    A missing timestamp uses the current time; a missing nonce is generated from
    ``secrets`` (128 bits). Verification never generates either value.
    """
    timestamp_text = str(int(time.time()) if timestamp is None else timestamp)
    nonce_text = secrets.token_hex(NONCE_BYTES) if nonce is None else nonce
    message = build_signing_message(
        key_id=key_id,
        method=method,
        path=path,
        timestamp=timestamp_text,
        nonce=nonce_text,
        body_sha256=body_sha256_hex(body),
    )
    return RequestSignature(
        key_id=key_id,
        timestamp=timestamp_text,
        nonce=nonce_text,
        signature=compute_signature(secret, message),
    )

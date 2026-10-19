"""Host-request verification tests (blueprint section 9.2; ADR-001).

Covers the exact signing-message wire format, the full rejection-code surface of the
verifier, timestamp-window boundaries, and constant-time signature comparison paths
(forged/mutated/mismatched requests must never verify).
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from ai_security.identity.host_auth import (
    HostAuthError,
    HostAuthRejection,
    VerifiedHostContext,
    verify_host_request,
)
from ai_security.identity.signing import (
    RequestSignature,
    SigningError,
    body_sha256_hex,
    build_signing_message,
    sign_request,
)
from ai_security.settings import HostAuthKey, parse_host_auth_keys

SECRET = b"\x09" * 32
KEY_ID = "test-key"
NOW = 1_700_000_000
NONCE = "A" * 32
TOLERANCE = 60


def make_keys(**overrides: object) -> dict[str, HostAuthKey]:
    record: dict[str, object] = {
        "secret_b64": base64.b64encode(SECRET).decode(),
        "host_id": "host-a",
        "audience": "ai-agent-security-gateway",
        "allowed_tenants": ["t1", "t2"],
    }
    record.update(overrides)
    return parse_host_auth_keys(json.dumps({KEY_ID: record}))


def wire_headers(signature: RequestSignature) -> list[tuple[bytes, bytes]]:
    return [
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in signature.as_headers().items()
    ]


def signed_headers(
    *, body: bytes = b"payload", path: str = "/v1/test", method: str = "POST", **kwargs: object
) -> list[tuple[bytes, bytes]]:
    signature = sign_request(
        SECRET,
        key_id=KEY_ID,
        method=method,
        path=path,
        body=body,
        timestamp=kwargs.pop("timestamp", NOW),  # type: ignore[arg-type]
        nonce=kwargs.pop("nonce", NONCE),  # type: ignore[arg-type]
    )
    return wire_headers(signature)


def verify(
    *,
    method: str = "POST",
    raw_path: bytes = b"/v1/test",
    query_string: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"payload",
    keys: dict[str, HostAuthKey] | None = None,
    now_seconds: int = NOW,
) -> VerifiedHostContext:
    return verify_host_request(
        method=method,
        raw_path=raw_path,
        query_string=query_string,
        headers=signed_headers() if headers is None else headers,
        body=body,
        keys=make_keys() if keys is None else keys,
        tolerance_seconds=TOLERANCE,
        now_seconds=now_seconds,
    )


# --- Exact signing-message wire format ---


def test_signing_message_is_exact_newline_joined_bytes() -> None:
    message = build_signing_message(
        key_id=KEY_ID,
        method="post",
        path="/v1/test",
        timestamp="1700000000",
        nonce=NONCE,
        body_sha256=body_sha256_hex(b"hello"),
    )
    expected = (
        "v1\ntest-key\nPOST\n/v1/test\n1700000000\n"
        + NONCE
        + "\n"
        + hashlib.sha256(b"hello").hexdigest()
    )
    assert message == expected.encode("utf-8")
    assert not message.endswith(b"\n")


def message_kwargs(**overrides: str) -> dict[str, str]:
    values = {
        "key_id": "k",
        "method": "POST",
        "path": "/v1/x",
        "timestamp": "1",
        "nonce": "n",
        "body_sha256": "0" * 64,
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    "kwargs",
    [
        message_kwargs(key_id=""),
        message_kwargs(method="GE T"),
        message_kwargs(path="v1/x"),
        message_kwargs(timestamp="abc"),
        message_kwargs(body_sha256="AB" * 32),
    ],
)
def test_signing_message_rejects_non_canonical_fields(kwargs: dict[str, str]) -> None:
    with pytest.raises(SigningError):
        build_signing_message(**kwargs)  # type: ignore[arg-type]


def test_sign_request_generates_nonce_and_timestamp_by_default() -> None:
    signature = sign_request(SECRET, key_id=KEY_ID, method="POST", path="/v1/test", body=b"x")
    assert len(signature.nonce) == 32
    assert signature.nonce.isalnum()
    assert signature.timestamp.isdigit()
    assert len(signature.signature) == 64
    assert signature.signature == signature.signature.lower()


# --- Verification success ---


def test_verified_request_returns_host_context() -> None:
    context = verify()
    assert context == VerifiedHostContext(
        key_id=KEY_ID,
        host_id="host-a",
        audience="ai-agent-security-gateway",
        allowed_tenants=("t1", "t2"),
    )


def test_verification_is_independent_of_header_order() -> None:
    headers = signed_headers()
    headers.reverse()
    assert verify(headers=headers).key_id == KEY_ID


def test_timestamp_boundaries_inclusive() -> None:
    assert verify(now_seconds=NOW + TOLERANCE).key_id == KEY_ID
    assert verify(now_seconds=NOW - TOLERANCE).key_id == KEY_ID


def test_empty_body_verifies() -> None:
    assert verify(body=b"", headers=signed_headers(body=b"")).key_id == KEY_ID


# --- Signature and window rejections (401 family) ---


def test_forged_signature_is_rejected() -> None:
    headers = signed_headers()
    name, value = headers[-1]
    original = value.decode("ascii")
    flipped = ("0" if original[0] != "0" else "1") + original[1:]
    with pytest.raises(HostAuthError) as excinfo:
        verify(headers=[*headers[:-1], (name, flipped.encode())])
    assert excinfo.value.code is HostAuthRejection.bad_signature
    assert excinfo.value.http_status == 401


def test_mutated_body_is_rejected() -> None:
    with pytest.raises(HostAuthError) as excinfo:
        verify(body=b"payload-x")
    assert excinfo.value.code is HostAuthRejection.bad_signature


def test_mutated_path_is_rejected() -> None:
    with pytest.raises(HostAuthError) as excinfo:
        verify(raw_path=b"/v1/other")
    assert excinfo.value.code is HostAuthRejection.bad_signature


def test_mutated_method_is_rejected() -> None:
    with pytest.raises(HostAuthError) as excinfo:
        verify(method="GET")
    assert excinfo.value.code is HostAuthRejection.bad_signature


@pytest.mark.parametrize("skew", [TOLERANCE + 1, -TOLERANCE - 1, 3600])
def test_stale_or_future_timestamp_is_rejected(skew: int) -> None:
    with pytest.raises(HostAuthError) as excinfo:
        verify(now_seconds=NOW + skew)
    assert excinfo.value.code is HostAuthRejection.stale_timestamp
    assert excinfo.value.http_status == 401


def test_unknown_key_id_is_rejected() -> None:
    signature = sign_request(
        SECRET,
        key_id="ghost-key",
        method="POST",
        path="/v1/test",
        body=b"payload",
        timestamp=NOW,
        nonce=NONCE,
    )
    with pytest.raises(HostAuthError) as excinfo:
        verify(headers=wire_headers(signature))
    assert excinfo.value.code is HostAuthRejection.unknown_key_id
    assert excinfo.value.http_status == 401


def test_wrong_secret_for_known_key_is_rejected() -> None:
    signature = sign_request(
        b"\x0e" * 32,
        key_id=KEY_ID,
        method="POST",
        path="/v1/test",
        body=b"payload",
        timestamp=NOW,
        nonce=NONCE,
    )
    with pytest.raises(HostAuthError) as excinfo:
        verify(headers=wire_headers(signature))
    assert excinfo.value.code is HostAuthRejection.bad_signature


# --- Malformed header rejections (400 family) ---


@pytest.mark.parametrize("header_index", range(4))
def test_missing_auth_header_is_rejected(header_index: int) -> None:
    headers = signed_headers()
    del headers[header_index]
    with pytest.raises(HostAuthError) as excinfo:
        verify(headers=headers)
    assert excinfo.value.code is HostAuthRejection.missing_headers
    assert excinfo.value.http_status == 400


def test_duplicated_auth_header_is_rejected() -> None:
    headers = signed_headers()
    headers.append(headers[0])
    with pytest.raises(HostAuthError) as excinfo:
        verify(headers=headers)
    assert excinfo.value.code is HostAuthRejection.duplicated_headers


@pytest.mark.parametrize(
    ("index", "value", "code"),
    [
        (0, b"\xc3\xa9", HostAuthRejection.malformed_key_id),
        (0, b"bad key!", HostAuthRejection.malformed_key_id),
        (1, b"17e9", HostAuthRejection.malformed_timestamp),
        (1, b"-10", HostAuthRejection.malformed_timestamp),
        (2, b"A" * 31, HostAuthRejection.malformed_nonce),
        (2, b"A" * 129, HostAuthRejection.malformed_nonce),
        (2, b"A" * 31 + b".", HostAuthRejection.malformed_nonce),
        (3, b"AB" * 32, HostAuthRejection.malformed_signature),
        (3, b"a" * 63, HostAuthRejection.malformed_signature),
        (3, b"\xff" * 64, HostAuthRejection.malformed_signature),
    ],
)
def test_malformed_header_values_are_rejected(
    index: int, value: bytes, code: HostAuthRejection
) -> None:
    headers = signed_headers()
    headers[index] = (headers[index][0], value)
    with pytest.raises(HostAuthError) as excinfo:
        verify(headers=headers)
    assert excinfo.value.code is code
    assert excinfo.value.http_status == 400


# --- Request-target rejections (400 family) ---


@pytest.mark.parametrize(
    ("raw_path", "query_string"),
    [
        (b"/v1/test", b"a=1"),
        (b"/v1/a%20b", b""),
        (b"/v1//a", b""),
        (b"/v1/./a", b""),
        (b"/v1/../a", b""),
        (b"/v1/\xc3\xa9", b""),
        (b"/v1/a b", b""),
        (b"/v1/a#b", b""),
        (b"/v1/a?x", b""),
        (b"v1/test", b""),
        (b"", b""),
    ],
)
def test_non_canonical_request_targets_are_rejected(raw_path: bytes, query_string: bytes) -> None:
    with pytest.raises(HostAuthError) as excinfo:
        verify(raw_path=raw_path, query_string=query_string)
    assert excinfo.value.code is HostAuthRejection.invalid_request_target
    assert excinfo.value.http_status == 400

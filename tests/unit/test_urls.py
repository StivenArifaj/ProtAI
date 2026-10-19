"""Destination canonicalization tests (blueprint section 6.2).

One canonical form, exact-match semantics: every accepted input maps to the documented
canonical string, and every ambiguous/unsafe input is rejected (fail closed).
"""

from __future__ import annotations

import pytest

from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("https://sink.internal.example/collect", "https://sink.internal.example/collect"),
        ("HTTPS://SINK.Example.COM/Collect", "https://sink.example.com/Collect"),
        ("https://example.com", "https://example.com/"),
        ("https://example.com/", "https://example.com/"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("https://[::1]:8443/x", "https://[::1]:8443/x"),
        ("https://[2001:DB8::1]/x", "https://[2001:db8::1]/x"),
        ("https://example.com/%7euser", "https://example.com/%7Euser"),
        ("https://example.com/a%2Fb", "https://example.com/a%2Fb"),
        ("https://example.com/x?a=1&b=2", "https://example.com/x?a=1&b=2"),
        ("https://example.com/x?", "https://example.com/x"),
        ("https://BÜCHER.example/x", "https://xn--bcher-kva.example/x"),
        ("https://u\u0308ber.example/x", "https://xn--ber-goa.example/x"),
        ("https://XN--BCHER-KVA.example/x", "https://xn--bcher-kva.example/x"),
    ],
)
def test_canonicalizes_valid_destinations(raw: str, canonical: str) -> None:
    assert canonicalize_destination(raw) == canonical


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("", id="empty"),
        pytest.param("not a url", id="no-scheme"),
        pytest.param("http://example.com/x", id="http-scheme"),
        pytest.param("ftp://example.com/x", id="ftp-scheme"),
        pytest.param("https://", id="no-host"),
        pytest.param("https://@example.com/x", id="empty-userinfo"),
        pytest.param("https://user@example.com/x", id="userinfo"),
        pytest.param("https://user:pass@example.com/x", id="credential-userinfo"),
        pytest.param("https://example.com/x#frag", id="fragment"),
        pytest.param("https://example.com./x", id="trailing-dot"),
        pytest.param("https://example.com:99999/x", id="invalid-port"),
        pytest.param("https://[::1/x", id="malformed-ipv6"),
        pytest.param("https://[fe80::1%25eth0]/x", id="ipv6-zone-identifier"),
        pytest.param("https://exa mple.com/x", id="space-in-host"),
        pytest.param("https://example.com/a b", id="space-in-path"),
        pytest.param("https://example.com/x\ny", id="newline-in-path"),
        pytest.param("https://example.com/caf\u00e9", id="non-ascii-path"),
        pytest.param("https://example.com/%zz", id="malformed-percent-escape"),
        pytest.param("https://example.com/%4", id="truncated-percent-escape"),
        pytest.param("https://..example.com/x", id="degenerate-idna-label"),
    ],
)
def test_rejects_unsafe_or_malformed_destinations(raw: str) -> None:
    with pytest.raises(DestinationCanonicalizationError):
        canonicalize_destination(raw)


def test_canonical_output_is_idempotent() -> None:
    once = canonicalize_destination("HTTPS://BÜCHER.example:443/%7e?q=%2f")
    assert canonicalize_destination(once) == once

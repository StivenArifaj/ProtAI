"""Destination (URL) canonicalization for policy egress rules (blueprint section 6.2).

One canonical form, defined and tested once: policy allowlists and evaluated
destinations are compared as exact canonical strings. There are no wildcard patterns in
v1; a destination matches an allowlist entry only when the canonical forms are equal.

Canonical rules (fail closed — anything ambiguous or unsafe is rejected):

- scheme must be exactly ``https``; every other scheme (including ``http``) is rejected;
- the netloc must not contain user-info credentials (``user@``/``user:pass@``);
- the host is IDNA-encoded and lowercased (Unicode hosts are supported and have one
  canonical punycode form; IPv6 literals are kept in bracket form, but zone identifiers
  are rejected);
- an explicit port is rejected when it is the https default (443) and kept otherwise;
- fragments (``#...``) are rejected; the path defaults to ``/``;
- whitespace, control characters, and non-ASCII characters outside the host are
  rejected (path/query text must be percent-encoded); existing percent-escapes are
  normalized to uppercase hex and malformed escapes are rejected;
- malformed URLs raise ``DestinationCanonicalizationError`` and callers fail closed.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_UNSAFE_CHARACTERS = re.compile(r"[\s\x00-\x1f\x7f-\x9f]")
_ASCII_PRINTABLE = re.compile(r"^[!-~]*$")
_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")

HTTPS_DEFAULT_PORT = 443


class DestinationCanonicalizationError(ValueError):
    """The destination is malformed or unsafe and must not be evaluated."""


def _normalize_percent_escapes(text: str, what: str) -> str:
    if _PERCENT_ESCAPE.search(text):
        raise DestinationCanonicalizationError(f"{what} contains a malformed percent-escape")
    return re.sub(
        r"%([0-9A-Fa-f]{2})",
        lambda match: "%" + match.group(1).upper(),
        text,
    )


def _canonical_host(hostname: str) -> str:
    if ":" in hostname:  # IPv6 literal (urlsplit strips the brackets, raises on garbage)
        if "%" in hostname:
            raise DestinationCanonicalizationError("IPv6 zone identifiers are not allowed")
        return f"[{hostname.lower()}]"
    if hostname.endswith("."):
        raise DestinationCanonicalizationError("host must not end with a trailing dot")
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DestinationCanonicalizationError(f"host is not a valid IDNA name: {exc}") from exc
    if not ascii_host or ascii_host.startswith("."):
        raise DestinationCanonicalizationError("host must not be empty")
    return ascii_host.lower()


def canonicalize_destination(value: str) -> str:
    """Return the canonical https destination form or raise (fail closed)."""
    if not value:
        raise DestinationCanonicalizationError("destination must not be empty")
    if _UNSAFE_CHARACTERS.search(value):
        raise DestinationCanonicalizationError(
            "destination must not contain whitespace or control characters"
        )
    try:
        parts = urlsplit(value)
        port = parts.port  # raises ValueError for invalid ports
    except ValueError as exc:
        raise DestinationCanonicalizationError(f"destination is not a valid URL: {exc}") from exc
    if parts.scheme != "https":
        raise DestinationCanonicalizationError(
            f"destination scheme {parts.scheme or '<none>'!r} is not allowed; https is required"
        )
    if "@" in parts.netloc:
        raise DestinationCanonicalizationError("destination must not contain user-info")
    if parts.fragment:
        raise DestinationCanonicalizationError("destination must not contain a fragment")
    if parts.hostname is None:
        raise DestinationCanonicalizationError("destination must contain a host")
    if (
        _ASCII_PRINTABLE.fullmatch(parts.path) is None
        or _ASCII_PRINTABLE.fullmatch(parts.query) is None
    ):
        raise DestinationCanonicalizationError(
            "path and query must be printable ASCII (percent-encode anything else)"
        )

    host = _canonical_host(parts.hostname)
    path = _normalize_percent_escapes(parts.path, "path") or "/"
    path = path if path.startswith("/") else f"/{path}"
    query = _normalize_percent_escapes(parts.query, "query")

    port_part = f":{port}" if port is not None and port != HTTPS_DEFAULT_PORT else ""
    query_part = f"?{query}" if query else ""
    return f"https://{host}{port_part}{path}{query_part}"

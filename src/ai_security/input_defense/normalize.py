"""Bounded intake and safe normalization copy (blueprint section 7.2 steps 1-2).

The original content is never mutated or "sanitized". Normalization produces a separate
copy used only for detection (NFKC, removal of zero-width/format characters, one bounded
decoding pass for percent/HTML escapes). Every transformation is reported as a typed
signal so callers can apply disposition policy and preserve evidence.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from .models import FindingCode

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_HTML_ENTITY = re.compile(r"&#(?:[xX][0-9A-Fa-f]+|\d+);|&[A-Za-z][A-Za-z0-9]{1,31};")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_WORD = re.compile(r"[^\W\d_]{2,64}", re.UNICODE)
_HOMOGLYPH_SCRIPT_PAIRS = {frozenset({"LATIN", "CYRILLIC"}), frozenset({"LATIN", "GREEK"})}
_ZERO_WIDTH_RANGES = (
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xE0100, 0xE01EF),
)


@dataclass(frozen=True)
class NormalizationSignal:
    """One deterministic normalization/obfuscation signal (no raw content)."""

    code: FindingCode
    detail: str


def decode_bytes(raw: bytes) -> str:
    """Strict UTF-8 decode of the declared text payload."""
    return raw.decode("utf-8")


def json_depth(value: object) -> int:
    """Iterative maximum container depth of a JSON value (scalars are depth 0)."""
    maximum = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        maximum = max(maximum, depth)
        if isinstance(item, dict):
            for child in item.values():
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            for child in item:
                stack.append((child, depth + 1))
    return maximum


def inspect_json_structure(text: str, max_depth: int) -> tuple[NormalizationSignal, ...]:
    """Validate JSON structure and nesting depth (typed failure, fail closed)."""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return (
            NormalizationSignal(
                code=FindingCode.invalid_structure,
                detail="declared application/json was not valid JSON",
            ),
        )
    try:
        depth = json_depth(parsed)
    except RecursionError:
        return (
            NormalizationSignal(
                code=FindingCode.nesting_too_deep,
                detail="JSON nesting exceeded the parser safety bound",
            ),
        )
    if depth > max_depth:
        return (
            NormalizationSignal(
                code=FindingCode.nesting_too_deep,
                detail=f"JSON nesting depth {depth} exceeds configured {max_depth}",
            ),
        )
    return ()


def _is_zero_width(character: str) -> bool:
    if unicodedata.category(character) == "Cf":
        return True
    codepoint = ord(character)
    return any(start <= codepoint <= end for start, end in _ZERO_WIDTH_RANGES)


def _has_mixed_script_token(text: str) -> bool:
    for match in _WORD.finditer(text):
        scripts: set[str] = set()
        for character in match.group(0):
            name = unicodedata.name(character, "")
            if name:
                scripts.add(name.split(" ", 1)[0])
        if any(pair <= scripts for pair in _HOMOGLYPH_SCRIPT_PAIRS):
            return True
    return False


def normalize_for_detection(text: str) -> tuple[str, bool, tuple[NormalizationSignal, ...]]:
    """Return (detection copy, changed, signals); the input string is not modified."""
    signals: list[NormalizationSignal] = []

    control_count = len(_CONTROL_CHARACTERS.findall(text))
    if control_count:
        signals.append(
            NormalizationSignal(
                code=FindingCode.control_characters,
                detail=f"{control_count} unexpected control character(s)",
            )
        )

    zero_width_count = sum(1 for character in text if _is_zero_width(character))
    if zero_width_count:
        signals.append(
            NormalizationSignal(
                code=FindingCode.obfuscated_content,
                detail=f"{zero_width_count} zero-width/format character(s)",
            )
        )

    percent_count = len(_PERCENT_ESCAPE.findall(text))
    entity_count = len(_HTML_ENTITY.findall(text))
    escape_count = percent_count + entity_count
    if escape_count >= 8 and escape_count * 20 >= len(text):
        signals.append(
            NormalizationSignal(
                code=FindingCode.excessive_encoding,
                detail=f"{percent_count} percent and {entity_count} entity escape(s)",
            )
        )

    base64_blobs = [
        match.group(0)
        for match in _BASE64_BLOB.finditer(text)
        if any(char.isalpha() for char in match.group(0))
        and any(char.isdigit() for char in match.group(0))
    ]
    if base64_blobs:
        signals.append(
            NormalizationSignal(
                code=FindingCode.obfuscated_content,
                detail=f"{len(base64_blobs)} long base64-looking token(s)",
            )
        )

    working = text
    if percent_count or entity_count:
        working = unquote(html.unescape(working))
    working = "".join(
        " " if _CONTROL_CHARACTERS.fullmatch(character) else character
        for character in working
        if not _is_zero_width(character)
    )
    working = unicodedata.normalize("NFKC", working)
    if _has_mixed_script_token(working):
        signals.append(
            NormalizationSignal(
                code=FindingCode.homoglyph_indicators,
                detail="token mixes Latin letters with Cyrillic/Greek characters",
            )
        )
    return working, working != text, tuple(signals)

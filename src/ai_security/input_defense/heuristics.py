"""Versioned deterministic heuristics (blueprint sections 7.2 step 3, 7.3, 7.5).

Patterns are indicators, not proof. Detection never deletes or rewrites content and
never grants authority. Matches that are visibly quoted or embedded in educational /
defensive explanations are downgraded to ``QUOTED_INSTRUCTION_CONTEXT`` (FLAG) instead of
being treated as a direct override; the detector still reports them so a human or a
later policy can decide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import FindingCode, TrustLabel


@dataclass(frozen=True)
class HeuristicRule:
    """One stable indicator rule (rule ids are auditable contract)."""

    rule_id: str
    code: FindingCode
    pattern: re.Pattern[str]
    external_only: bool = False
    qualified_downgrade: bool = True


def _compile(pattern: str, *, multiline: bool = False) -> re.Pattern[str]:
    flags = re.IGNORECASE | re.UNICODE
    if multiline:
        flags |= re.MULTILINE
    return re.compile(pattern, flags)


_DOWNGRADE_MARKERS = _compile(
    r"\b(?:for example|e\.g\.|for instance|educational|education|defensive|quoted|"
    r"quote|research|detect(?:ion|ing)?|attack example|training example|benign)\b"
)
_QUOTE_CHARACTERS = frozenset("\"'`\u2018\u2019\u201c\u201d")

RULES: tuple[HeuristicRule, ...] = (
    HeuristicRule(
        rule_id="direct-override/ignore-prior-instructions",
        code=FindingCode.direct_override_pattern,
        pattern=_compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,60}"
            r"\b(?:previous|prior|above|earlier|system|all)\b[^.\n]{0,30}"
            r"\b(?:instructions?|prompts?|rules?|directives?)\b"
        ),
    ),
    HeuristicRule(
        rule_id="direct-override/reveal-hidden-instructions",
        code=FindingCode.direct_override_pattern,
        pattern=_compile(
            r"\b(?:reveal|show|print|repeat|expose|dump|output)\b[^.\n]{0,50}"
            r"\b(?:system prompt|hidden (?:prompt|instructions?)|developer message|"
            r"initial instructions?)\b"
        ),
    ),
    HeuristicRule(
        rule_id="direct-override/developer-mode",
        code=FindingCode.direct_override_pattern,
        pattern=_compile(r"\b(?:enable|enter|activate|switch to)\b[^.\n]{0,20}\bdeveloper mode\b"),
    ),
    HeuristicRule(
        rule_id="direct-override/jailbreak",
        code=FindingCode.direct_override_pattern,
        pattern=_compile(r"\bjailbreak(?:ing|ed|s)?\b"),
    ),
    HeuristicRule(
        rule_id="secret-extraction/credential-request",
        code=FindingCode.secret_extraction_request,
        pattern=_compile(
            r"\b(?:send|reveal|print|show|provide|exfiltrate|leak|dump)\b[^.\n]{0,40}"
            r"\b(?:api[ _-]?key|secret|token|password|passphrase|credentials?)\b"
        ),
    ),
    HeuristicRule(
        rule_id="secret-extraction/system-prompt-request",
        code=FindingCode.secret_extraction_request,
        pattern=_compile(r"\b(?:what|tell me|repeat|recite)\b[^.\n]{0,30}\bsystem prompt\b"),
    ),
    HeuristicRule(
        rule_id="untrusted-instruction/assistant-directed",
        code=FindingCode.untrusted_instruction,
        pattern=_compile(
            r"\b(?:assistant|agent|model|llm|ai)\b[^.\n]{0,30}"
            r"\b(?:must|should|shall|needs? to|is required to)\b"
        ),
        external_only=True,
        qualified_downgrade=False,
    ),
    HeuristicRule(
        rule_id="untrusted-instruction/role-marker",
        code=FindingCode.untrusted_instruction,
        pattern=_compile(r"^\s*(?:system|developer|assistant)\s*:", multiline=True),
        external_only=True,
        qualified_downgrade=False,
    ),
    HeuristicRule(
        rule_id="untrusted-instruction/conceal-from-user",
        code=FindingCode.untrusted_instruction,
        pattern=_compile(
            r"\b(?:do not|don't|without)\b[^.\n]{0,20}\b(?:tell|telling|inform|informing|"
            r"notify|notifying)\b[^.\n]{0,20}\b(?:the )?user\b"
        ),
        external_only=True,
        qualified_downgrade=False,
    ),
    HeuristicRule(
        rule_id="untrusted-instruction/read-this",
        code=FindingCode.untrusted_instruction,
        pattern=_compile(
            r"\bwhen (?:you|the assistant|the model) (?:read|see|process)(?:es)? this\b"
        ),
        external_only=True,
        qualified_downgrade=False,
    ),
)


@dataclass(frozen=True)
class HeuristicMatch:
    """One rule match (offset only; never the matched text)."""

    rule_id: str
    code: FindingCode
    char_offset: int


def _line_bounds(text: str, offset: int) -> tuple[int, int]:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return start, len(text) if end == -1 else end


def _is_contextually_qualified(text: str, start: int, end: int) -> bool:
    line_start, line_end = _line_bounds(text, start)
    line_prefix = text[line_start:start]
    prefixes = (text[max(0, start - 80) : start], line_prefix)
    if any(_DOWNGRADE_MARKERS.search(candidate) for candidate in prefixes):
        return True
    # An odd number of quote characters before the match on its line means the match is
    # inside a quoted span such as: The guide says "ignore previous instructions".
    if sum(1 for character in line_prefix if character in _QUOTE_CHARACTERS) % 2 == 1:
        return True
    line_suffix = text[end:line_end]
    return any(character in _QUOTE_CHARACTERS for character in line_suffix[:1])


def scan(text: str, trust_label: TrustLabel) -> tuple[HeuristicMatch, ...]:
    """Run the versioned rules; deterministic order, at most one match per rule."""
    matches: list[HeuristicMatch] = []
    emitted_codes: set[FindingCode] = set()
    for rule in RULES:
        if rule.external_only and trust_label not in (
            TrustLabel.external_untrusted,
            TrustLabel.tool_result,
        ):
            continue
        match = rule.pattern.search(text)
        if match is None:
            continue
        qualified = rule.qualified_downgrade and _is_contextually_qualified(
            text, match.start(), match.end()
        )
        code = FindingCode.quoted_instruction_context if qualified else rule.code
        if code in emitted_codes:
            continue
        emitted_codes.add(code)
        matches.append(HeuristicMatch(rule_id=rule.rule_id, code=code, char_offset=match.start()))
    return tuple(matches)

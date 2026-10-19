"""Typed input-defense contracts and trust labels (blueprint sections 2.2, 7.2, 7.5).

Everything here is data: findings estimate suspicious patterns, they never authorize a
tool call. Codes and versions are stable, versioned strings so they can be audited and
compared across releases. No model clears content; a clean report is not proof of safety.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

INPUT_DEFENSE_SCHEMA_VERSION = 1
DETECTOR_VERSION = "input-detector-v1"
HEURISTICS_VERSION = "input-heuristics-v1"
MAX_SOURCE_ID_LENGTH = 256
MAX_DETAIL_LENGTH = 256
MAX_SEGMENT_ID_LENGTH = 128


class TrustLabel(StrEnum):
    """Trust classes from blueprint section 2.2 (enum, never free-form strings)."""

    system_policy = "SYSTEM_POLICY"
    authenticated_user = "AUTHENTICATED_USER"
    model_generated = "MODEL_GENERATED"
    external_untrusted = "EXTERNAL_UNTRUSTED"
    tool_result = "TOOL_RESULT"
    security_metadata = "SECURITY_METADATA"


class Disposition(StrEnum):
    """Intake disposition (blueprint section 7.2 step 6)."""

    pass_ = "PASS"  # noqa: S105
    flag = "FLAG"
    quarantine = "QUARANTINE"
    reject = "REJECT"

    @property
    def rank(self) -> int:
        return _DISPOSITION_RANK[self]


_DISPOSITION_RANK: dict[Disposition, int] = {
    Disposition.pass_: 0,
    Disposition.flag: 1,
    Disposition.quarantine: 2,
    Disposition.reject: 3,
}


def strongest_disposition(dispositions: tuple[Disposition, ...]) -> Disposition:
    """Return the strongest disposition; an empty sequence means PASS."""
    return max(dispositions, key=lambda disposition: disposition.rank, default=Disposition.pass_)


class FindingCode(StrEnum):
    """Stable finding codes (blueprint section 7.5, extended additively)."""

    direct_override_pattern = "DIRECT_OVERRIDE_PATTERN"
    secret_extraction_request = "SECRET_EXTRACTION_REQUEST"  # noqa: S105
    untrusted_instruction = "UNTRUSTED_INSTRUCTION"
    obfuscated_content = "OBFUSCATED_CONTENT"
    quoted_instruction_context = "QUOTED_INSTRUCTION_CONTEXT"
    oversize_input = "OVERSIZE_INPUT"
    unsupported_content_type = "UNSUPPORTED_CONTENT_TYPE"
    invalid_encoding = "INVALID_ENCODING"
    control_characters = "CONTROL_CHARACTERS"
    homoglyph_indicators = "HOMOGLYPH_INDICATORS"
    excessive_encoding = "EXCESSIVE_ENCODING"
    invalid_structure = "INVALID_STRUCTURE"
    nesting_too_deep = "NESTING_TOO_DEEP"
    detector_unavailable = "DETECTOR_UNAVAILABLE"


class DetectorFinding(BaseModel):
    """One typed finding; stores no raw payload (blueprint sections 7.5, 16.3)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    code: FindingCode
    segment_id: str = Field(min_length=1, max_length=MAX_SEGMENT_ID_LENGTH)
    source_id: str = Field(min_length=1, max_length=MAX_SOURCE_ID_LENGTH)
    trust_label: TrustLabel
    rule_id: str | None = Field(default=None, min_length=1, max_length=128)
    char_offset: int | None = Field(default=None, ge=0)
    detail: str | None = Field(default=None, min_length=1, max_length=MAX_DETAIL_LENGTH)

    @field_validator("detail")
    @classmethod
    def _detail_is_bounded_summary(cls, value: str | None) -> str | None:
        if value is not None and ("\n" in value or "\r" in value):
            raise ValueError("finding details must be single-line summaries")
        return value


class IntakeReport(BaseModel):
    """Deterministic result of inspecting one content segment.

    ``disposition`` is the strongest configured finding disposition. ``PASS`` only
    means no configured signal fired; it is not a safety guarantee.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: int = Field(default=INPUT_DEFENSE_SCHEMA_VERSION, ge=1)
    detector_version: str = Field(default=DETECTOR_VERSION, min_length=1, max_length=128)
    heuristics_version: str = Field(default=HEURISTICS_VERSION, min_length=1, max_length=128)
    config_version: str = Field(min_length=1, max_length=128)
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    segment_id: str = Field(min_length=1, max_length=MAX_SEGMENT_ID_LENGTH)
    source_id: str = Field(min_length=1, max_length=MAX_SOURCE_ID_LENGTH)
    trust_label: TrustLabel
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_length_bytes: int = Field(ge=0)
    normalized_changed: bool = False
    disposition: Disposition
    findings: tuple[DetectorFinding, ...] = ()

    @property
    def content_digest(self) -> str:
        return self.content_sha256


def content_digest(raw: bytes) -> str:
    """SHA-256 over the exact original bytes (never the normalized copy)."""
    return hashlib.sha256(raw).hexdigest()

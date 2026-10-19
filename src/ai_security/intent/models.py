"""Server-issued intent manifests and concrete request constraints (blueprint §8).

Intent extraction proposes the user's apparent goal; it never grants authority. A
manifest is created only by the server-side issuer after the extractor's structured
output has been strictly validated, and it binds the request, verified principal,
policy version/hash, extractor version, and a short expiry.

``IntentConstraint`` entries are concrete and enforceable: exact tool/action ids, exact
resource ids, exact canonical destinations, exact allowed parameter values, and a
per-constraint use limit. There are no wildcards, prefix scopes, or caller-supplied
tool allowlists. A manifest can only narrow what the deterministic policy engine later
authorizes; it is never an authorization input.

The manifest is sentinel-sealed: direct construction fails closed. As with the
execution authorization, this is an in-process guardrail, not a sandbox against
malicious in-process code (Phase 10).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ai_security.policy.models import TOOL_ID_PATTERN
from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)
from ai_security.tools.base import STABLE_ID_PATTERN

MAX_CONSTRAINTS = 16
MAX_TOTAL_USES = 32
MAX_RESOURCES_PER_CONSTRAINT = 32
MAX_DESTINATIONS_PER_CONSTRAINT = 8
MAX_VALUES_PER_PARAMETER = 8
MAX_EXTRACTED_TEXT_BYTES = 32_768

_PARAMETER_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_STABLE_ID = re.compile(STABLE_ID_PATTERN)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")

IntentScalar = str | int | bool | None


class RelativeTimeScope(StrEnum):
    """Relative date expressions the server resolves using a trusted timezone."""

    today = "TODAY"
    this_week = "THIS_WEEK"


class TimeWindow(BaseModel):
    """Exact UTC interval resolved once on the server (blueprint §8.3)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _window_is_ordered_and_aware(self) -> TimeWindow:
        if self.start.utcoffset() is None or self.end.utcoffset() is None:
            raise ValueError("time window bounds must be timezone-aware")
        if self.end <= self.start:
            raise ValueError("time window end must be after start")
        return self


class IntentConstraint(BaseModel):
    """One concrete action constraint (not a permission; policy still decides)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    tool_id: str = Field(min_length=1, max_length=128, pattern=TOOL_ID_PATTERN)
    action_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    allowed_resource_ids: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    allowed_parameter_values: dict[str, tuple[IntentScalar, ...]] = Field(default_factory=dict)
    max_uses: int = Field(default=1, ge=1, le=MAX_TOTAL_USES)

    @field_validator("allowed_resource_ids")
    @classmethod
    def _resources_are_unique_stable_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_RESOURCES_PER_CONSTRAINT:
            raise ValueError(
                f"at most {MAX_RESOURCES_PER_CONSTRAINT} allowed resources per constraint"
            )
        if len(set(value)) != len(value):
            raise ValueError("allowed_resource_ids must be unique")
        for resource_id in value:
            if _STABLE_ID.fullmatch(resource_id) is None:
                raise ValueError(f"allowed resource id {resource_id!r} is not a stable id")
        return value

    @field_validator("allowed_destinations")
    @classmethod
    def _destinations_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_DESTINATIONS_PER_CONSTRAINT:
            raise ValueError(
                f"at most {MAX_DESTINATIONS_PER_CONSTRAINT} allowed destinations per constraint"
            )
        canonical: list[str] = []
        for destination in value:
            try:
                canonical.append(canonicalize_destination(destination))
            except DestinationCanonicalizationError as exc:
                raise ValueError(f"invalid allowed destination: {exc}") from exc
        if len(set(canonical)) != len(canonical):
            raise ValueError("allowed_destinations must be unique after canonicalization")
        return tuple(canonical)

    @field_validator("allowed_parameter_values")
    @classmethod
    def _parameter_values_are_exact_and_bounded(
        cls, value: dict[str, tuple[IntentScalar, ...]]
    ) -> dict[str, tuple[IntentScalar, ...]]:
        for name, allowed in value.items():
            if _PARAMETER_NAME.fullmatch(name) is None:
                raise ValueError(f"parameter name {name!r} is not a lowercase identifier")
            if not allowed:
                raise ValueError(f"parameter {name!r} must have at least one allowed value")
            if len(allowed) > MAX_VALUES_PER_PARAMETER:
                raise ValueError(
                    f"parameter {name!r} has more than {MAX_VALUES_PER_PARAMETER} values"
                )
            seen: set[tuple[type[object], object]] = set()
            for item in allowed:
                if isinstance(item, float):
                    raise ValueError("float parameter values are not permitted")
                key = (type(item), item)
                if key in seen:
                    raise ValueError(f"parameter {name!r} has duplicate allowed values")
                seen.add(key)
        return value


class IntentExtractionStatus(StrEnum):
    """Extractor outcome; only ``ACTIVE`` can lead to a manifest."""

    active = "ACTIVE"
    requires_clarification = "REQUIRES_CLARIFICATION"
    rejected = "REJECTED"


class IntentExtraction(BaseModel):
    """Strict structured extractor output (validated before any manifest exists)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: IntentExtractionStatus
    constraints: tuple[IntentConstraint, ...] = ()
    clarification_question: str | None = Field(default=None, min_length=1, max_length=1_024)
    confidence_score: int | None = Field(default=None, ge=0, le=100)
    relative_time_scope: RelativeTimeScope | None = None
    extractor_version: str = Field(min_length=1, max_length=128)

    @field_validator("clarification_question")
    @classmethod
    def _question_has_no_control_characters(cls, value: str | None) -> str | None:
        if value is not None and _CONTROL_CHARACTERS.search(value):
            raise ValueError("clarification_question must not contain control characters")
        return value

    @field_validator("constraints")
    @classmethod
    def _constraints_are_bounded_and_unique(
        cls, value: tuple[IntentConstraint, ...]
    ) -> tuple[IntentConstraint, ...]:
        if len(value) > MAX_CONSTRAINTS:
            raise ValueError(f"at most {MAX_CONSTRAINTS} intent constraints")
        keys = [(constraint.tool_id, constraint.action_id) for constraint in value]
        if len(set(keys)) != len(keys):
            raise ValueError("intent constraints must have unique (tool_id, action_id) pairs")
        if sum(constraint.max_uses for constraint in value) > MAX_TOTAL_USES:
            raise ValueError(f"total intent uses must not exceed {MAX_TOTAL_USES}")
        return value

    @model_validator(mode="after")
    def _status_matches_the_payload(self) -> IntentExtraction:
        if self.status is IntentExtractionStatus.active:
            if not self.constraints:
                raise ValueError("an ACTIVE extraction must contain at least one constraint")
            if self.clarification_question is not None:
                raise ValueError("an ACTIVE extraction must not carry a clarification question")
        else:
            if self.constraints:
                raise ValueError("a non-ACTIVE extraction must not contain constraints")
            if self.clarification_question is None:
                raise ValueError(
                    "a non-ACTIVE extraction must carry a clarification/rejection message"
                )
        return self


@dataclass(frozen=True)
class IntentExtractionRequest:
    """Input to an extractor; the raw text is never copied into the manifest."""

    request_id: str
    principal_subject_id: str
    text: str
    received_at: datetime

    def __post_init__(self) -> None:
        if not self.text.strip():
            raise ValueError("intent extraction text must not be empty")
        if len(self.text.encode("utf-8")) > MAX_EXTRACTED_TEXT_BYTES:
            raise ValueError(
                f"intent extraction text exceeds the {MAX_EXTRACTED_TEXT_BYTES}-byte bound"
            )
        if self.received_at.utcoffset() is None:
            raise ValueError("received_at must be timezone-aware")
        if _STABLE_ID.fullmatch(self.request_id) is None:
            raise ValueError("request_id must be a stable id")
        if not self.principal_subject_id:
            raise ValueError("principal_subject_id must not be empty")


_MANIFEST_SENTINEL = object()


class IntentManifestErrorCode(StrEnum):
    """Typed manifest verification failures (all fail closed)."""

    forged = "forged_or_unsealed"
    not_yet_valid = "not_yet_valid"
    expired = "expired"
    request_mismatch = "request_mismatch"
    principal_mismatch = "principal_mismatch"
    tenant_mismatch = "tenant_mismatch"
    policy_mismatch = "policy_mismatch"


class IntentManifestError(ValueError):
    """A manifest was not issued for this request/principal/policy or has expired."""

    def __init__(self, code: IntentManifestErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True)
class IntentManifest:
    """Server-created, expiring, request/principal/policy-bound constraints."""

    manifest_id: str
    request_id: str
    principal_subject_id: str
    tenant_id: str | None
    policy_version: str
    policy_hash: str
    extractor_version: str
    created_at: datetime
    expires_at: datetime
    goal_digest: str
    constraints: tuple[IntentConstraint, ...]
    time_window: TimeWindow | None = None
    _sentinel: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._sentinel is not _MANIFEST_SENTINEL:
            raise IntentManifestError(IntentManifestErrorCode.forged)
        if self.created_at.utcoffset() is None or self.expires_at.utcoffset() is None:
            raise ValueError("manifest timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("manifest expiry must be after creation")
        if _STABLE_ID.fullmatch(self.manifest_id) is None:
            raise ValueError("manifest_id must be a stable id")

    def constraint_for(self, tool_id: str, action_id: str) -> IntentConstraint | None:
        for constraint in self.constraints:
            if constraint.tool_id == tool_id and constraint.action_id == action_id:
                return constraint
        return None


def _issue_intent_manifest(
    *,
    manifest_id: str,
    request_id: str,
    principal_subject_id: str,
    tenant_id: str | None,
    policy_version: str,
    policy_hash: str,
    extractor_version: str,
    created_at: datetime,
    expires_at: datetime,
    goal_digest: str,
    constraints: tuple[IntentConstraint, ...],
    time_window: TimeWindow | None,
) -> IntentManifest:
    """Private issuer used by ``intent.service`` only (not exported)."""
    return IntentManifest(
        manifest_id=manifest_id,
        request_id=request_id,
        principal_subject_id=principal_subject_id,
        tenant_id=tenant_id,
        policy_version=policy_version,
        policy_hash=policy_hash,
        extractor_version=extractor_version,
        created_at=created_at,
        expires_at=expires_at,
        goal_digest=goal_digest,
        constraints=constraints,
        time_window=time_window,
        _sentinel=_MANIFEST_SENTINEL,
    )


def verify_intent_manifest(
    manifest: IntentManifest,
    *,
    request_id: str,
    principal_subject_id: str,
    tenant_id: str | None,
    policy_version: str,
    policy_hash: str,
    now: datetime,
) -> None:
    """Verify issuance and every binding; raise ``IntentManifestError`` on failure."""
    if not isinstance(manifest, IntentManifest) or manifest._sentinel is not _MANIFEST_SENTINEL:
        raise IntentManifestError(IntentManifestErrorCode.forged)
    if now.utcoffset() is None:
        raise ValueError("verification time must be timezone-aware")
    if manifest.created_at > now:
        raise IntentManifestError(IntentManifestErrorCode.not_yet_valid)
    if manifest.expires_at <= now:
        raise IntentManifestError(IntentManifestErrorCode.expired)
    if manifest.request_id != request_id:
        raise IntentManifestError(IntentManifestErrorCode.request_mismatch)
    if manifest.principal_subject_id != principal_subject_id:
        raise IntentManifestError(IntentManifestErrorCode.principal_mismatch)
    if manifest.tenant_id != tenant_id:
        raise IntentManifestError(IntentManifestErrorCode.tenant_mismatch)
    if manifest.policy_version != policy_version or manifest.policy_hash != policy_hash:
        raise IntentManifestError(IntentManifestErrorCode.policy_mismatch)


class IntentResolutionStatus(StrEnum):
    """Outcome of extract-and-issue; only ``ACTIVE`` carries a manifest."""

    active = "ACTIVE"
    requires_clarification = "REQUIRES_CLARIFICATION"
    rejected = "REJECTED"
    extractor_unavailable = "EXTRACTOR_UNAVAILABLE"
    invalid_extraction = "INVALID_EXTRACTION"


@dataclass(frozen=True)
class IntentResolution:
    """Server result of extraction/validation (never a permission by itself)."""

    status: IntentResolutionStatus
    manifest: IntentManifest | None = None
    clarification_question: str | None = None
    error_code: str | None = None
    extractor_version: str | None = None

    def __post_init__(self) -> None:
        if (self.status is IntentResolutionStatus.active) != (self.manifest is not None):
            raise ValueError("only ACTIVE resolutions may carry an IntentManifest")
        if self.status is IntentResolutionStatus.requires_clarification:
            if self.clarification_question is None:
                raise ValueError("a clarification resolution needs a question")
        if self.status is IntentResolutionStatus.active and self.error_code is not None:
            raise ValueError("an ACTIVE resolution must not carry an error code")


__all__ = [
    "IntentConstraint",
    "IntentExtraction",
    "IntentExtractionRequest",
    "IntentExtractionStatus",
    "IntentManifest",
    "IntentManifestError",
    "IntentManifestErrorCode",
    "IntentResolution",
    "IntentResolutionStatus",
    "IntentScalar",
    "MAX_EXTRACTED_TEXT_BYTES",
    "RelativeTimeScope",
    "TimeWindow",
    "verify_intent_manifest",
]

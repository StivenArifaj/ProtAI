"""Strict dataset and manifest contracts for the evaluation harness.

A case is repository-owned, synthetic, and explicitly labeled. Every case carries a
stable ID, task, category, split, provenance, license note, and a template ID used for
cross-split leakage checks. Task-specific payloads use the same typed vocabularies as the
shipped code (trust labels, data classes, side-effect classes, decisions, and
dispositions), so a fixture cannot invent a parallel meaning.

Public benchmark datasets are not vendored. Only original synthetic fixtures live in this
repository (blueprint sections 19.1, 19.4, 19.5).
"""

from __future__ import annotations

import base64
import re
from datetime import date
from typing import Annotated, Literal, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from ai_security.data_security.classification import DataClass
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.models import InvocationOutcome
from ai_security.input_defense.models import TrustLabel
from ai_security.intent.models import IntentResolutionStatus
from ai_security.tools.base import STABLE_ID_PATTERN, SideEffectClass

CASE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,63}$"
STABLE_NAME_PATTERN = r"^[a-z][a-z0-9_]{1,63}$"
TEMPLATE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,63}$"
DATASET_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
CONSTRAINT_KEY_PATTERN = r"^[A-Za-z0-9._-]{1,128}\.[A-Za-z0-9._-]{1,128}$"


Task = str


class TaskName:
    """Canonical task names (kept separate from the string discriminator)."""

    input_detection = "input_detection"
    dlp_egress = "dlp_egress"
    dlp_response = "dlp_response"
    risk = "risk"
    intent = "intent"
    authorization = "authorization"


TASK_NAMES: tuple[str, ...] = (
    TaskName.input_detection,
    TaskName.dlp_egress,
    TaskName.dlp_response,
    TaskName.risk,
    TaskName.intent,
    TaskName.authorization,
)


Split = str


class SplitName:
    dev = "dev"
    validation = "validation"
    holdout = "holdout"


SPLIT_NAMES: tuple[str, ...] = (SplitName.dev, SplitName.validation, SplitName.holdout)


class CaseBase(BaseModel):
    """Fields shared by every evaluation case."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(pattern=CASE_ID_PATTERN)
    category: str = Field(pattern=STABLE_NAME_PATTERN)
    split: str = Field(pattern=r"^(dev|validation|holdout)$")
    template_id: str = Field(pattern=TEMPLATE_ID_PATTERN)
    provenance: str = Field(min_length=8, max_length=256)
    license: str = Field(min_length=3, max_length=128)
    synthetic: Literal[True]
    notes: str | None = Field(default=None, min_length=1, max_length=512)

    @field_validator("provenance", "license", "notes")
    @classmethod
    def _no_control_characters(cls, value: str | None) -> str | None:
        if value is not None and any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ValueError("metadata must not contain control characters")
        return value


class InputDetectionCase(CaseBase):
    """One input-defense inspection. Positive = malicious/unauthorized input."""

    task: Literal["input_detection"] = "input_detection"
    content: str | None = Field(default=None, min_length=1, max_length=200_000)
    content_b64: str | None = Field(default=None, min_length=4, max_length=300_000)
    content_type: Literal["text/plain", "text/markdown", "application/json", "message/rfc822"] = (
        "text/plain"
    )
    trust_label: TrustLabel = TrustLabel.authenticated_user
    expected_malicious: bool

    @model_validator(mode="after")
    def _exactly_one_content_encoding(self) -> Self:
        if (self.content is None) == (self.content_b64 is None):
            raise ValueError("exactly one of content/content_b64 must be present")
        if self.content_b64 is not None:
            try:
                base64.b64decode(self.content_b64.encode("ascii"), validate=True)
            except (ValueError, UnicodeEncodeError) as exc:
                raise ValueError("content_b64 is not valid base64") from exc
        return self


class DlpEgressCase(CaseBase):
    """One tool-bound egress inspection. Positive = protected content must not egress."""

    task: Literal["dlp_egress"] = "dlp_egress"
    data: dict[str, JsonValue] = Field(min_length=1)
    declared_data_class: DataClass
    destination: str | None = Field(default=None, min_length=1, max_length=2_048)
    require_destination: bool = True
    expected_protected: bool
    must_not_contain: tuple[str, ...] = ()


class DlpResponseCase(CaseBase):
    """One response-release inspection. Positive = content must not be released unmodified."""

    task: Literal["dlp_response"] = "dlp_response"
    data: dict[str, JsonValue] = Field(min_length=1)
    declared_data_class: DataClass
    expected_protected: bool
    must_not_contain: tuple[str, ...] = ()


class RiskCase(CaseBase):
    """One deterministic risk-v2 assessment. No probability label is assigned."""

    task: Literal["risk"] = "risk"
    side_effect_class: SideEffectClass
    data_class: DataClass
    destination: str | None = Field(default=None, min_length=1, max_length=2_048)
    resource_count: int = Field(ge=0, le=32)
    expected_score: int = Field(ge=0, le=100)
    expected_factor_codes: tuple[str, ...]

    @field_validator("expected_factor_codes")
    @classmethod
    def _factor_codes_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("expected_factor_codes must be unique")
        return value

    @model_validator(mode="after")
    def _destination_matches_side_effect(self) -> Self:
        if (
            self.destination is not None
            and self.side_effect_class is not SideEffectClass.external_mutation
        ):
            raise ValueError("only EXTERNAL_MUTATION may carry a destination")
        return self


class IntentCase(CaseBase):
    """One extract-and-issue run. Status is multiclass; no aggregate accuracy is claimed."""

    task: Literal["intent"] = "intent"
    text: str = Field(min_length=1, max_length=32_768)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    extractor: Literal["mock", "local_transcript"] = "mock"
    provider_output: str | None = Field(default=None, min_length=1, max_length=65_536)
    provider_failure: Literal["timeout", "unavailable"] | None = None
    expected_status: IntentResolutionStatus
    expected_constraint_keys: tuple[str, ...] = ()
    expected_resource_ids: tuple[str, ...] = ()

    @field_validator("timezone")
    @classmethod
    def _timezone_is_iana(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"{value!r} is not a known IANA timezone") from exc
        return value

    @field_validator("expected_constraint_keys")
    @classmethod
    def _constraint_keys_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("expected_constraint_keys must be unique")
        return value

    @field_validator("expected_resource_ids")
    @classmethod
    def _resource_ids_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("expected_resource_ids must be unique")
        return value

    @model_validator(mode="after")
    def _provider_and_status_shape(self) -> Self:
        if self.extractor == "mock":
            if self.provider_output is not None or self.provider_failure is not None:
                raise ValueError("mock extraction must not carry provider transcript fields")
        elif (self.provider_output is None) == (self.provider_failure is None):
            raise ValueError(
                "local_transcript requires exactly one of provider_output/provider_failure"
            )
        if self.expected_status is not IntentResolutionStatus.active:
            if self.expected_constraint_keys or self.expected_resource_ids:
                raise ValueError("a non-ACTIVE expectation must not declare constraints")
        return self


class AuthorizationCase(CaseBase):
    """One real gateway invocation with mock adapters (observation only)."""

    task: Literal["authorization"] = "authorization"
    profile: Literal["shipped", "sink_enabled_eval"] = "shipped"
    principal_subject_id: str = Field(default="dev-user", min_length=1, max_length=256)
    tool_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    action_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    target_resource_ids: tuple[str, ...] = ()
    declared_destination: str | None = Field(default=None, min_length=1, max_length=2_048)
    proposal_principal_subject_id: str | None = Field(default=None, min_length=1, max_length=256)
    proposal_request_id: str | None = Field(default=None, min_length=1, max_length=128)
    deadline_offset_seconds: int | None = Field(default=None, ge=-3_600, le=3_600)
    expected_decision: FirewallDecision
    expected_execution: bool
    expected_outcome: InvocationOutcome | None = None
    expected_reason: DecisionReason | None = None
    expected_sink_writes: int = Field(default=0, ge=0, le=1)
    result_must_not_contain: tuple[str, ...] = ()

    @field_validator("target_resource_ids")
    @classmethod
    def _resources_are_unique_stable_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("target_resource_ids must be unique")
        for resource_id in value:
            if re.fullmatch(STABLE_ID_PATTERN, resource_id) is None:
                raise ValueError(f"target resource id {resource_id!r} is not a stable id")
        return value

    @model_validator(mode="after")
    def _expectations_are_consistent(self) -> Self:
        if self.expected_decision is FirewallDecision.block and self.expected_execution:
            raise ValueError("a BLOCK expectation cannot execute")
        if self.expected_decision is FirewallDecision.ask_user and self.expected_execution:
            raise ValueError("ASK_USER without an approval must not execute")
        if self.expected_decision is FirewallDecision.allow and not self.expected_execution:
            raise ValueError("an ALLOW expectation must execute in the evaluation profile")
        if self.expected_sink_writes > 0:
            if self.profile != "sink_enabled_eval":
                raise ValueError("sink writes require the sink_enabled_eval profile")
            if not self.expected_execution:
                raise ValueError("sink writes require execution")
        if (
            self.expected_outcome is InvocationOutcome.response_blocked
            and not self.expected_execution
        ):
            raise ValueError("a response-blocked outcome requires an executed adapter")
        return self


EvaluationCase = Annotated[
    InputDetectionCase
    | DlpEgressCase
    | DlpResponseCase
    | RiskCase
    | IntentCase
    | AuthorizationCase,
    Field(discriminator="task"),
]


class FixtureFile(BaseModel):
    """One fixture file and its content hash/count contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_count: int = Field(ge=1)


class SplitFile(BaseModel):
    """The explicit split partition and quick-regression subset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    counts: dict[str, int]

    @model_validator(mode="after")
    def _all_splits_counted(self) -> Self:
        if set(self.counts) != set(SPLIT_NAMES):
            raise ValueError("split counts must cover dev, validation, and holdout exactly")
        if any(count < 1 for count in self.counts.values()):
            raise ValueError("each split must contain at least one case")
        return self


class DatasetManifest(BaseModel):
    """``evaluation/dataset_manifest.yaml`` (strict; no unknown fields)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    dataset_version: str = Field(pattern=DATASET_VERSION_PATTERN)
    description: str = Field(min_length=8, max_length=512)
    license: str = Field(min_length=3, max_length=128)
    provenance: str = Field(min_length=8, max_length=512)
    seed: int = Field(ge=0)
    created_at: date
    fixtures: dict[str, FixtureFile]
    splits: SplitFile

    @model_validator(mode="after")
    def _all_tasks_declared(self) -> Self:
        if set(self.fixtures) != set(TASK_NAMES):
            raise ValueError("fixtures must declare every task exactly once")
        return self


class SplitDocument(BaseModel):
    """``evaluation/splits/splits.json``: explicit IDs, not inferred at runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    dataset_version: str = Field(pattern=DATASET_VERSION_PATTERN)
    splits: dict[str, tuple[str, ...]]
    quick: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _all_splits_present_and_unique(self) -> Self:
        if set(self.splits) != set(SPLIT_NAMES):
            raise ValueError("splits must declare dev, validation, and holdout exactly")
        seen: set[str] = set()
        for split_name, case_ids in self.splits.items():
            if not case_ids:
                raise ValueError(f"split {split_name!r} must not be empty")
            for case_id in case_ids:
                if case_id in seen:
                    raise ValueError(f"case id {case_id!r} appears in more than one split")
                seen.add(case_id)
        if len(set(self.quick)) != len(self.quick):
            raise ValueError("quick subset must not contain duplicate case ids")
        if not set(self.quick) <= seen:
            raise ValueError("quick subset references an unknown case id")
        return self


__all__ = [
    "AuthorizationCase",
    "CaseBase",
    "DatasetManifest",
    "DlpEgressCase",
    "DlpResponseCase",
    "EvaluationCase",
    "FixtureFile",
    "InputDetectionCase",
    "IntentCase",
    "RiskCase",
    "SPLIT_NAMES",
    "Split",
    "SplitDocument",
    "SplitFile",
    "SplitName",
    "TASK_NAMES",
    "Task",
    "TaskName",
]

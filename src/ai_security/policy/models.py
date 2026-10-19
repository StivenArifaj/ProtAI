"""Validated policy document models (blueprint sections 10.4, 11.4; ADR-007).

Two declarative documents make the v1 matrix real:

- ``config/policies.yaml`` — the starter policy: exact tool/action identifiers, each
  with its canonical side-effect class and its explicit permissions (local-write
  permission, approval eligibility, external-egress enablement and exact destination
  allowlist). Tools absent from this document are unknown and therefore denied.
- ``config/risk_thresholds.yaml`` — the risk bands (initial experimental defaults,
  section 11.4) that only apply to actions which already passed every hard gate.

Both are strictly validated: unknown fields, unknown enum values, malformed tool ids,
inconsistently configured flags (e.g. egress config on a non-egress tool), and
non-canonical destinations all fail validation. Nothing here executes or resolves
anything dynamically — policy is data.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)
from ai_security.tools.base import SideEffectClass

SCHEMA_VERSION = 1

# Tool/action identifiers: 1-128 chars, alphanumeric start/end, ``. _ -`` inside.
# Anchored so the pattern is a full match under pydantic's search-semantics `pattern=`.
TOOL_ID_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$"


class Thresholds(BaseModel):
    """Risk bands (blueprint section 11.4): initial experimental defaults, not
    empirically validated security thresholds. They apply only to actions that already
    passed every hard gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ask_user_at_or_above: int = Field(ge=1, le=100)
    block_at_or_above: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def _ask_band_before_block_band(self) -> Thresholds:
        if self.ask_user_at_or_above >= self.block_at_or_above:
            raise ValueError(
                "ask_user_at_or_above must be strictly below block_at_or_above "
                "(blueprint section 11.4)"
            )
        return self


class RiskThresholdsDocument(BaseModel):
    """``config/risk_thresholds.yaml`` (blueprint section 11.4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    version: str = Field(min_length=1, max_length=128)
    thresholds: Thresholds


class ToolPolicy(BaseModel):
    """One tool/action entry in ``config/policies.yaml`` (blueprint section 10.4).

    Flags are meaningful only for matching side-effect classes and validation rejects
    nonsense (``explicitly_permitted`` on a non-mutating tool, egress configuration on
    a tool that cannot egress) instead of silently ignoring it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    side_effect_class: SideEffectClass
    explicitly_permitted: bool = False
    approval_eligible: bool = False
    external_egress_enabled: bool = False
    allowed_destinations: tuple[str, ...] = ()

    @field_validator("allowed_destinations")
    @classmethod
    def _destinations_are_canonical_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        canonical: list[str] = []
        for destination in value:
            try:
                canonical.append(canonicalize_destination(destination))
            except DestinationCanonicalizationError as exc:
                raise ValueError(f"allowed destination {destination!r} is invalid: {exc}") from exc
        if len(set(canonical)) != len(canonical):
            raise ValueError(
                "allowed_destinations must not contain duplicates after canonicalization"
            )
        return tuple(canonical)

    @model_validator(mode="after")
    def _flags_match_side_effect_class(self) -> ToolPolicy:
        if (
            self.explicitly_permitted
            and self.side_effect_class is not SideEffectClass.local_mutation
        ):
            raise ValueError("explicitly_permitted is only meaningful for LOCAL_MUTATION tools")
        if (
            self.external_egress_enabled or self.allowed_destinations
        ) and self.side_effect_class is not SideEffectClass.external_mutation:
            raise ValueError(
                "external egress configuration is only meaningful for EXTERNAL_MUTATION tools"
            )
        return self


class PoliciesDocument(BaseModel):
    """``config/policies.yaml`` (blueprint section 10.4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    version: str = Field(min_length=1, max_length=128)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)

    @field_validator("tools")
    @classmethod
    def _tool_ids_are_canonical(cls, value: dict[str, ToolPolicy]) -> dict[str, ToolPolicy]:
        for tool_id in value:
            if re.fullmatch(TOOL_ID_PATTERN, tool_id) is None:
                raise ValueError(
                    f"tool id {tool_id!r} is malformed; allowed: 1-128 characters, "
                    "alphanumeric start/end, '.', '_', '-' inside"
                )
        return value


@dataclass(frozen=True)
class PolicyBundle:
    """A fully validated policy set: the two documents plus their content hashes.

    ``scenario`` is set only for self-check scenario bundles (``with_tool_policy``);
    the content hashes always describe the source files.
    """

    policies: PoliciesDocument
    risk_thresholds: RiskThresholdsDocument
    policies_sha256: str
    thresholds_sha256: str
    scenario: str | None = None

    @property
    def version(self) -> str:
        return self.policies.version

    @property
    def combined_hash(self) -> str:
        """Deterministic digest over both documents' content hashes."""
        payload = f"policies={self.policies_sha256};thresholds={self.thresholds_sha256}"
        return hashlib.sha256(payload.encode("ascii")).hexdigest()

    @property
    def ask_user_at_or_above(self) -> int:
        return self.risk_thresholds.thresholds.ask_user_at_or_above

    @property
    def block_at_or_above(self) -> int:
        return self.risk_thresholds.thresholds.block_at_or_above

    def tool_policy(self, tool_id: str) -> ToolPolicy | None:
        """The registered policy for a tool, or ``None`` (unknown -> deny)."""
        return self.policies.tools.get(tool_id)

    def with_tool_policy(self, tool_id: str, tool_policy: ToolPolicy) -> PolicyBundle:
        """Return a scenario bundle overriding/adding one tool entry.

        Used only by the ADR-007 self-checks to exercise matrix rows the starter policy
        deliberately does not enable (blueprint section 10.5's "dedicated test
        scenario"). The override is validated by the same ``ToolPolicy`` model.
        """
        if re.fullmatch(TOOL_ID_PATTERN, tool_id) is None:
            raise ValueError(f"scenario tool id {tool_id!r} is malformed")
        tools = dict(self.policies.tools)
        tools[tool_id] = tool_policy
        scenario_policies = self.policies.model_copy(update={"tools": tools})
        scenario = f"tool-policy override for {tool_id}"
        return replace(self, policies=scenario_policies, scenario=scenario)

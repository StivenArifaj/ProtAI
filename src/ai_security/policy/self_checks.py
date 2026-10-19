"""Policy self-check fixtures: loader, runner, and pass/fail reporting (ADR-007).

``config/policy_self_checks.yaml`` holds deterministic, side-effect-free evaluation
fixtures derived from ``docs/POLICY_DECISION_MATRIX.md``. Startup and readiness evaluate
them against the active decision path; any mismatch fails startup/readiness (deliberate
fail-fast on policy/documentation drift).

Loading is strict: safe YAML only, unknown keys rejected, enum values exact, duplicate
fixture names rejected, and a missing/malformed file is a configuration error — never a
silent pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .interim_matrix import Decision, PolicyInput, evaluate


class PolicySelfCheckError(RuntimeError):
    """Policy self-checks failed (startup/readiness must refuse)."""


class PolicySelfCheckConfigError(PolicySelfCheckError):
    """The self-check fixture file itself is missing, malformed, or invalid."""


@dataclass(frozen=True)
class PolicySelfCheckFailure:
    fixture: str
    expected: Decision
    actual: Decision
    reason: str  # the evaluator's actual reason code


class PolicySelfCheckFixture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    case: PolicyInput
    expected_decision: Decision
    expected_reason: str | None = None


class PolicySelfCheckFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixtures: list[PolicySelfCheckFixture] = Field(min_length=1)


def load_policy_self_checks(path: Path) -> list[PolicySelfCheckFixture]:
    """Load and strictly validate the fixture file."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicySelfCheckConfigError(
            f"policy self-check file {path} cannot be read: {exc}"
        ) from exc
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PolicySelfCheckConfigError(
            f"policy self-check file {path} is not valid YAML"
        ) from exc
    try:
        document = PolicySelfCheckFile.model_validate(data)
    except ValidationError as exc:
        raise PolicySelfCheckConfigError(
            f"policy self-check file {path} failed strict validation: {exc.error_count()} error(s)"
        ) from exc
    seen: set[str] = set()
    for fixture in document.fixtures:
        if fixture.name in seen:
            raise PolicySelfCheckConfigError(
                f"policy self-check file {path} contains duplicate fixture name {fixture.name!r}"
            )
        seen.add(fixture.name)
    return document.fixtures


def run_policy_self_checks(fixtures: list[PolicySelfCheckFixture]) -> list[PolicySelfCheckFailure]:
    """Evaluate every fixture; return all mismatches (empty list = pass)."""
    failures: list[PolicySelfCheckFailure] = []
    for fixture in fixtures:
        decision = evaluate(fixture.case)
        reason_mismatch = (
            fixture.expected_reason is not None and decision.reason != fixture.expected_reason
        )
        if decision.decision is not fixture.expected_decision or reason_mismatch:
            failures.append(
                PolicySelfCheckFailure(
                    fixture=fixture.name,
                    expected=fixture.expected_decision,
                    actual=decision.decision,
                    reason=decision.reason,
                )
            )
    return failures


def check_policy_self_checks(path: str | Path) -> list[PolicySelfCheckFailure]:
    """Load and evaluate the fixture file (raises ``PolicySelfCheckConfigError`` if invalid)."""
    return run_policy_self_checks(load_policy_self_checks(Path(path)))


def policy_self_checks_pass(path: str | Path) -> bool:
    """Readiness-shaped probe: never raises; invalid/missing configuration is a failure."""
    try:
        return not check_policy_self_checks(path)
    except PolicySelfCheckConfigError:
        return False

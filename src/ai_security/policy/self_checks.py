"""Policy self-check fixtures evaluated against the real policy engine (ADR-007).

``config/policy_self_checks.yaml`` holds deterministic, side-effect-free evaluation
fixtures derived from ``docs/POLICY_DECISION_MATRIX.md``. Startup and readiness evaluate
them against the loaded policy documents (``config/policies.yaml`` +
``config/risk_thresholds.yaml``) and the real engine; any mismatch fails
startup/readiness (deliberate fail-fast on policy drift).

A fixture may carry a strictly validated ``tool_policy`` override to express matrix
rows the starter policy deliberately does not enable (blueprint section 10.5's
"dedicated test scenario", e.g. external egress). The override is validated by the same
``ToolPolicy`` model as production policy and only affects that one evaluation.

Loading is strict: safe YAML only, duplicate keys rejected, unknown keys rejected, enum
values exact, duplicate fixture names rejected, and a missing/malformed file is a
configuration error — never a silent pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.policy_engine import PolicyEngine, PolicyEvaluationRequest
from ai_security.policy.loader import PolicyConfigError, load_policy_bundle
from ai_security.policy.models import PolicyBundle, ToolPolicy


class PolicySelfCheckError(RuntimeError):
    """Policy self-checks failed (startup/readiness must refuse)."""


class PolicySelfCheckConfigError(PolicySelfCheckError):
    """The self-check fixture file itself is missing, malformed, or invalid."""


@dataclass(frozen=True)
class PolicySelfCheckFailure:
    fixture: str
    expected: FirewallDecision
    actual: FirewallDecision
    reason: DecisionReason  # the engine's actual reason code


class PolicySelfCheckFixture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    case: PolicyEvaluationRequest
    tool_policy: ToolPolicy | None = None
    expected_decision: FirewallDecision
    expected_reason: DecisionReason | None = None


class PolicySelfCheckFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixtures: list[PolicySelfCheckFixture] = Field(min_length=1)


def load_policy_self_checks(path: str | Path) -> list[PolicySelfCheckFixture]:
    """Load and strictly validate the fixture file."""
    fixture_path = Path(path)
    try:
        raw_text = fixture_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicySelfCheckConfigError(
            f"policy self-check file {fixture_path} cannot be read: {exc}"
        ) from exc
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PolicySelfCheckConfigError(
            f"policy self-check file {fixture_path} is not valid YAML"
        ) from exc
    try:
        document = PolicySelfCheckFile.model_validate(data)
    except ValidationError as exc:
        raise PolicySelfCheckConfigError(
            f"policy self-check file {fixture_path} failed strict validation: "
            f"{exc.error_count()} error(s)"
        ) from exc
    seen: set[str] = set()
    for fixture in document.fixtures:
        if fixture.name in seen:
            raise PolicySelfCheckConfigError(
                f"policy self-check file {fixture_path} contains duplicate fixture name "
                f"{fixture.name!r}"
            )
        seen.add(fixture.name)
    return document.fixtures


def run_policy_self_checks(
    fixtures: list[PolicySelfCheckFixture], bundle: PolicyBundle
) -> list[PolicySelfCheckFailure]:
    """Evaluate every fixture against the bundle; return all mismatches (empty = pass)."""
    failures: list[PolicySelfCheckFailure] = []
    for fixture in fixtures:
        scoped = bundle
        if fixture.tool_policy is not None:
            scoped = bundle.with_tool_policy(fixture.case.tool_id, fixture.tool_policy)
        record = PolicyEngine(scoped).evaluate(fixture.case)
        reason_mismatch = (
            fixture.expected_reason is not None and record.reason != fixture.expected_reason
        )
        if record.decision != fixture.expected_decision or reason_mismatch:
            failures.append(
                PolicySelfCheckFailure(
                    fixture=fixture.name,
                    expected=fixture.expected_decision,
                    actual=record.decision,
                    reason=record.reason,
                )
            )
    return failures


def check_policy_self_checks(
    policies_path: str | Path, risk_thresholds_path: str | Path, fixtures_path: str | Path
) -> list[PolicySelfCheckFailure]:
    """Load policy documents + fixtures and evaluate (raises ``PolicyConfigError``/
    ``PolicySelfCheckConfigError`` when either configuration is invalid)."""
    bundle = load_policy_bundle(policies_path, risk_thresholds_path)
    fixtures = load_policy_self_checks(fixtures_path)
    return run_policy_self_checks(fixtures, bundle)


def policy_self_checks_pass(
    policies_path: str | Path, risk_thresholds_path: str | Path, fixtures_path: str | Path
) -> bool:
    """Never-raising probe: invalid/missing configuration is a failure."""
    try:
        return not check_policy_self_checks(policies_path, risk_thresholds_path, fixtures_path)
    except (PolicyConfigError, PolicySelfCheckConfigError):
        return False


@dataclass(frozen=True)
class PolicyReadinessReport:
    """Readiness-shaped policy report (ADR-007: expose version/hash in health metadata)."""

    ok: bool
    policy_version: str | None
    policy_hash: str | None


def evaluate_policy_readiness(
    policies_path: str | Path, risk_thresholds_path: str | Path, fixtures_path: str | Path
) -> PolicyReadinessReport:
    """Readiness probe: reload both documents + fixtures live; never raises.

    Invalid policy configuration reports no version/hash; a valid policy with broken
    fixtures or mismatches still reports the loaded version/hash with ``ok=False``.
    """
    try:
        bundle = load_policy_bundle(policies_path, risk_thresholds_path)
    except PolicyConfigError:
        return PolicyReadinessReport(ok=False, policy_version=None, policy_hash=None)
    try:
        fixtures = load_policy_self_checks(fixtures_path)
    except PolicySelfCheckConfigError:
        return PolicyReadinessReport(
            ok=False, policy_version=bundle.version, policy_hash=bundle.combined_hash
        )
    return PolicyReadinessReport(
        ok=not run_policy_self_checks(fixtures, bundle),
        policy_version=bundle.version,
        policy_hash=bundle.combined_hash,
    )

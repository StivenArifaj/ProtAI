"""Policy self-check fixtures and interim matrix tests (ADR-007; blueprint 10.3).

The repository fixture file must load strictly and pass completely; the loader must
reject every malformed shape; the runner must detect decision and reason mismatches; and
the interim matrix must respect the documented risk boundaries and hard constraints.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_security.policy.interim_matrix import (
    Decision,
    PolicyInput,
    evaluate,
)
from ai_security.policy.self_checks import (
    PolicySelfCheckConfigError,
    PolicySelfCheckFixture,
    check_policy_self_checks,
    load_policy_self_checks,
    policy_self_checks_pass,
    run_policy_self_checks,
)

REPO_FIXTURE_PATH = Path("config/policy_self_checks.yaml")

# The seven matrix behaviors the Phase 0b plan mandates as mandatory regression anchors.
MANDATED_FIXTURE_NAMES = {
    "allowed-mock-read",
    "forbidden-external-egress",
    "cross-user-resource-denial",
    "unknown-tool-denial",
    "invalid-argument-denial",
    "restricted-data-egress-block",
    "hard-deny-low-risk",
}

VALID_FIXTURE_YAML = """
fixtures:
  - name: read-allowed
    case: {tool_id: mock.read, side_effect_class: READ_ONLY, data_class: PUBLIC, risk: 0}
    expected_decision: ALLOW
"""


def read_case(**overrides: object) -> PolicyInput:
    values: dict[str, object] = {
        "tool_id": "mock.read",
        "side_effect_class": "READ_ONLY",
        "data_class": "INTERNAL",
        "risk": 10,
    }
    values.update(overrides)
    return PolicyInput(**values)


def write_fixture_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy_self_checks.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_repository_fixture_file_passes_completely() -> None:
    assert check_policy_self_checks(REPO_FIXTURE_PATH) == []


def test_repository_fixture_file_contains_mandated_rows() -> None:
    fixtures = load_policy_self_checks(REPO_FIXTURE_PATH)
    names = {fixture.name for fixture in fixtures}
    assert MANDATED_FIXTURE_NAMES <= names
    assert len(fixtures) >= len(MANDATED_FIXTURE_NAMES)


def test_runner_detects_decision_mismatch() -> None:
    fixture = PolicySelfCheckFixture(
        name="wrong-decision", case=read_case(), expected_decision="BLOCK"
    )
    failures = run_policy_self_checks([fixture])
    assert len(failures) == 1
    failure = failures[0]
    assert failure.fixture == "wrong-decision"
    assert failure.expected is Decision.block
    assert failure.actual is Decision.allow
    assert failure.reason == "authorized_read"


def test_runner_detects_reason_mismatch_and_ignores_absent_reason() -> None:
    wrong_reason = PolicySelfCheckFixture(
        name="wrong-reason",
        case=read_case(),
        expected_decision="ALLOW",
        expected_reason="authorized_read_v2",
    )
    failures = run_policy_self_checks([wrong_reason])
    assert len(failures) == 1
    assert failures[0].reason == "authorized_read"

    unconstrained = PolicySelfCheckFixture(
        name="no-reason", case=read_case(), expected_decision="ALLOW"
    )
    assert run_policy_self_checks([unconstrained]) == []


@pytest.mark.parametrize(
    "yaml_text",
    [
        pytest.param("", id="empty-file"),
        pytest.param("fixtures: [", id="malformed-yaml"),
        pytest.param("- name: x", id="root-not-mapping"),
        pytest.param("fixtures: []", id="empty-fixtures"),
        pytest.param(f"{VALID_FIXTURE_YAML}\nextra_root_key: true", id="unknown-root-key"),
        pytest.param(
            VALID_FIXTURE_YAML.replace("    expected_decision: ALLOW", ""), id="missing-decision"
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace(
                "    expected_decision: ALLOW", "    expected_decision: ALLOW\n    surprise: 1"
            ),
            id="unknown-fixture-key",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace("side_effect_class: READ_ONLY", "side_effect_class: SHELL"),
            id="invalid-side-effect-enum",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace("data_class: PUBLIC", "data_class: TOP_SECRET"),
            id="invalid-data-class-enum",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace("risk: 0", "risk: 150"),
            id="risk-out-of-range",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace("risk: 0", "risk: 0\n      unexpected_case_key: 1"),
            id="unknown-case-key",
        ),
        pytest.param(
            VALID_FIXTURE_YAML
            + """
  - name: read-allowed
    case: {tool_id: mock.read, side_effect_class: READ_ONLY, data_class: PUBLIC, risk: 0}
    expected_decision: ALLOW
""",
            id="duplicate-fixture-names",
        ),
    ],
)
def test_loader_rejects_invalid_configuration(tmp_path: Path, yaml_text: str) -> None:
    path = write_fixture_file(tmp_path, yaml_text)
    with pytest.raises(PolicySelfCheckConfigError):
        load_policy_self_checks(path)


def test_loader_accepts_valid_file(tmp_path: Path) -> None:
    path = write_fixture_file(tmp_path, VALID_FIXTURE_YAML)
    fixtures = load_policy_self_checks(path)
    assert [fixture.name for fixture in fixtures] == ["read-allowed"]


def test_missing_file_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(PolicySelfCheckConfigError):
        load_policy_self_checks(tmp_path / "absent.yaml")


def test_pass_probe_never_raises() -> None:
    assert policy_self_checks_pass(REPO_FIXTURE_PATH) is True


def test_pass_probe_false_for_missing_file(tmp_path: Path) -> None:
    assert policy_self_checks_pass(tmp_path / "absent.yaml") is False


def test_pass_probe_false_for_tampered_file(tmp_path: Path) -> None:
    path = write_fixture_file(
        tmp_path, VALID_FIXTURE_YAML.replace("expected_decision: ALLOW", "expected_decision: BLOCK")
    )
    assert policy_self_checks_pass(path) is False


def test_policy_input_rejects_invalid_enums_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        PolicyInput(tool_id="m", side_effect_class="SHELL", data_class="PUBLIC", risk=0)
    with pytest.raises(ValidationError):
        PolicyInput(tool_id="m", side_effect_class="READ_ONLY", data_class="PUBLIC", risk=0, nope=1)


@pytest.mark.parametrize(
    ("risk", "expected", "reason"),
    [
        (0, Decision.allow, "authorized_read"),
        (39, Decision.allow, "authorized_read"),
        (40, Decision.block, "approval_not_eligible"),
        (79, Decision.block, "approval_not_eligible"),
        (80, Decision.block, "risk_too_high"),
        (100, Decision.block, "risk_too_high"),
    ],
)
def test_read_only_risk_boundaries(risk: int, expected: Decision, reason: str) -> None:
    decision = evaluate(read_case(risk=risk, data_class="PUBLIC"))
    assert decision.decision is expected
    assert decision.reason == reason


def test_read_only_mid_risk_approval_eligible_asks() -> None:
    decision = evaluate(read_case(risk=55, approval_eligible=True))
    assert decision.decision is Decision.ask_user
    assert decision.reason == "risk_requires_clarification"


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"hard_deny": True}, "hard_denied"),
        ({"tool_known": False}, "unknown_tool"),
        ({"arguments_valid": False}, "invalid_arguments"),
        ({"resource_authorized": False}, "resource_not_authorized"),
    ],
)
def test_hard_constraints_dominate_score_and_eligibility(
    overrides: dict[str, object], reason: str
) -> None:
    decision = evaluate(read_case(risk=0, data_class="PUBLIC", approval_eligible=True, **overrides))
    assert decision.decision is Decision.block
    assert decision.reason == reason

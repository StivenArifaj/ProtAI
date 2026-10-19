"""Policy self-check fixtures against the real engine (ADR-007; blueprint 10.3-10.7).

The repository fixture file must load strictly and pass completely against the real
policy documents and engine; the loader must reject every malformed shape; the runner
must detect decision and reason mismatches; and the readiness probe must expose the
loaded policy version/hash while staying fail-closed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.policy_engine import PolicyEvaluationRequest
from ai_security.policy.loader import PolicyConfigError, load_policy_bundle
from ai_security.policy.models import ToolPolicy
from ai_security.policy.self_checks import (
    PolicySelfCheckConfigError,
    PolicySelfCheckFailure,
    PolicySelfCheckFixture,
    check_policy_self_checks,
    evaluate_policy_readiness,
    load_policy_self_checks,
    policy_self_checks_pass,
    run_policy_self_checks,
)

REPO_POLICIES = Path("config/policies.yaml")
REPO_THRESHOLDS = Path("config/risk_thresholds.yaml")
REPO_FIXTURES = Path("config/policy_self_checks.yaml")

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

# Scenario-override fixtures (blueprint section 10.5 "dedicated test scenario").
SCENARIO_FIXTURE_NAMES = {
    "allowed-allowlisted-external-call",
    "allowed-explicit-local-write",
    "external-egress-disabled-by-default",
}

VALID_FIXTURE_YAML = """
fixtures:
  - name: read-allowed
    case:
      tool_id: mock_email.read
      side_effect_class: READ_ONLY
      data_class: PUBLIC
      risk_score: 0
    expected_decision: ALLOW
"""


def repo_bundle():  # type: ignore[no-untyped-def]
    return load_policy_bundle(REPO_POLICIES, REPO_THRESHOLDS)


def read_case(**overrides: object) -> PolicyEvaluationRequest:
    values: dict[str, object] = {
        "tool_id": "mock_email.read",
        "side_effect_class": "READ_ONLY",
        "data_class": "INTERNAL",
        "risk_score": 10,
    }
    values.update(overrides)
    return PolicyEvaluationRequest(**values)


def write_fixture_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy_self_checks.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# -- repository fixtures --------------------------------------------------------------


def test_repository_fixture_file_passes_completely() -> None:
    assert check_policy_self_checks(REPO_POLICIES, REPO_THRESHOLDS, REPO_FIXTURES) == []


def test_repository_fixture_file_contains_mandated_and_scenario_rows() -> None:
    fixtures = load_policy_self_checks(REPO_FIXTURES)
    names = {fixture.name for fixture in fixtures}
    assert MANDATED_FIXTURE_NAMES <= names
    assert SCENARIO_FIXTURE_NAMES <= names
    assert len(fixtures) >= len(MANDATED_FIXTURE_NAMES)


def test_repository_fixtures_carry_loadable_cases_and_reasons() -> None:
    for fixture in load_policy_self_checks(REPO_FIXTURES):
        assert isinstance(fixture.case, PolicyEvaluationRequest)
        assert isinstance(fixture.expected_decision, FirewallDecision)


# -- runner ---------------------------------------------------------------------------


def test_runner_detects_decision_mismatch() -> None:
    fixture = PolicySelfCheckFixture(
        name="wrong-decision", case=read_case(risk_score=0), expected_decision="BLOCK"
    )
    failures = run_policy_self_checks([fixture], repo_bundle())
    assert len(failures) == 1
    failure = failures[0]
    assert isinstance(failure, PolicySelfCheckFailure)
    assert failure.fixture == "wrong-decision"
    assert failure.expected is FirewallDecision.block
    assert failure.actual is FirewallDecision.allow
    assert failure.reason is DecisionReason.authorized_read


def test_runner_detects_reason_mismatch_and_ignores_absent_reason() -> None:
    wrong_reason = PolicySelfCheckFixture(
        name="wrong-reason",
        case=read_case(risk_score=0),
        expected_decision="ALLOW",
        expected_reason="risk_too_high",
    )
    failures = run_policy_self_checks([wrong_reason], repo_bundle())
    assert len(failures) == 1
    assert failures[0].reason is DecisionReason.authorized_read

    unconstrained = PolicySelfCheckFixture(
        name="no-reason", case=read_case(risk_score=0), expected_decision="ALLOW"
    )
    assert run_policy_self_checks([unconstrained], repo_bundle()) == []


def test_runner_applies_fixture_tool_policy_override_without_touching_bundle() -> None:
    fixture = PolicySelfCheckFixture(
        name="scenario-egress",
        tool_policy=ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=("https://sink.internal.example/collect",),
        ),
        case=PolicyEvaluationRequest(
            tool_id="mock_external_sink.write",
            side_effect_class="EXTERNAL_MUTATION",
            data_class="PUBLIC",
            risk_score=10,
            destination="https://sink.internal.example/collect",
        ),
        expected_decision="ALLOW",
        expected_reason="allowlisted_external_call",
    )
    bundle = repo_bundle()
    assert run_policy_self_checks([fixture], bundle) == []
    assert bundle.tool_policy("mock_external_sink.write") is not None
    assert not bundle.tool_policy("mock_external_sink.write").external_egress_enabled


# -- loader strictness ----------------------------------------------------------------


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
            VALID_FIXTURE_YAML.replace("risk_score: 0", "risk_score: 150"),
            id="risk-out-of-range",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace("risk_score: 0", 'risk_score: "5"'),
            id="risk-string-not-coerced",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace("risk_score: 0", "risk_score: 0\n      nope: 1"),
            id="unknown-case-key",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace("tool_id: mock_email.read", "tool_id: 'bad id'"),
            id="malformed-tool-id",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace(
                "    expected_decision: ALLOW",
                "    expected_decision: ALLOW\n    expected_reason: authorized_read_v2",
            ),
            id="unknown-reason-code",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace(
                "    case:",
                "    tool_policy: {side_effect_class: READ_ONLY, external_egress_enabled: true}\n"
                "    case:",
            ),
            id="invalid-tool-policy-override",
        ),
        pytest.param(
            VALID_FIXTURE_YAML.replace(
                "    case:",
                "    tool_policy:\n      side_effect_class: EXTERNAL_MUTATION\n"
                '      allowed_destinations: ["http://sink.example/collect"]\n'
                "    case:",
            ),
            id="non-https-override-destination",
        ),
        pytest.param(
            VALID_FIXTURE_YAML
            + """
  - name: read-allowed
    case:
      tool_id: mock_email.read
      side_effect_class: READ_ONLY
      data_class: PUBLIC
      risk_score: 0
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


# -- check / pass probes --------------------------------------------------------------


def test_check_raises_for_invalid_policy_documents(tmp_path: Path) -> None:
    bad_policies = tmp_path / "policies.yaml"
    bad_policies.write_text("schema_version: 2\nversion: v1\ntools: {}\n", encoding="utf-8")
    with pytest.raises(PolicyConfigError):
        check_policy_self_checks(bad_policies, REPO_THRESHOLDS, REPO_FIXTURES)


def test_pass_probe_true_for_repository_configuration() -> None:
    assert policy_self_checks_pass(REPO_POLICIES, REPO_THRESHOLDS, REPO_FIXTURES) is True


def test_pass_probe_false_for_missing_files(tmp_path: Path) -> None:
    absent = tmp_path / "absent.yaml"
    assert policy_self_checks_pass(absent, REPO_THRESHOLDS, REPO_FIXTURES) is False
    assert policy_self_checks_pass(REPO_POLICIES, REPO_THRESHOLDS, absent) is False


def test_pass_probe_false_for_tampered_expectation(tmp_path: Path) -> None:
    path = write_fixture_file(
        tmp_path, VALID_FIXTURE_YAML.replace("expected_decision: ALLOW", "expected_decision: BLOCK")
    )
    assert policy_self_checks_pass(REPO_POLICIES, REPO_THRESHOLDS, path) is False


def test_pass_probe_false_for_tampered_policy_drift(tmp_path: Path) -> None:
    drifted = tmp_path / "policies.yaml"
    drifted.write_text(
        "schema_version: 1\nversion: dev-2\ntools: {}\n",
        encoding="utf-8",
    )
    assert policy_self_checks_pass(drifted, REPO_THRESHOLDS, REPO_FIXTURES) is False


# -- readiness ------------------------------------------------------------------------


def test_readiness_reports_ok_version_and_hash_for_repository_configuration() -> None:
    report = evaluate_policy_readiness(REPO_POLICIES, REPO_THRESHOLDS, REPO_FIXTURES)
    assert report.ok is True
    assert report.policy_version == "dev-1"
    assert report.policy_hash is not None
    assert len(report.policy_hash) == 64


def test_readiness_is_fail_closed_without_version_for_invalid_policies(tmp_path: Path) -> None:
    report = evaluate_policy_readiness(tmp_path / "absent.yaml", REPO_THRESHOLDS, REPO_FIXTURES)
    assert report.ok is False
    assert report.policy_version is None
    assert report.policy_hash is None


def test_readiness_reports_version_with_ok_false_for_broken_fixtures(tmp_path: Path) -> None:
    path = write_fixture_file(
        tmp_path, VALID_FIXTURE_YAML.replace("expected_decision: ALLOW", "expected_decision: BLOCK")
    )
    report = evaluate_policy_readiness(REPO_POLICIES, REPO_THRESHOLDS, path)
    assert report.ok is False
    assert report.policy_version == "dev-1"
    assert report.policy_hash is not None

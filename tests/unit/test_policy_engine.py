"""Table-driven deterministic policy engine tests (blueprint sections 10.2-10.3, 21).

Covers the required categories: allowed, forbidden, malformed, cross-scope, unknown,
and error cases — plus fail-closed ordering, configurable thresholds, provenance, and
determinism. The engine performs no I/O and consults only the loaded bundle.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.policy_engine import PolicyEngine, PolicyEvaluationRequest
from ai_security.policy.models import (
    PoliciesDocument,
    PolicyBundle,
    RiskThresholdsDocument,
    Thresholds,
    ToolPolicy,
)

DEST = "https://sink.internal.example/collect"
EVIL_DEST = "https://evil.example/collect"

READ_TOOL = "mock_email.read"
LOCAL_TOOL = "mock_files.write"
EXTERNAL_TOOL = "mock_external_sink.write"
DESTRUCTIVE_TOOL = "mock_files.delete"

BASE_TOOLS: dict[str, dict[str, object]] = {
    READ_TOOL: {"side_effect_class": "READ_ONLY"},
    "mock_files.read": {"side_effect_class": "READ_ONLY"},
    LOCAL_TOOL: {"side_effect_class": "LOCAL_MUTATION"},
    EXTERNAL_TOOL: {"side_effect_class": "EXTERNAL_MUTATION"},
}

ENABLED_EGRESS: dict[str, object] = {
    "side_effect_class": "EXTERNAL_MUTATION",
    "external_egress_enabled": True,
    "allowed_destinations": (DEST,),
}

ALLOW = FirewallDecision.allow
ASK = FirewallDecision.ask_user
BLOCK = FirewallDecision.block


def make_bundle(
    tool_overrides: dict[str, dict[str, object]] | None = None,
    *,
    ask: int = 40,
    block: int = 80,
) -> PolicyBundle:
    tools = {tool_id: dict(policy) for tool_id, policy in BASE_TOOLS.items()}
    for tool_id, update in (tool_overrides or {}).items():
        tools[tool_id] = dict(update)
    return PolicyBundle(
        policies=PoliciesDocument(
            schema_version=1,
            version="test-1",
            tools={tool_id: ToolPolicy(**policy) for tool_id, policy in tools.items()},
        ),
        risk_thresholds=RiskThresholdsDocument(
            schema_version=1,
            version="th-1",
            thresholds=Thresholds(ask_user_at_or_above=ask, block_at_or_above=block),
        ),
        policies_sha256="a" * 64,
        thresholds_sha256="b" * 64,
    )


def read_policy(**overrides: object) -> dict[str, object]:
    return {"side_effect_class": "READ_ONLY", **overrides}


def local_policy(**overrides: object) -> dict[str, object]:
    return {"side_effect_class": "LOCAL_MUTATION", **overrides}


def read_case(**overrides: object) -> dict[str, object]:
    return {
        "tool_id": READ_TOOL,
        "side_effect_class": "READ_ONLY",
        "data_class": "INTERNAL",
        "risk_score": 10,
        **overrides,
    }


def local_case(**overrides: object) -> dict[str, object]:
    return {
        "tool_id": LOCAL_TOOL,
        "side_effect_class": "LOCAL_MUTATION",
        "data_class": "PUBLIC",
        "risk_score": 20,
        **overrides,
    }


def external_case(**overrides: object) -> dict[str, object]:
    return {
        "tool_id": EXTERNAL_TOOL,
        "side_effect_class": "EXTERNAL_MUTATION",
        "data_class": "PUBLIC",
        "risk_score": 5,
        "destination": DEST,
        **overrides,
    }


def destructive_case(**overrides: object) -> dict[str, object]:
    return {
        "tool_id": DESTRUCTIVE_TOOL,
        "side_effect_class": "DESTRUCTIVE",
        "data_class": "PUBLIC",
        "risk_score": 0,
        **overrides,
    }


def decide(
    bundle: PolicyBundle, case: dict[str, object]
) -> tuple[FirewallDecision, DecisionReason]:
    record = PolicyEngine(bundle).evaluate(PolicyEvaluationRequest(**case))
    return record.decision, record.reason


# -- matrix + hard-constraint table ---------------------------------------------------

MATRIX_CASES: list[
    tuple[
        str,
        dict[str, dict[str, object]],
        dict[str, object],
        FirewallDecision,
        DecisionReason,
    ]
] = [
    # READ_ONLY rows
    (
        "read-low-risk",
        {},
        read_case(data_class="PUBLIC", risk_score=0),
        ALLOW,
        DecisionReason.authorized_read,
    ),
    (
        "read-low-boundary-39",
        {},
        read_case(risk_score=39),
        ALLOW,
        DecisionReason.authorized_read,
    ),
    (
        "read-mid-40-not-eligible",
        {},
        read_case(risk_score=40),
        BLOCK,
        DecisionReason.approval_not_eligible,
    ),
    (
        "read-mid-79-not-eligible",
        {},
        read_case(risk_score=79),
        BLOCK,
        DecisionReason.approval_not_eligible,
    ),
    (
        "read-mid-40-eligible",
        {READ_TOOL: read_policy(approval_eligible=True)},
        read_case(risk_score=40),
        ASK,
        DecisionReason.risk_requires_clarification,
    ),
    (
        "read-mid-79-eligible",
        {READ_TOOL: read_policy(approval_eligible=True)},
        read_case(risk_score=79),
        ASK,
        DecisionReason.risk_requires_clarification,
    ),
    (
        "read-high-80-eligible-still-blocks",
        {READ_TOOL: read_policy(approval_eligible=True)},
        read_case(risk_score=80),
        BLOCK,
        DecisionReason.risk_too_high,
    ),
    ("read-high-100", {}, read_case(risk_score=100), BLOCK, DecisionReason.risk_too_high),
    # LOCAL_MUTATION rows
    (
        "local-public-low-permitted",
        {LOCAL_TOOL: local_policy(explicitly_permitted=True)},
        local_case(),
        ALLOW,
        DecisionReason.explicitly_permitted_local_write,
    ),
    (
        "local-public-low-not-permitted",
        {},
        local_case(),
        BLOCK,
        DecisionReason.explicit_permission_required,
    ),
    (
        "local-internal-low-not-permitted",
        {},
        local_case(data_class="INTERNAL"),
        BLOCK,
        DecisionReason.explicit_permission_required,
    ),
    (
        "local-mid-eligible",
        {LOCAL_TOOL: local_policy(approval_eligible=True)},
        local_case(data_class="INTERNAL", risk_score=55),
        ASK,
        DecisionReason.risk_requires_clarification,
    ),
    (
        "local-mid-not-eligible",
        {},
        local_case(risk_score=55),
        BLOCK,
        DecisionReason.approval_not_eligible,
    ),
    (
        "local-high-permitted-still-blocks",
        {LOCAL_TOOL: local_policy(explicitly_permitted=True)},
        local_case(risk_score=80),
        BLOCK,
        DecisionReason.risk_too_high,
    ),
    (
        "local-confidential-low-eligible",
        {LOCAL_TOOL: local_policy(approval_eligible=True)},
        local_case(data_class="CONFIDENTIAL", risk_score=10),
        ASK,
        DecisionReason.confidential_write_requires_approval,
    ),
    (
        "local-confidential-mid-not-eligible",
        {},
        local_case(data_class="CONFIDENTIAL", risk_score=50),
        BLOCK,
        DecisionReason.approval_not_eligible,
    ),
    (
        "local-confidential-high-eligible-still-blocks",
        {LOCAL_TOOL: local_policy(approval_eligible=True)},
        local_case(data_class="CONFIDENTIAL", risk_score=80),
        BLOCK,
        DecisionReason.risk_too_high,
    ),
    (
        "local-restricted-blocks-with-every-flag",
        {LOCAL_TOOL: local_policy(explicitly_permitted=True, approval_eligible=True)},
        local_case(data_class="RESTRICTED", risk_score=0),
        BLOCK,
        DecisionReason.restricted_write_not_registered,
    ),
    # EXTERNAL_MUTATION rows (PUBLIC)
    (
        "external-disabled",
        {},
        external_case(),
        BLOCK,
        DecisionReason.external_egress_disabled,
    ),
    (
        "external-disabled-without-destination",
        {},
        external_case(risk_score=5, destination=None),
        BLOCK,
        DecisionReason.external_egress_disabled,
    ),
    (
        "external-enabled-not-allowlisted",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(destination=EVIL_DEST),
        BLOCK,
        DecisionReason.destination_not_allowlisted,
    ),
    (
        "external-enabled-without-destination",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(destination=None),
        BLOCK,
        DecisionReason.destination_not_allowlisted,
    ),
    (
        "external-allowlisted-low",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(),
        ALLOW,
        DecisionReason.allowlisted_external_call,
    ),
    (
        "external-allowlisted-mid-not-eligible",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(risk_score=40),
        BLOCK,
        DecisionReason.approval_not_eligible,
    ),
    (
        "external-allowlisted-mid-eligible",
        {EXTERNAL_TOOL: {**ENABLED_EGRESS, "approval_eligible": True}},
        external_case(risk_score=40),
        ASK,
        DecisionReason.risk_requires_clarification,
    ),
    (
        "external-high-blocks-before-egress-config",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(risk_score=80),
        BLOCK,
        DecisionReason.risk_too_high,
    ),
    (
        "external-high-disabled-still-risk-too-high",
        {},
        external_case(risk_score=90),
        BLOCK,
        DecisionReason.risk_too_high,
    ),
    # EXTERNAL_MUTATION rows (INTERNAL)
    (
        "internal-allowlisted-eligible",
        {EXTERNAL_TOOL: {**ENABLED_EGRESS, "approval_eligible": True}},
        external_case(data_class="INTERNAL", risk_score=20),
        ASK,
        DecisionReason.internal_egress_requires_approval,
    ),
    (
        "internal-allowlisted-not-eligible",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(data_class="INTERNAL", risk_score=20),
        BLOCK,
        DecisionReason.approval_not_eligible,
    ),
    (
        "internal-not-allowlisted",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(data_class="INTERNAL", risk_score=20, destination=EVIL_DEST),
        BLOCK,
        DecisionReason.internal_egress_requires_approved_destination,
    ),
    (
        "internal-disabled",
        {},
        external_case(data_class="INTERNAL", risk_score=20),
        BLOCK,
        DecisionReason.internal_egress_requires_approved_destination,
    ),
    (
        "internal-high-blocks",
        {EXTERNAL_TOOL: {**ENABLED_EGRESS, "approval_eligible": True}},
        external_case(data_class="INTERNAL", risk_score=80),
        BLOCK,
        DecisionReason.risk_too_high,
    ),
    # EXTERNAL_MUTATION rows (CONFIDENTIAL / RESTRICTED)
    (
        "confidential-egress-blocked-even-approved",
        {EXTERNAL_TOOL: {**ENABLED_EGRESS, "approval_eligible": True}},
        external_case(data_class="CONFIDENTIAL", risk_score=10),
        BLOCK,
        DecisionReason.confidential_egress_blocked,
    ),
    (
        "restricted-egress-blocked-even-approved",
        {EXTERNAL_TOOL: {**ENABLED_EGRESS, "approval_eligible": True}},
        external_case(data_class="RESTRICTED", risk_score=10),
        BLOCK,
        DecisionReason.restricted_egress_blocked,
    ),
    # DESTRUCTIVE
    (
        "destructive-low-risk-blocks",
        {DESTRUCTIVE_TOOL: {"side_effect_class": "DESTRUCTIVE"}},
        destructive_case(),
        BLOCK,
        DecisionReason.destructive_not_registered,
    ),
    # Hard constraints dominate score, eligibility, and data class
    (
        "principal-not-resolved",
        {},
        read_case(data_class="PUBLIC", risk_score=0, principal_resolved=False),
        BLOCK,
        DecisionReason.principal_not_resolved,
    ),
    (
        "unknown-tool-low-risk",
        {},
        {
            "tool_id": "shell.exec",
            "side_effect_class": "READ_ONLY",
            "data_class": "PUBLIC",
            "risk_score": 0,
        },
        BLOCK,
        DecisionReason.unknown_tool,
    ),
    (
        "unknown-tool-beats-hard-deny-order",
        {},
        {
            "tool_id": "shell.exec",
            "side_effect_class": "DESTRUCTIVE",
            "data_class": "RESTRICTED",
            "risk_score": 0,
            "hard_deny": True,
        },
        BLOCK,
        DecisionReason.unknown_tool,
    ),
    (
        "declared-class-mismatch",
        {},
        read_case(side_effect_class="LOCAL_MUTATION", risk_score=0),
        BLOCK,
        DecisionReason.side_effect_class_mismatch,
    ),
    (
        "invalid-arguments",
        {},
        read_case(data_class="PUBLIC", risk_score=0, arguments_valid=False),
        BLOCK,
        DecisionReason.invalid_arguments,
    ),
    (
        "invalid-arguments-beats-hard-deny-order",
        {},
        read_case(risk_score=0, arguments_valid=False, hard_deny=True),
        BLOCK,
        DecisionReason.invalid_arguments,
    ),
    (
        "hard-deny-with-zero-risk-and-eligibility",
        {READ_TOOL: read_policy(approval_eligible=True)},
        read_case(data_class="PUBLIC", risk_score=0, hard_deny=True),
        BLOCK,
        DecisionReason.hard_denied,
    ),
    (
        "cross-scope-resource-not-authorized",
        {},
        read_case(data_class="PUBLIC", risk_score=0, resource_authorized=False),
        BLOCK,
        DecisionReason.resource_not_authorized,
    ),
    (
        "malformed-destination",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(destination="http://sink.internal.example/collect"),
        BLOCK,
        DecisionReason.invalid_destination,
    ),
    (
        "destination-on-read-tool",
        {},
        read_case(data_class="PUBLIC", risk_score=0, destination=DEST),
        BLOCK,
        DecisionReason.invalid_destination,
    ),
    (
        "destination-on-local-tool",
        {LOCAL_TOOL: local_policy(explicitly_permitted=True)},
        local_case(destination=DEST),
        BLOCK,
        DecisionReason.invalid_destination,
    ),
    # Phase 2 gateway facts (ADR-009)
    (
        "binding-mismatch",
        {},
        read_case(data_class="PUBLIC", risk_score=0, binding_valid=False),
        BLOCK,
        DecisionReason.binding_mismatch,
    ),
    (
        "binding-mismatch-precedes-unknown-tool",
        {},
        read_case(
            tool_id="shell.exec",
            side_effect_class="DESTRUCTIVE",
            data_class="RESTRICTED",
            risk_score=0,
            binding_valid=False,
        ),
        BLOCK,
        DecisionReason.binding_mismatch,
    ),
    (
        "deadline-exceeded",
        {},
        read_case(data_class="PUBLIC", risk_score=0, deadline_exceeded=True),
        BLOCK,
        DecisionReason.deadline_exceeded,
    ),
    (
        "deadline-exceeded-precedes-resource-scope",
        {},
        read_case(
            data_class="PUBLIC", risk_score=0, deadline_exceeded=True, resource_authorized=False
        ),
        BLOCK,
        DecisionReason.deadline_exceeded,
    ),
    (
        "hard-deny-precedes-expired-deadline",
        {READ_TOOL: read_policy(approval_eligible=True)},
        read_case(data_class="PUBLIC", risk_score=0, hard_deny=True, deadline_exceeded=True),
        BLOCK,
        DecisionReason.hard_denied,
    ),
    (
        "destination-inconsistent",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(destination_consistent=False),
        BLOCK,
        DecisionReason.invalid_destination,
    ),
    (
        "destination-outside-registered-capability",
        {EXTERNAL_TOOL: ENABLED_EGRESS},
        external_case(destination_registered=False),
        BLOCK,
        DecisionReason.destination_not_allowlisted,
    ),
]


@pytest.mark.parametrize(
    ("tool_overrides", "request_case", "expected", "reason"),
    [
        pytest.param(overrides, request_case, expected, reason, id=case_id)
        for case_id, overrides, request_case, expected, reason in MATRIX_CASES
    ],
)
def test_matrix_cases(
    tool_overrides: dict[str, dict[str, object]],
    request_case: dict[str, object],
    expected: FirewallDecision,
    reason: DecisionReason,
) -> None:
    assert decide(make_bundle(tool_overrides), request_case) == (expected, reason)


def test_side_effect_class_mismatch_both_directions() -> None:
    external_as_read = decide(make_bundle(), external_case(side_effect_class="READ_ONLY"))
    assert external_as_read == (BLOCK, DecisionReason.side_effect_class_mismatch)
    local_as_read = decide(make_bundle(), local_case(side_effect_class="READ_ONLY"))
    assert local_as_read == (BLOCK, DecisionReason.side_effect_class_mismatch)


# -- thresholds are configuration-driven ----------------------------------------------


def test_thresholds_come_from_the_loaded_configuration() -> None:
    strict = make_bundle(ask=10, block=20)
    assert decide(strict, read_case(data_class="PUBLIC", risk_score=9)) == (
        ALLOW,
        DecisionReason.authorized_read,
    )
    assert decide(strict, read_case(data_class="PUBLIC", risk_score=10)) == (
        BLOCK,
        DecisionReason.approval_not_eligible,
    )
    eligible = make_bundle({READ_TOOL: read_policy(approval_eligible=True)}, ask=10, block=20)
    assert decide(eligible, read_case(risk_score=10)) == (
        ASK,
        DecisionReason.risk_requires_clarification,
    )
    assert decide(eligible, read_case(risk_score=19)) == (
        ASK,
        DecisionReason.risk_requires_clarification,
    )
    assert decide(eligible, read_case(risk_score=20)) == (
        BLOCK,
        DecisionReason.risk_too_high,
    )
    # The same request is ALLOW under the default 40/80 bands.
    assert decide(make_bundle(), read_case(data_class="PUBLIC", risk_score=20)) == (
        ALLOW,
        DecisionReason.authorized_read,
    )


# -- provenance, determinism, purity --------------------------------------------------


def test_decision_record_carries_policy_version_and_hash() -> None:
    bundle = make_bundle()
    record = PolicyEngine(bundle).evaluate(PolicyEvaluationRequest(**read_case()))
    assert record.decision is ALLOW
    assert record.policy_version == "test-1"
    assert record.policy_hash == bundle.combined_hash


def test_scenario_bundle_keeps_source_provenance() -> None:
    bundle = make_bundle()
    scenario = bundle.with_tool_policy(LOCAL_TOOL, ToolPolicy(side_effect_class="LOCAL_MUTATION"))
    record = PolicyEngine(scenario).evaluate(
        PolicyEvaluationRequest(**local_case(data_class="RESTRICTED", risk_score=0))
    )
    assert record.decision is BLOCK
    assert record.reason is DecisionReason.restricted_write_not_registered
    assert record.policy_version == bundle.version
    assert record.policy_hash == bundle.combined_hash


def test_evaluation_is_deterministic_and_pure() -> None:
    bundle = make_bundle()
    engine = PolicyEngine(bundle)
    first = engine.evaluate(PolicyEvaluationRequest(**read_case(risk_score=55)))
    second = PolicyEngine(make_bundle()).evaluate(
        PolicyEvaluationRequest(**read_case(risk_score=55))
    )
    assert first == second
    assert engine.bundle is bundle
    assert bundle.tool_policy(LOCAL_TOOL) is not None  # unchanged by evaluation


def test_decision_record_is_frozen() -> None:
    record = PolicyEngine(make_bundle()).evaluate(PolicyEvaluationRequest(**read_case()))
    with pytest.raises(ValidationError):
        record.decision = FirewallDecision.block  # type: ignore[misc]


# -- malformed requests fail validation (fail closed upstream) ------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"risk_score": 101}, id="risk-above-range"),
        pytest.param({"risk_score": -1}, id="risk-below-range"),
        pytest.param({"risk_score": "10"}, id="string-risk-not-coerced"),
        pytest.param({"risk_score": True}, id="bool-risk-not-coerced"),
        pytest.param({"side_effect_class": "SHELL"}, id="unknown-side-effect"),
        pytest.param({"data_class": "TOP_SECRET"}, id="unknown-data-class"),
        pytest.param({"extra_field": 1}, id="unknown-field"),
        pytest.param({"tool_id": "bad id"}, id="malformed-tool-id"),
        pytest.param({"tool_id": ""}, id="empty-tool-id"),
        pytest.param({"destination": ""}, id="empty-destination"),
        pytest.param({"destination": "x" * 2049}, id="destination-too-long"),
        pytest.param({"side_effect_class": "read_only"}, id="lowercase-enum-not-coerced"),
    ],
)
def test_malformed_requests_are_rejected(overrides: dict[str, object]) -> None:
    case = read_case()
    case.update(overrides)
    with pytest.raises(ValidationError):
        PolicyEvaluationRequest(**case)

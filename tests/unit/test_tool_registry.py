"""Tool registry validation tests (blueprint sections 12.2, 12.4, 14.1).

Capability drift is a startup failure: policy may not authorize an unregistered tool,
side-effect classes must agree, approval requirements must be satisfiable, and policy
destinations must lie inside the adapter's declared capability. Registrations absent
from the policy document remain registered but policy-disabled.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ConfigDict

from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.models import PolicyBundle, ToolPolicy
from ai_security.tools.base import SideEffectClass, ToolArguments
from ai_security.tools.mock_email import MockEmailAdapter
from ai_security.tools.mock_external_sink import (
    DESTINATION,
    MockExternalSinkAdapter,
    SinkStore,
)
from ai_security.tools.mock_files import MockFilesAdapter
from ai_security.tools.mock_text import MockTextAdapter
from ai_security.tools.registry import (
    ToolRegistration,
    ToolRegistry,
    ToolRegistryConfigError,
    build_registry,
)

POLICIES = Path("config/policies.yaml")
THRESHOLDS = Path("config/risk_thresholds.yaml")


def starter_bundle() -> PolicyBundle:
    return load_policy_bundle(POLICIES, THRESHOLDS)


def adapters() -> tuple[object, ...]:
    return (
        MockEmailAdapter(),
        MockFilesAdapter(),
        MockExternalSinkAdapter(SinkStore()),
        MockTextAdapter(),
    )


def text_registration() -> ToolRegistration:
    return MockTextAdapter().registrations()[0]


class StubAdapter:
    """Minimal adapter used to exercise registry validation rules."""

    def __init__(self, adapter_version: str, *registrations: ToolRegistration) -> None:
        self.adapter_version = adapter_version
        self._registrations = registrations

    def registrations(self) -> tuple[ToolRegistration, ...]:
        return self._registrations

    def check_resource_access(self, **kwargs: object) -> bool:
        return True

    async def execute(self, **kwargs: object) -> object:  # pragma: no cover - never called
        raise AssertionError("stub adapters never execute")


# -- positive paths -------------------------------------------------------------------


def test_builds_against_starter_policy_and_resolves_every_mvp_adapter() -> None:
    registry = build_registry(starter_bundle(), adapters())
    expected = {
        "mock_email.search",
        "mock_email.read",
        "mock_files.search",
        "mock_files.read",
        "text.summarize",
        "mock_external_sink.write",
    }
    assert {registration.tool_id for registration in registry.registrations()} == expected
    for tool_id in expected:
        registration = registry.resolve(tool_id, tool_id.rsplit(".", 1)[1])
        assert registration is not None
        assert registration.registration.tool_id == tool_id


def test_registrations_are_returned_in_deterministic_order() -> None:
    registry = build_registry(starter_bundle(), adapters())
    tool_ids = [registration.tool_id for registration in registry.registrations()]
    assert tool_ids == sorted(tool_ids)


def test_registration_absent_from_policy_is_registered_but_disabled() -> None:
    # Blueprint section 14.1 registers mock_files.search, while the starter policy
    # (section 10.5) intentionally enables only mock_files.read.
    registry = build_registry(starter_bundle(), adapters())
    assert registry.resolve("mock_files.search", "search") is not None
    assert "mock_files.search" not in starter_bundle().policies.tools


def test_unknown_resolution_returns_none() -> None:
    registry = build_registry(starter_bundle(), adapters())
    assert registry.resolve("mock_email.delete", "delete") is None
    assert registry.resolve("mock_email.read", "search") is None
    assert registry.resolve("Mock_Email.Read", "read") is None


def test_scenario_bundle_enabling_the_sink_is_consistent() -> None:
    bundle = starter_bundle().with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
        ),
    )
    registry = build_registry(bundle, adapters())
    assert registry.resolve("mock_external_sink.write", "write") is not None


# -- registration validation ----------------------------------------------------------


def test_rejects_duplicate_tool_ids_across_adapters() -> None:
    registration = text_registration()
    with pytest.raises(ToolRegistryConfigError, match="duplicate registration"):
        ToolRegistry(
            [
                StubAdapter("mock-text-v1", registration),
                StubAdapter("mock-text-v1", registration),
            ]
        )


def test_rejects_destructive_registration() -> None:
    with pytest.raises(ToolRegistryConfigError, match="DESTRUCTIVE"):
        replace(text_registration(), side_effect_class=SideEffectClass.destructive)


def test_rejects_argument_schema_without_extra_forbid() -> None:
    class LooseArguments(ToolArguments):
        model_config = ConfigDict(extra="ignore", frozen=True)

    with pytest.raises(ToolRegistryConfigError, match="extra='forbid'"):
        replace(text_registration(), argument_schema=LooseArguments)


def test_rejects_unknown_resource_argument() -> None:
    with pytest.raises(ToolRegistryConfigError, match="resource_id_arguments"):
        replace(text_registration(), resource_id_arguments=("email_id",))


def test_rejects_destinations_without_destination_argument() -> None:
    sink_registration = MockExternalSinkAdapter(SinkStore()).registrations()[0]
    with pytest.raises(ToolRegistryConfigError, match="destination_argument"):
        replace(
            sink_registration,
            side_effect_class=SideEffectClass.read_only,
            destination_argument=None,
        )


def test_rejects_non_canonical_destination() -> None:
    sink_registration = MockExternalSinkAdapter(SinkStore()).registrations()[0]
    with pytest.raises(ToolRegistryConfigError, match="canonical"):
        replace(
            sink_registration,
            destinations=("https://MOCK-SINK.invalid:443/collect",),
        )


def test_rejects_destination_argument_on_non_egress_tool() -> None:
    sink_registration = MockExternalSinkAdapter(SinkStore()).registrations()[0]
    with pytest.raises(ToolRegistryConfigError, match="only EXTERNAL_MUTATION"):
        replace(sink_registration, side_effect_class=SideEffectClass.read_only)


@pytest.mark.parametrize(
    "field,value",
    [
        ("timeout_ms", 0),
        ("timeout_ms", 60_001),
        ("timeout_ms", True),
        ("max_concurrent_invocations", 0),
        ("max_concurrent_invocations", 65),
        ("max_result_bytes", 0),
        ("max_result_bytes", 1_048_577),
    ],
)
def test_rejects_out_of_range_bounds(field: str, value: object) -> None:
    with pytest.raises(ToolRegistryConfigError, match=field):
        replace(text_registration(), **{field: value})


def test_rejects_approval_required_without_approver_rule() -> None:
    with pytest.raises(ToolRegistryConfigError, match="required_approver_rule"):
        replace(
            text_registration(),
            approval_required=True,
            required_approver_rule=None,
        )


def test_rejects_approver_rule_without_approval_required() -> None:
    with pytest.raises(ToolRegistryConfigError, match="only meaningful"):
        replace(text_registration(), required_approver_rule="role:admin")


def test_rejects_malformed_approver_rule_at_registration() -> None:
    with pytest.raises(ToolRegistryConfigError, match="invalid required_approver_rule"):
        replace(
            text_registration(),
            approval_required=True,
            required_approver_rule="admin",
        )


def test_rejects_adapter_version_mismatch() -> None:
    registration = replace(text_registration(), adapter_version="stub-v1")
    with pytest.raises(ToolRegistryConfigError, match="adapter_version"):
        ToolRegistry([StubAdapter("stub-v2", registration)])


# -- registry/policy consistency -------------------------------------------------------


def test_rejects_policy_tool_without_registration() -> None:
    bundle = starter_bundle().with_tool_policy(
        "mock_files.write", ToolPolicy(side_effect_class="LOCAL_MUTATION")
    )
    with pytest.raises(ToolRegistryConfigError, match="no registered adapter"):
        build_registry(bundle, adapters())


def test_rejects_side_effect_class_mismatch() -> None:
    bundle = starter_bundle().with_tool_policy(
        "mock_files.read", ToolPolicy(side_effect_class="LOCAL_MUTATION")
    )
    with pytest.raises(ToolRegistryConfigError, match="side-effect class mismatch"):
        build_registry(bundle, adapters())


def test_rejects_policy_destination_outside_adapter_capability() -> None:
    bundle = starter_bundle().with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=("https://evil.example/collect",),
        ),
    )
    with pytest.raises(ToolRegistryConfigError, match="does not declare it"):
        build_registry(bundle, adapters())


def test_rejects_approval_required_registration_when_policy_is_not_eligible() -> None:
    registration = replace(
        text_registration(),
        tool_id="stub.read",
        action_id="read",
        approval_required=True,
        required_approver_rule="role:admin",
    )
    bundle = starter_bundle().with_tool_policy(
        "stub.read", ToolPolicy(side_effect_class="READ_ONLY")
    )
    with pytest.raises(ToolRegistryConfigError, match="approval-eligible"):
        build_registry(bundle, (*adapters(), StubAdapter("mock-text-v1", registration)))


def test_rejects_egress_policy_for_adapter_without_destinations() -> None:
    bundle = starter_bundle().with_tool_policy(
        "text.summarize",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
        ),
    )
    registration = replace(text_registration(), side_effect_class=SideEffectClass.external_mutation)
    with pytest.raises(ToolRegistryConfigError, match="no destination capability"):
        build_registry(
            bundle,
            (
                MockEmailAdapter(),
                MockFilesAdapter(),
                MockExternalSinkAdapter(SinkStore()),
                StubAdapter("mock-text-v1", registration),
            ),
        )

"""Policy document model validation tests (blueprint sections 10.4, 11.4; ADR-008).

Strict contracts: unknown fields, unknown enum values, malformed tool ids, and
inconsistently configured flags fail validation (fail closed), and destinations are
canonicalized at validation time.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ai_security.policy.models import (
    PoliciesDocument,
    PolicyBundle,
    RiskThresholdsDocument,
    Thresholds,
    ToolPolicy,
)


def thresholds(**overrides: object) -> Thresholds:
    values: dict[str, object] = {"ask_user_at_or_above": 40, "block_at_or_above": 80}
    values.update(overrides)
    return Thresholds(**values)


def tool_policy(**overrides: object) -> ToolPolicy:
    values: dict[str, object] = {"side_effect_class": "READ_ONLY"}
    values.update(overrides)
    return ToolPolicy(**values)


def bundle(**overrides: object) -> PolicyBundle:
    values: dict[str, object] = {
        "policies": PoliciesDocument(schema_version=1, version="test-1", tools={}),
        "risk_thresholds": RiskThresholdsDocument(
            schema_version=1, version="th-1", thresholds=thresholds()
        ),
        "policies_sha256": "a" * 64,
        "thresholds_sha256": "b" * 64,
    }
    values.update(overrides)
    return PolicyBundle(**values)  # type: ignore[arg-type]


# -- Thresholds -----------------------------------------------------------------------


def test_thresholds_accept_valid_bands() -> None:
    values = thresholds(ask_user_at_or_above=40, block_at_or_above=80)
    assert values.ask_user_at_or_above == 40
    assert values.block_at_or_above == 80


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"ask_user_at_or_above": 80, "block_at_or_above": 80}, id="equal"),
        pytest.param({"ask_user_at_or_above": 81, "block_at_or_above": 80}, id="inverted"),
        pytest.param({"ask_user_at_or_above": 0}, id="ask-zero"),
        pytest.param({"block_at_or_above": 101}, id="block-above-100"),
        pytest.param({"surprise": 1}, id="unknown-field"),
    ],
)
def test_thresholds_reject_invalid_configuration(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        thresholds(**overrides)


def test_thresholds_missing_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Thresholds(ask_user_at_or_above=40)  # type: ignore[call-arg]


# -- ToolPolicy -----------------------------------------------------------------------


def test_tool_policy_defaults_are_conservative() -> None:
    policy = tool_policy()
    assert policy.explicitly_permitted is False
    assert policy.approval_eligible is False
    assert policy.external_egress_enabled is False
    assert policy.allowed_destinations == ()


def test_tool_policy_canonicalizes_destinations() -> None:
    policy = tool_policy(
        side_effect_class="EXTERNAL_MUTATION",
        external_egress_enabled=True,
        allowed_destinations=("HTTPS://Sink.Example.COM:443/collect",),
    )
    assert policy.allowed_destinations == ("https://sink.example.com/collect",)


def test_tool_policy_rejects_duplicate_destinations_after_canonicalization() -> None:
    with pytest.raises(ValidationError):
        tool_policy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=("https://sink.example.com", "https://sink.example.com/"),
        )


def test_tool_policy_rejects_invalid_destination() -> None:
    with pytest.raises(ValidationError):
        tool_policy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=("http://sink.example.com/collect",),
        )


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"explicitly_permitted": True}, id="permission-on-read-only"),
        pytest.param(
            {"side_effect_class": "EXTERNAL_MUTATION", "explicitly_permitted": True},
            id="permission-on-external",
        ),
        pytest.param(
            {"side_effect_class": "LOCAL_MUTATION", "external_egress_enabled": True},
            id="egress-on-local",
        ),
        pytest.param(
            {"allowed_destinations": ("https://sink.example.com/collect",)},
            id="allowlist-on-read-only",
        ),
        pytest.param(
            {"side_effect_class": "DESTRUCTIVE", "external_egress_enabled": True},
            id="egress-on-destructive",
        ),
        pytest.param({"side_effect_class": "SHELL"}, id="unknown-enum"),
        pytest.param({"side_effect_class": "READ_ONLY", "nope": 1}, id="unknown-field"),
    ],
)
def test_tool_policy_rejects_inconsistent_or_invalid_flags(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        tool_policy(**overrides)


def test_tool_policy_accepts_local_permission_and_confidential_approval() -> None:
    policy = tool_policy(
        side_effect_class="LOCAL_MUTATION",
        explicitly_permitted=True,
        approval_eligible=True,
    )
    assert policy.explicitly_permitted is True
    assert policy.approval_eligible is True


# -- PoliciesDocument -----------------------------------------------------------------


def test_policies_document_accepts_valid_tools() -> None:
    document = PoliciesDocument(
        schema_version=1,
        version="v1",
        tools={"mock_email.read": tool_policy(), "text.summarize": tool_policy()},
    )
    assert set(document.tools) == {"mock_email.read", "text.summarize"}


def test_policies_document_allows_empty_catalog_deny_all() -> None:
    document = PoliciesDocument(schema_version=1, version="v1", tools={})
    assert document.tools == {}


@pytest.mark.parametrize(
    "tool_id",
    [
        pytest.param("", id="empty"),
        pytest.param(" mock_email.read", id="leading-space"),
        pytest.param("mock email.read", id="inner-space"),
        pytest.param("mock/email", id="slash"),
        pytest.param("-leading", id="leading-dash"),
        pytest.param("trailing-", id="trailing-dash"),
        pytest.param("a" * 129, id="too-long"),
        pytest.param("shell!exec", id="punctuation"),
    ],
)
def test_policies_document_rejects_malformed_tool_ids(tool_id: str) -> None:
    with pytest.raises(ValidationError):
        PoliciesDocument(schema_version=1, version="v1", tools={tool_id: tool_policy()})


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"schema_version": 2, "version": "v1", "tools": {}}, id="wrong-schema"),
        pytest.param({"schema_version": 1, "version": "", "tools": {}}, id="empty-version"),
        pytest.param(
            {"schema_version": 1, "version": "v1", "tools": {}, "default": "ALLOW"},
            id="unknown-root-field",
        ),
        pytest.param({"schema_version": 1, "tools": {}}, id="missing-version"),
    ],
)
def test_policies_document_rejects_invalid_documents(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        PoliciesDocument.model_validate(payload)


# -- PolicyBundle ---------------------------------------------------------------------


def test_bundle_version_and_combined_hash_are_deterministic() -> None:
    first = bundle()
    second = bundle()
    assert first.version == "test-1"
    assert first.combined_hash == second.combined_hash
    assert len(first.combined_hash) == 64
    assert first.ask_user_at_or_above == 40
    assert first.block_at_or_above == 80


def test_bundle_hash_changes_with_source_hashes() -> None:
    assert bundle().combined_hash != bundle(policies_sha256="c" * 64).combined_hash


def test_bundle_tool_policy_lookup() -> None:
    document = PoliciesDocument(
        schema_version=1, version="v1", tools={"mock_email.read": tool_policy()}
    )
    assert bundle(policies=document).tool_policy("mock_email.read") is not None
    assert bundle(policies=document).tool_policy("shell.exec") is None


def test_bundle_with_tool_policy_overrides_without_mutating_original() -> None:
    original = bundle()
    scenario = original.with_tool_policy(
        "mock_files.write", tool_policy(side_effect_class="LOCAL_MUTATION")
    )
    assert original.tool_policy("mock_files.write") is None
    assert scenario.tool_policy("mock_files.write") is not None
    assert scenario.scenario == "tool-policy override for mock_files.write"
    assert scenario.version == original.version
    assert scenario.combined_hash == original.combined_hash


def test_bundle_with_tool_policy_rejects_malformed_tool_id() -> None:
    with pytest.raises(ValueError):
        bundle().with_tool_policy("bad id", tool_policy())

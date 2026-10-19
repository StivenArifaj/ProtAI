"""Strict intent models, manifest sealing, and binding verification (Phase 4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from ai_security.intent.models import (
    IntentConstraint,
    IntentExtraction,
    IntentExtractionStatus,
    IntentManifest,
    IntentManifestError,
    IntentManifestErrorCode,
    IntentResolution,
    IntentResolutionStatus,
    RelativeTimeScope,
    TimeWindow,
    _issue_intent_manifest,
    verify_intent_manifest,
)

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
DESTINATION = "https://mock-sink.invalid/collect"


def constraint(**overrides: object) -> IntentConstraint:
    values: dict[str, object] = {
        "tool_id": "mock_email.read",
        "action_id": "read",
        "allowed_resource_ids": ("email-1",),
    }
    values.update(overrides)
    return IntentConstraint(**values)


def manifest(**overrides: object) -> IntentManifest:
    values: dict[str, object] = {
        "manifest_id": "manifest-1",
        "request_id": "req-1",
        "principal_subject_id": "dev-user",
        "tenant_id": "dev-tenant",
        "policy_version": "dev-1",
        "policy_hash": "a" * 64,
        "extractor_version": "mock-intent-v1",
        "created_at": NOW,
        "expires_at": NOW + timedelta(seconds=300),
        "goal_digest": "b" * 64,
        "constraints": (constraint(),),
        "time_window": None,
    }
    values.update(overrides)
    return _issue_intent_manifest(**values)


def test_constraints_are_concrete_and_strict() -> None:
    with pytest.raises(ValidationError):
        constraint(allowed_resource_ids=("email-*",))
    with pytest.raises(ValidationError):
        constraint(allowed_resource_ids=("email-1", "email-1"))
    with pytest.raises(ValidationError):
        constraint(allowed_destinations=("http://mock-sink.invalid/collect",))
    with pytest.raises(ValidationError):
        constraint(allowed_parameter_values={"query": ()})
    with pytest.raises(ValidationError):
        constraint(allowed_parameter_values={"Query": ("x",)})
    with pytest.raises(ValidationError):
        constraint(allowed_parameter_values={"limit": (1.5,)})
    with pytest.raises(ValidationError):
        constraint(max_uses=0)
    with pytest.raises(ValidationError):
        constraint(max_uses=33)
    with pytest.raises(ValidationError):
        constraint(tool_id="../../escape")


def test_destinations_are_canonicalized_and_unique() -> None:
    value = constraint(allowed_destinations=(DESTINATION,))
    assert value.allowed_destinations == (DESTINATION,)
    with pytest.raises(ValidationError):
        constraint(allowed_destinations=(DESTINATION, DESTINATION))


def test_extraction_status_must_match_its_payload() -> None:
    with pytest.raises(ValidationError):
        IntentExtraction(
            status=IntentExtractionStatus.active,
            constraints=(),
            extractor_version="v1",
        )
    with pytest.raises(ValidationError):
        IntentExtraction(
            status=IntentExtractionStatus.active,
            constraints=(constraint(),),
            clarification_question="why?",
            extractor_version="v1",
        )
    with pytest.raises(ValidationError):
        IntentExtraction(
            status=IntentExtractionStatus.requires_clarification,
            constraints=(constraint(),),
            clarification_question="which mailbox?",
            extractor_version="v1",
        )
    with pytest.raises(ValidationError):
        IntentExtraction(
            status=IntentExtractionStatus.rejected,
            extractor_version="v1",
        )
    with pytest.raises(ValidationError):
        IntentExtraction(
            status=IntentExtractionStatus.active,
            constraints=(constraint(), constraint()),
            extractor_version="v1",
        )


def test_relative_time_and_confidence_are_bounded() -> None:
    valid = IntentExtraction(
        status=IntentExtractionStatus.active,
        constraints=(constraint(),),
        confidence_score=50,
        relative_time_scope=RelativeTimeScope.today,
        extractor_version="v1",
    )
    assert valid.relative_time_scope is RelativeTimeScope.today
    with pytest.raises(ValidationError):
        IntentExtraction(
            status=IntentExtractionStatus.active,
            constraints=(constraint(),),
            confidence_score=101,
            extractor_version="v1",
        )
    with pytest.raises(ValidationError):
        TimeWindow(start=NOW, end=NOW)
    with pytest.raises(ValidationError):
        TimeWindow(start=datetime(2026, 1, 1), end=NOW)  # noqa: DTZ001 - naive rejection test


def test_direct_manifest_construction_fails_closed() -> None:
    with pytest.raises(IntentManifestError) as caught:
        IntentManifest(
            manifest_id="manifest-1",
            request_id="req-1",
            principal_subject_id="dev-user",
            tenant_id=None,
            policy_version="dev-1",
            policy_hash="a" * 64,
            extractor_version="v1",
            created_at=NOW,
            expires_at=NOW + timedelta(seconds=300),
            goal_digest="b" * 64,
            constraints=(),
        )
    assert caught.value.code is IntentManifestErrorCode.forged


def test_issued_manifest_verifies_all_bindings() -> None:
    value = manifest()
    verify_intent_manifest(
        value,
        request_id="req-1",
        principal_subject_id="dev-user",
        tenant_id="dev-tenant",
        policy_version="dev-1",
        policy_hash="a" * 64,
        now=NOW + timedelta(seconds=1),
    )


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"request_id": "req-2"}, IntentManifestErrorCode.request_mismatch),
        ({"principal_subject_id": "other-user"}, IntentManifestErrorCode.principal_mismatch),
        ({"tenant_id": "other-tenant"}, IntentManifestErrorCode.tenant_mismatch),
        ({"policy_version": "dev-2"}, IntentManifestErrorCode.policy_mismatch),
        ({"policy_hash": "c" * 64}, IntentManifestErrorCode.policy_mismatch),
    ],
)
def test_manifest_binding_mismatches_fail_closed(
    overrides: dict[str, object], code: IntentManifestErrorCode
) -> None:
    value = manifest(**overrides)
    with pytest.raises(IntentManifestError) as caught:
        verify_intent_manifest(
            value,
            request_id="req-1",
            principal_subject_id="dev-user",
            tenant_id="dev-tenant",
            policy_version="dev-1",
            policy_hash="a" * 64,
            now=NOW + timedelta(seconds=1),
        )
    assert caught.value.code is code


def test_expired_and_not_yet_valid_manifests_fail_closed() -> None:
    value = manifest()
    with pytest.raises(IntentManifestError) as caught:
        verify_intent_manifest(
            value,
            request_id="req-1",
            principal_subject_id="dev-user",
            tenant_id="dev-tenant",
            policy_version="dev-1",
            policy_hash="a" * 64,
            now=NOW - timedelta(seconds=1),
        )
    assert caught.value.code is IntentManifestErrorCode.not_yet_valid

    with pytest.raises(IntentManifestError) as caught:
        verify_intent_manifest(
            value,
            request_id="req-1",
            principal_subject_id="dev-user",
            tenant_id="dev-tenant",
            policy_version="dev-1",
            policy_hash="a" * 64,
            now=NOW + timedelta(seconds=300),
        )
    assert caught.value.code is IntentManifestErrorCode.expired


def test_manifest_repr_does_not_include_goal_text() -> None:
    value = manifest()
    assert "summarize" not in repr(value)
    assert value.constraint_for("mock_email.read", "read") is not None
    assert value.constraint_for("mock_email.read", "delete") is None


def test_resolution_status_must_match_manifest_presence() -> None:
    with pytest.raises(ValueError):
        IntentResolution(status=IntentResolutionStatus.active)
    with pytest.raises(ValueError):
        IntentResolution(
            status=IntentResolutionStatus.extractor_unavailable,
            manifest=manifest(),
        )
    with pytest.raises(ValueError):
        IntentResolution(status=IntentResolutionStatus.requires_clarification)
    assert (
        IntentResolution(status=IntentResolutionStatus.active, manifest=manifest()).manifest
        is not None
    )

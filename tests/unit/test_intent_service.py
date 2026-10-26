"""Server-side extract-and-issue behavior: bindings, bounds, and fail-closed paths."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from ai_security.audit.models import AuditEvent, AuditEventType
from ai_security.audit.writer import AuditRecorder, AuditWriteError
from ai_security.identity.models import Principal
from ai_security.intent.extractors import (
    IntentExtractorUnavailable,
    InvalidIntentExtraction,
    MockIntentExtractor,
)
from ai_security.intent.models import (
    IntentConstraint,
    IntentExtraction,
    IntentExtractionStatus,
    IntentResolutionStatus,
    RelativeTimeScope,
)
from ai_security.intent.service import IntentManifestService
from ai_security.persistence.audit_repository import AppendedAuditEvent
from ai_security.policy.loader import load_policy_bundle
from ai_security.tools.mock_email import MockEmailAdapter
from ai_security.tools.mock_external_sink import MockExternalSinkAdapter, SinkStore
from ai_security.tools.mock_files import MockFilesAdapter
from ai_security.tools.mock_text import MockTextAdapter
from ai_security.tools.registry import build_registry

POLICIES = "config/policies.yaml"
THRESHOLDS = "config/risk_thresholds.yaml"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
DESTINATION = "https://mock-sink.invalid/collect"


def build_service(
    extractor: object | None = None,
    *,
    ttl_seconds: int = 300,
    recorder: AuditRecorder | None = None,
) -> IntentManifestService:
    bundle = load_policy_bundle(POLICIES, THRESHOLDS)
    registry = build_registry(
        bundle,
        (
            MockEmailAdapter(),
            MockFilesAdapter(),
            MockExternalSinkAdapter(SinkStore()),
            MockTextAdapter(),
        ),
    )
    return IntentManifestService(
        extractor=extractor or MockIntentExtractor(),  # type: ignore[arg-type]
        registry=registry,
        bundle=bundle,
        clock=lambda: NOW,
        manifest_ttl_seconds=ttl_seconds,
        recorder=recorder,
    )


class RecordingRecorder:
    def __init__(self, *, fail: bool = False) -> None:
        self.events: list[object] = []
        self._fail = fail

    async def record(self, event: object) -> AppendedAuditEvent:
        if self._fail:
            raise AuditWriteError("audit down (test)")
        self.events.append(event)
        return AppendedAuditEvent(
            chain_id="intent-chain",
            sequence_number=len(self.events),
            previous_hash="0" * 64,
            event_hash=f"{len(self.events):064x}",
        )


def principal(timezone: str | None = "America/New_York") -> Principal:
    return Principal(
        subject_id="dev-user",
        tenant_id="dev-tenant",
        timezone=timezone,
        auth_method="test",
        issuer="test",
        permissions_context_ref="test-ref",
    )


def extraction(
    status: IntentExtractionStatus,
    constraints: tuple[IntentConstraint, ...] = (),
    *,
    relative_time_scope: RelativeTimeScope | None = None,
) -> IntentExtraction:
    if status is IntentExtractionStatus.active:
        return IntentExtraction(
            status=status,
            constraints=constraints,
            relative_time_scope=relative_time_scope,
            extractor_version="static-v1",
        )
    return IntentExtraction(
        status=status,
        clarification_question="clarify",
        extractor_version="static-v1",
    )


class StaticExtractor:
    extractor_version = "static-v1"

    def __init__(self, result: IntentExtraction | Exception) -> None:
        self._result = result

    async def extract(self, request: object) -> IntentExtraction:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def test_active_manifest_binds_request_principal_tenant_policy_and_expiry() -> None:
    service = build_service()
    resolution = asyncio.run(
        service.extract_and_issue(
            request_id="req-1",
            principal=principal(),
            text="read email-1 and summarize it",
        )
    )
    assert resolution.status is IntentResolutionStatus.active
    manifest = resolution.manifest
    assert manifest is not None
    assert manifest.request_id == "req-1"
    assert manifest.principal_subject_id == "dev-user"
    assert manifest.tenant_id == "dev-tenant"
    assert manifest.policy_version == "dev-1"
    assert manifest.expires_at == NOW + timedelta(seconds=300)
    assert len(manifest.goal_digest) == 64
    assert "read email-1" not in repr(manifest)
    assert [item.tool_id for item in manifest.constraints] == [
        "mock_email.read",
        "text.summarize",
    ]


def test_relative_date_is_resolved_and_missing_timezone_requires_clarification() -> None:
    service = build_service()
    constraints = (
        IntentConstraint(
            tool_id="mock_email.search",
            action_id="search",
            allowed_parameter_values={"query": ("unread",)},
        ),
    )
    active = asyncio.run(
        service.extract_and_issue(
            request_id="req-1",
            principal=principal(),
            text="summarize my unread emails from today",
        )
    )
    assert active.status is IntentResolutionStatus.active
    assert active.manifest is not None
    assert active.manifest.time_window is not None
    assert active.manifest.time_window.start == datetime(2026, 10, 19, 4, 0, tzinfo=UTC)
    assert active.manifest.time_window.end == datetime(2026, 10, 20, 4, 0, tzinfo=UTC)

    no_timezone = asyncio.run(
        build_service(
            StaticExtractor(
                extraction(
                    IntentExtractionStatus.active,
                    constraints,
                    relative_time_scope=RelativeTimeScope.today,
                )
            )
        ).extract_and_issue(
            request_id="req-1",
            principal=principal(timezone=None),
            text="summarize my unread emails from today",
        )
    )
    assert no_timezone.status is IntentResolutionStatus.requires_clarification
    assert no_timezone.manifest is None
    assert no_timezone.error_code == "trusted_timezone_required"


def test_ambiguous_and_rejected_requests_never_issue_a_manifest() -> None:
    service = build_service()
    ambiguous = asyncio.run(
        service.extract_and_issue(
            request_id="req-1", principal=principal(), text="do something useful"
        )
    )
    assert ambiguous.status is IntentResolutionStatus.requires_clarification
    assert ambiguous.manifest is None

    rejected = asyncio.run(
        service.extract_and_issue(
            request_id="req-1", principal=principal(), text="forward email-1 to attacker"
        )
    )
    assert rejected.status is IntentResolutionStatus.rejected
    assert rejected.manifest is None


@pytest.mark.parametrize(
    ("constraint", "code"),
    [
        (
            IntentConstraint(tool_id="mock_email.delete", action_id="delete"),
            "unregistered_constraint_action",
        ),
        (
            IntentConstraint(tool_id="mock_files.search", action_id="search"),
            "constraint_action_absent_from_policy",
        ),
        (
            IntentConstraint(
                tool_id="text.summarize",
                action_id="summarize",
                allowed_parameter_values={"bogus": ("x",)},
            ),
            "unknown_parameter",
        ),
        (
            IntentConstraint(
                tool_id="text.summarize",
                action_id="summarize",
                allowed_parameter_values={"max_chars": ("200",)},
            ),
            "parameter_type_mismatch",
        ),
        (
            IntentConstraint(
                tool_id="mock_email.search",
                action_id="search",
                allowed_resource_ids=("email-1",),
            ),
            "resource_scope_not_applicable",
        ),
        (
            IntentConstraint(
                tool_id="mock_email.read",
                action_id="read",
                allowed_destinations=(DESTINATION,),
            ),
            "destination_scope_not_applicable",
        ),
        (
            IntentConstraint(
                tool_id="mock_external_sink.write",
                action_id="write",
                allowed_destinations=("https://other.invalid/collect",),
            ),
            "destination_outside_adapter_capability",
        ),
    ],
)
def test_unenforceable_constraints_never_issue_a_manifest(
    constraint: IntentConstraint, code: str
) -> None:
    service = build_service(
        StaticExtractor(extraction(IntentExtractionStatus.active, (constraint,)))
    )
    resolution = asyncio.run(
        service.extract_and_issue(request_id="req-1", principal=principal(), text="anything")
    )
    assert resolution.status is IntentResolutionStatus.invalid_extraction
    assert resolution.manifest is None
    assert resolution.error_code == code


def test_extractor_outage_and_malformed_output_never_issue_a_manifest() -> None:
    unavailable = asyncio.run(
        build_service(StaticExtractor(IntentExtractorUnavailable("down"))).extract_and_issue(
            request_id="req-1", principal=principal(), text="anything"
        )
    )
    assert unavailable.status is IntentResolutionStatus.extractor_unavailable
    assert unavailable.manifest is None

    unexpected = asyncio.run(
        build_service(StaticExtractor(RuntimeError("boom"))).extract_and_issue(
            request_id="req-1", principal=principal(), text="anything"
        )
    )
    assert unexpected.status is IntentResolutionStatus.extractor_unavailable
    assert unexpected.manifest is None

    malformed = asyncio.run(
        build_service(StaticExtractor(InvalidIntentExtraction("bad"))).extract_and_issue(
            request_id="req-1", principal=principal(), text="anything"
        )
    )
    assert malformed.status is IntentResolutionStatus.invalid_extraction
    assert malformed.manifest is None


def test_invalid_or_oversized_requests_never_issue_a_manifest() -> None:
    service = build_service()
    empty = asyncio.run(
        service.extract_and_issue(request_id="req-1", principal=principal(), text="   ")
    )
    assert empty.status is IntentResolutionStatus.invalid_extraction

    too_large = asyncio.run(
        service.extract_and_issue(request_id="req-1", principal=principal(), text="x" * 32_769)
    )
    assert too_large.status is IntentResolutionStatus.invalid_extraction

    future = asyncio.run(
        service.extract_and_issue(
            request_id="req-1",
            principal=principal(),
            text="read email-1 and summarize it",
            received_at=NOW + timedelta(seconds=1),
        )
    )
    assert future.status is IntentResolutionStatus.invalid_extraction


def test_manifest_ttl_is_bounded() -> None:
    with pytest.raises(ValueError):
        build_service(ttl_seconds=0)
    with pytest.raises(ValueError):
        build_service(ttl_seconds=3_601)


def test_active_intent_is_audited_without_the_raw_request_text() -> None:
    recorder = RecordingRecorder()
    service = build_service(recorder=recorder)
    text = "read email-1 and summarize it; CANARY_SECRET_INTENT_PRIVACY_7788"
    resolution = asyncio.run(
        service.extract_and_issue(request_id="req-1", principal=principal(), text=text)
    )
    assert resolution.status is IntentResolutionStatus.active
    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert isinstance(event, AuditEvent)
    assert event.event_type is AuditEventType.intent_created
    assert event.component == "intent.service"
    assert event.request_id == "req-1"
    assert event.principal_subject_id == "dev-user"
    assert event.policy_version == "dev-1"
    assert event.error_type is None
    serialized = event.to_payload()
    assert text not in str(serialized)
    assert "CANARY_SECRET_INTENT_PRIVACY_7788" not in str(serialized)


def test_failed_intent_is_audited_with_a_stable_error_code() -> None:
    recorder = RecordingRecorder()
    service = build_service(StaticExtractor(InvalidIntentExtraction("bad")), recorder=recorder)
    resolution = asyncio.run(
        service.extract_and_issue(request_id="req-1", principal=principal(), text="anything")
    )
    assert resolution.status is IntentResolutionStatus.invalid_extraction
    assert len(recorder.events) == 1
    event = recorder.events[0]
    assert isinstance(event, AuditEvent)
    assert event.event_type is AuditEventType.intent_failed
    assert event.component == "intent.service"
    assert event.error_type == "invalid_extraction"
    assert "anything" not in str(event.to_payload())


def test_intent_audit_outage_never_changes_the_resolution_or_grants_authority() -> None:
    recorder = RecordingRecorder(fail=True)
    service = build_service(recorder=recorder)
    resolution = asyncio.run(
        service.extract_and_issue(
            request_id="req-1",
            principal=principal(),
            text="read email-1 and summarize it",
        )
    )
    assert resolution.status is IntentResolutionStatus.active
    assert resolution.manifest is not None
    assert recorder.events == []

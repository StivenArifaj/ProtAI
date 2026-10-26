"""Intent manifests never grant authority; the gateway enforces concrete limits.

A malformed, missing, forged, expired, or differently-bound manifest can only cause a
denial. Even a valid manifest cannot widen the policy ALLOW or the manifest's own
concrete action/resource/destination/parameter/use limits.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from ai_security.audit.models import AuditEvent
from ai_security.data_security.dlp import OutputDefenseService, load_output_dlp_config
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import InvocationOutcome, ProposedToolCall, RequestContext
from ai_security.firewall.policy_engine import PolicyEngine
from ai_security.identity.models import Principal
from ai_security.intent.extractors import MockIntentExtractor
from ai_security.intent.models import (
    IntentConstraint,
    IntentManifest,
    IntentManifestError,
    _issue_intent_manifest,
)
from ai_security.intent.service import IntentManifestService
from ai_security.intent.validator import IntentUsageTracker
from ai_security.persistence.audit_repository import AppendedAuditEvent
from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.models import PolicyBundle, ToolPolicy
from ai_security.tools.base import ToolArguments, ToolResult
from ai_security.tools.mock_email import MockEmailAdapter
from ai_security.tools.mock_external_sink import (
    DESTINATION,
    MockExternalSinkAdapter,
    SinkStore,
)
from ai_security.tools.mock_files import MockFilesAdapter
from ai_security.tools.mock_text import MockTextAdapter
from ai_security.tools.registry import build_registry

POLICIES = "config/policies.yaml"
THRESHOLDS = "config/risk_thresholds.yaml"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
REQUEST_ID = "req-intent-security"


class Recorder:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> AppendedAuditEvent:
        self.events.append(event)
        sequence = len(self.events)
        return AppendedAuditEvent(
            chain_id="intent",
            sequence_number=sequence,
            previous_hash="0" * 64,
            event_hash=f"{sequence:064x}",
        )


class CountingEmailAdapter(MockEmailAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.executions = 0

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: object,
    ) -> ToolResult:
        self.executions += 1
        return await super().execute(
            tool_id=tool_id,
            action_id=action_id,
            arguments=arguments,
            authorization=authorization,  # type: ignore[arg-type]
        )


def bundle(*, sink_enabled: bool = True) -> PolicyBundle:
    base = load_policy_bundle(POLICIES, THRESHOLDS)
    if not sink_enabled:
        return base
    return base.with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
        ),
    )


def principal(subject_id: str = "dev-user") -> Principal:
    return Principal(
        subject_id=subject_id,
        tenant_id="dev-tenant",
        timezone="America/New_York",
        auth_method="test",
        issuer="test",
        permissions_context_ref="test-ref",
    )


def proposal(
    tool_id: str,
    action_id: str,
    *,
    arguments: dict[str, object],
    target_resources: tuple[str, ...] = (),
    destination: str | None = None,
    principal_subject_id: str = "dev-user",
) -> ProposedToolCall:
    return ProposedToolCall(
        call_id="call-intent",
        request_id=REQUEST_ID,
        principal_subject_id=principal_subject_id,
        tool_id=tool_id,
        action_id=action_id,
        arguments=arguments,
        target_resource_ids=target_resources,
        destination=destination,
    )


def read_proposal(email_id: str = "email-1", subject_id: str = "dev-user") -> ProposedToolCall:
    return proposal(
        "mock_email.read",
        "read",
        arguments={"email_id": email_id},
        target_resources=(email_id,),
        principal_subject_id=subject_id,
    )


def default_output_defense() -> OutputDefenseService:
    return OutputDefenseService(load_output_dlp_config("config/output_dlp.yaml"))


def build(
    *,
    intent_required: bool = True,
    policy: PolicyBundle | None = None,
    gateway_clock: datetime = NOW,
) -> tuple[ToolGateway, CountingEmailAdapter, SinkStore, IntentManifestService, Recorder]:
    policy = policy or bundle()
    email = CountingEmailAdapter()
    store = SinkStore()
    registry = build_registry(
        policy,
        (email, MockFilesAdapter(), MockExternalSinkAdapter(store), MockTextAdapter()),
    )
    recorder = Recorder()
    tracker = IntentUsageTracker() if intent_required else None
    gateway = ToolGateway(
        registry=registry,
        engine=PolicyEngine(policy),
        recorder=recorder,
        output_defense=default_output_defense(),
        clock=lambda: gateway_clock,
        intent_tracker=tracker,
    )
    service = IntentManifestService(
        extractor=MockIntentExtractor(),
        registry=registry,
        bundle=policy,
        clock=lambda: NOW,
    )
    return gateway, email, store, service, recorder


def issue(
    service: IntentManifestService, text: str = "read email-1 and summarize it"
) -> IntentManifest:
    resolution = asyncio.run(
        service.extract_and_issue(request_id=REQUEST_ID, principal=principal(), text=text)
    )
    assert resolution.manifest is not None, resolution
    return resolution.manifest


def invoke(
    gateway: ToolGateway,
    call: ProposedToolCall,
    manifest: IntentManifest | None,
    *,
    subject: Principal | None = None,
) -> object:
    async def scenario() -> object:
        return await gateway.invoke_tool(
            principal=subject or principal(),
            request_context=RequestContext(request_id=REQUEST_ID),
            proposal=call,
            manifest=manifest,
        )

    return asyncio.run(scenario())


def test_forged_manifest_cannot_be_constructed() -> None:
    with pytest.raises(IntentManifestError):
        IntentManifest(
            manifest_id="manifest-forged",
            request_id=REQUEST_ID,
            principal_subject_id="dev-user",
            tenant_id="dev-tenant",
            policy_version="dev-1",
            policy_hash="a" * 64,
            extractor_version="attacker",
            created_at=NOW,
            expires_at=NOW + timedelta(seconds=300),
            goal_digest="b" * 64,
            constraints=(),
        )


def test_missing_manifest_denies_before_policy_or_execution() -> None:
    gateway, email, _store, _service, recorder = build()
    result = invoke(gateway, read_proposal(), None)

    assert result.decision is FirewallDecision.block  # type: ignore[attr-defined]
    assert result.reason is DecisionReason.intent_manifest_invalid  # type: ignore[attr-defined]
    assert result.outcome is InvocationOutcome.denied  # type: ignore[attr-defined]
    assert email.executions == 0
    assert [event.event_type.value for event in recorder.events] == ["POLICY_EVALUATED"]


def test_expired_or_differently_bound_manifest_denies_without_execution() -> None:
    gateway, email, _store, service, _recorder = build(gateway_clock=NOW + timedelta(seconds=301))
    manifest = issue(service)
    expired = invoke(gateway, read_proposal(), manifest)
    assert expired.reason is DecisionReason.intent_manifest_invalid  # type: ignore[attr-defined]
    assert email.executions == 0

    gateway, email, _store, service, _recorder = build()
    manifest = issue(service)
    other_principal = principal("other-user")
    wrong_principal = invoke(
        gateway,
        read_proposal(subject_id="other-user"),
        manifest,
        subject=other_principal,
    )
    assert wrong_principal.reason is DecisionReason.intent_manifest_invalid  # type: ignore[attr-defined]
    assert email.executions == 0

    other_resolution = asyncio.run(
        service.extract_and_issue(
            request_id="req-other",
            principal=principal(),
            text="read email-1 and summarize it",
        )
    )
    assert other_resolution.manifest is not None
    wrong = invoke(gateway, read_proposal(), other_resolution.manifest)
    assert wrong.reason is DecisionReason.intent_manifest_invalid  # type: ignore[attr-defined]
    assert email.executions == 0


def test_manifest_does_not_permit_a_different_action_resource_or_parameter() -> None:
    gateway, email, _store, service, _recorder = build()
    manifest = issue(service)

    other_action = invoke(
        gateway,
        proposal(
            "mock_files.read",
            "read",
            arguments={"file_id": "file-1"},
            target_resources=("file-1",),
        ),
        manifest,
    )
    assert other_action.reason is DecisionReason.intent_action_not_allowed  # type: ignore[attr-defined]
    assert email.executions == 0

    other_resource = invoke(gateway, read_proposal("email-2"), manifest)
    assert other_resource.reason is DecisionReason.intent_constraint_violation  # type: ignore[attr-defined]
    assert email.executions == 0

    other_parameter = invoke(
        gateway,
        proposal(
            "text.summarize",
            "summarize",
            arguments={"text": "hello", "max_chars": 201},
        ),
        manifest,
    )
    assert other_parameter.reason is DecisionReason.intent_constraint_violation  # type: ignore[attr-defined]


def test_manifest_cannot_authorize_an_unlisted_destination() -> None:
    gateway, _email, store, _service, _recorder = build()
    manifest = _issue_intent_manifest(
        manifest_id="manifest-sink",
        request_id=REQUEST_ID,
        principal_subject_id="dev-user",
        tenant_id="dev-tenant",
        policy_version="dev-1",
        policy_hash=gateway._engine.bundle.combined_hash,  # noqa: SLF001 - binding fixture
        extractor_version="test-v1",
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        goal_digest="b" * 64,
        constraints=(
            IntentConstraint(
                tool_id="mock_external_sink.write",
                action_id="write",
            ),
        ),
        time_window=None,
    )
    result = invoke(
        gateway,
        proposal(
            "mock_external_sink.write",
            "write",
            arguments={"destination": DESTINATION, "content": "canary"},
            destination=DESTINATION,
        ),
        manifest,
    )
    assert result.reason is DecisionReason.intent_constraint_violation  # type: ignore[attr-defined]
    assert len(store) == 0


def test_manifest_use_limits_and_legacy_mode_are_fail_closed() -> None:
    gateway, email, _store, service, _recorder = build()
    manifest = issue(service)
    first = invoke(gateway, read_proposal(), manifest)
    assert first.decision is FirewallDecision.allow  # type: ignore[attr-defined]
    assert email.executions == 1

    second = invoke(gateway, read_proposal(), manifest)
    assert second.reason is DecisionReason.intent_limit_exceeded  # type: ignore[attr-defined]
    assert email.executions == 1

    legacy, legacy_email, _legacy_store, _legacy_service, _legacy_recorder = build(
        intent_required=False
    )
    rejected = invoke(legacy, read_proposal(), manifest)
    assert rejected.reason is DecisionReason.intent_manifest_invalid  # type: ignore[attr-defined]
    assert legacy_email.executions == 0

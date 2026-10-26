"""Privacy invariants for audit payloads and default logs (section 16.3; ADR-014).

These tests feed synthetic secrets (a canary, email, credential assignment, API-key
shape, and private-key header) through the enforced gateway, an adapter failure, a tool
result, and intent extraction. The audit payloads and default logs must never contain
the raw values — only stable codes, identifiers, digests, and sizes.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

from ai_security.audit.models import AuditEvent
from ai_security.audit.writer import AuditRecorder
from ai_security.data_security.dlp import OutputDefenseService, load_output_dlp_config
from ai_security.firewall.decision import FirewallDecision
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import InvocationOutcome, ProposedToolCall, RequestContext
from ai_security.firewall.policy_engine import PolicyEngine
from ai_security.identity.models import Principal
from ai_security.intent.extractors import MockIntentExtractor
from ai_security.intent.service import IntentManifestService
from ai_security.persistence.audit_repository import AppendedAuditEvent
from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.models import PolicyBundle, ToolPolicy
from ai_security.security.canonical_json import canonical_json_bytes
from ai_security.tools.base import (
    ExecutionAuthorization,
    ToolArguments,
    ToolResult,
)
from ai_security.tools.mock_email import MockEmailAdapter
from ai_security.tools.mock_external_sink import (
    DESTINATION,
    MockExternalSinkAdapter,
    SinkStore,
)
from ai_security.tools.mock_files import MockFilesAdapter
from ai_security.tools.mock_text import (
    ACTION_ID,
    TOOL_ID,
    MockTextAdapter,
    SummarizeResult,
)
from ai_security.tools.registry import build_registry

POLICIES = "config/policies.yaml"
THRESHOLDS = "config/risk_thresholds.yaml"
FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

CANARY = "CANARY_SECRET_PRIVACY_9F3A2B"
EMAIL = "finance@internal.example"
API_KEY = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
CREDENTIAL = "password=CorrectHorseBatteryStaple"

SECRETS = (CANARY, EMAIL, API_KEY, PRIVATE_KEY_HEADER, CREDENTIAL)


class Recorder:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> AppendedAuditEvent:
        self.events.append(event)
        return AppendedAuditEvent(
            chain_id="privacy",
            sequence_number=len(self.events),
            previous_hash="0" * 64,
            event_hash=f"{len(self.events):064x}",
        )


def bundle() -> PolicyBundle:
    starter = load_policy_bundle(POLICIES, THRESHOLDS)
    return starter.with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
        ),
    )


def gateway_for(
    recorder: AuditRecorder, *, text_adapter: MockTextAdapter | None = None
) -> tuple[ToolGateway, SinkStore]:
    policy = bundle()
    store = SinkStore()
    registry = build_registry(
        policy,
        (
            MockEmailAdapter(),
            MockFilesAdapter(),
            MockExternalSinkAdapter(store),
            text_adapter or MockTextAdapter(),
        ),
    )
    return (
        ToolGateway(
            registry=registry,
            engine=PolicyEngine(policy),
            recorder=recorder,
            output_defense=OutputDefenseService(load_output_dlp_config("config/output_dlp.yaml")),
            clock=lambda: FIXED_NOW,
        ),
        store,
    )


def principal() -> Principal:
    return Principal(
        subject_id="dev-user",
        tenant_id="dev-tenant",
        timezone="UTC",
        auth_method="test",
        issuer="test",
        permissions_context_ref="test-ref",
    )


def context() -> RequestContext:
    return RequestContext(request_id="req-privacy")


def proposal(
    tool_id: str, action_id: str, *, arguments: dict[str, object], destination: str | None = None
) -> ProposedToolCall:
    return ProposedToolCall(
        call_id="call-privacy",
        request_id="req-privacy",
        principal_subject_id="dev-user",
        tool_id=tool_id,
        action_id=action_id,
        arguments=arguments,
        target_resource_ids=(),
        destination=destination,
    )


def serialized_events(recorder: Recorder) -> str:
    return "\n".join(
        canonical_json_bytes(event.to_payload()).decode("utf-8") for event in recorder.events
    )


def assert_secrets_absent(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, f"raw secret leaked: {secret!r}"


class LeakyFailureAdapter(MockTextAdapter):
    """Raises an exception whose message carries a secret."""

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        raise RuntimeError(f"backend rejected {CANARY} with {CREDENTIAL}")


class LeakyResultAdapter(MockTextAdapter):
    """Returns a successful result whose content carries a secret."""

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        return SummarizeResult(
            summary=f"{CANARY} {PRIVATE_KEY_HEADER} {API_KEY}",
            original_chars=len(CANARY),
            truncated=False,
        )


def test_egress_secrets_never_reach_audit_payloads_or_default_logs(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    recorder = Recorder()
    gateway, store = gateway_for(recorder)
    leaky_content = " | ".join(SECRETS)
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(
                "mock_external_sink.write",
                "write",
                arguments={"destination": DESTINATION, "content": leaky_content},
                destination=DESTINATION,
            ),
        )
    )

    assert result.decision is FirewallDecision.block
    assert result.outcome is InvocationOutcome.denied
    assert store.records() == ()
    assert recorder.events
    assert_secrets_absent(serialized_events(recorder))
    assert_secrets_absent(caplog.text)
    # The audit still carries the useful, content-free evidence.
    egress = next(event for event in recorder.events if event.dlp is not None)
    assert egress.dlp is not None
    assert {finding.category.value for finding in egress.dlp.findings} >= {
        "SYNTHETIC_CANARY",
        "PRIVATE_KEY",
        "API_KEY",
        "CREDENTIAL",
        "PII_EMAIL",
    }


def test_adapter_exception_message_never_reaches_audit_payloads_or_logs(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    recorder = Recorder()
    gateway, _ = gateway_for(recorder, text_adapter=LeakyFailureAdapter())
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(TOOL_ID, ACTION_ID, arguments={"text": "summarize this"}),
        )
    )

    assert result.decision is FirewallDecision.allow
    assert result.outcome is InvocationOutcome.adapter_failed
    assert result.result is None
    failure = next(event for event in recorder.events if event.error_type is not None)
    assert failure.error_type == "RuntimeError"
    assert_secrets_absent(serialized_events(recorder))
    assert_secrets_absent(caplog.text)


def test_suppressed_result_content_never_reaches_audit_payloads_or_logs(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    recorder = Recorder()
    gateway, _ = gateway_for(recorder, text_adapter=LeakyResultAdapter())
    result = asyncio.run(
        gateway.invoke_tool(
            principal=principal(),
            request_context=context(),
            proposal=proposal(TOOL_ID, ACTION_ID, arguments={"text": "summarize this"}),
        )
    )

    assert result.decision is FirewallDecision.allow
    assert result.outcome is InvocationOutcome.response_blocked
    assert result.result is None
    suppression = next(event for event in recorder.events if event.result_digest is not None)
    assert suppression.result_digest is not None
    assert_secrets_absent(serialized_events(recorder))
    assert_secrets_absent(caplog.text)


def test_intent_audit_never_contains_the_request_text(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    recorder = Recorder()
    policy = load_policy_bundle(POLICIES, THRESHOLDS)
    registry = build_registry(
        policy,
        (
            MockEmailAdapter(),
            MockFilesAdapter(),
            MockExternalSinkAdapter(SinkStore()),
            MockTextAdapter(),
        ),
    )
    service = IntentManifestService(
        extractor=MockIntentExtractor(),
        registry=registry,
        bundle=policy,
        clock=lambda: FIXED_NOW,
        recorder=recorder,
    )
    request_text = f"read email-1 and summarize it {CANARY} {CREDENTIAL}"

    resolution = asyncio.run(
        service.extract_and_issue(
            request_id="req-privacy",
            principal=principal(),
            text=request_text,
        )
    )

    assert resolution.manifest is not None
    assert len(recorder.events) == 1
    payload = recorder.events[0].to_payload()
    assert request_text not in json.dumps(payload)
    assert_secrets_absent(json.dumps(payload))
    assert_secrets_absent(caplog.text)

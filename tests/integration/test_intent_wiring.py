"""Production app wiring for Phase 4 intent manifests and enforced execution.

The app-built gateway must require a server-issued manifest, enforce its concrete
constraints, and record the full decision/outcome chain in PostgreSQL — proving the
intent layer cannot be bypassed by an in-process caller.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from ai_security.api.app import create_app
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.models import InvocationOutcome, ProposedToolCall, RequestContext
from ai_security.identity.models import Principal
from ai_security.intent.models import IntentManifest, IntentResolutionStatus
from ai_security.intent.service import IntentManifestService
from ai_security.intent.validator import IntentUsageTracker
from ai_security.settings import Settings

SettingsFactory = Callable[..., Settings]


def principal() -> Principal:
    return Principal(
        subject_id="dev-user",
        tenant_id="dev-tenant",
        timezone="America/New_York",
        auth_method="dev",
        issuer="dev",
        permissions_context_ref="dev-ref",
    )


def read_proposal(request_id: str) -> ProposedToolCall:
    return ProposedToolCall(
        call_id="call-app-intent",
        request_id=request_id,
        principal_subject_id="dev-user",
        tool_id="mock_email.read",
        action_id="read",
        arguments={"email_id": "email-1"},
        target_resource_ids=("email-1",),
    )


async def invoke(
    app: object,
    *,
    request_id: str,
    proposal: ProposedToolCall,
    manifest: IntentManifest | None,
) -> object:
    gateway = app.state.tool_gateway  # type: ignore[attr-defined]
    return await gateway.invoke_tool(
        principal=principal(),
        request_context=RequestContext(request_id=request_id),
        proposal=proposal,
        manifest=manifest,
    )


def test_app_exposes_the_manifest_service_tracker_and_ttl(
    settings_factory: SettingsFactory, migrated_database: str
) -> None:
    app = create_app(settings_factory(intent_manifest_ttl_seconds=60))
    assert isinstance(app.state.intent_usage_tracker, IntentUsageTracker)
    assert isinstance(app.state.intent_manifest_service, IntentManifestService)
    assert app.state.tool_gateway._intent_tracker is app.state.intent_usage_tracker  # noqa: SLF001

    resolution = asyncio.run(
        app.state.intent_manifest_service.extract_and_issue(
            request_id="req-app-intent",
            principal=principal(),
            text="read email-1 and summarize it",
        )
    )
    assert resolution.status is IntentResolutionStatus.active
    assert resolution.manifest is not None
    assert (resolution.manifest.expires_at - resolution.manifest.created_at).total_seconds() == 60


def test_wired_gateway_requires_a_manifest_and_executes_on_allow(
    settings_factory: SettingsFactory, migrated_database: str
) -> None:
    app = create_app(settings_factory())

    async def scenario() -> None:
        resolution = await app.state.intent_manifest_service.extract_and_issue(
            request_id="req-app-intent",
            principal=principal(),
            text="read email-1 and summarize it",
        )
        manifest = resolution.manifest
        assert manifest is not None

        missing = await invoke(
            app,
            request_id="req-app-intent",
            proposal=read_proposal("req-app-intent"),
            manifest=None,
        )
        assert missing.decision is FirewallDecision.block  # type: ignore[attr-defined]
        assert missing.reason is DecisionReason.intent_manifest_invalid  # type: ignore[attr-defined]
        assert missing.outcome is InvocationOutcome.denied  # type: ignore[attr-defined]

        allowed = await invoke(
            app,
            request_id="req-app-intent",
            proposal=read_proposal("req-app-intent"),
            manifest=manifest,
        )
        assert allowed.decision is FirewallDecision.allow  # type: ignore[attr-defined]
        assert allowed.reason is DecisionReason.authorized_read  # type: ignore[attr-defined]
        assert allowed.outcome is InvocationOutcome.executed  # type: ignore[attr-defined]
        assert allowed.result is not None  # type: ignore[attr-defined]

        again = await invoke(
            app,
            request_id="req-app-intent",
            proposal=read_proposal("req-app-intent"),
            manifest=manifest,
        )
        assert again.reason is DecisionReason.intent_limit_exceeded  # type: ignore[attr-defined]

        await app.state.database.dispose()

    asyncio.run(scenario())


def test_ambiguous_request_yields_clarification_not_a_manifest(
    settings_factory: SettingsFactory, migrated_database: str
) -> None:
    app = create_app(settings_factory())
    resolution = asyncio.run(
        app.state.intent_manifest_service.extract_and_issue(
            request_id="req-app-intent",
            principal=principal(),
            text="do something useful",
        )
    )
    assert resolution.status is IntentResolutionStatus.requires_clarification
    assert resolution.manifest is None
    assert resolution.clarification_question is not None


def test_app_rejects_a_manifest_bound_to_another_request(
    settings_factory: SettingsFactory, migrated_database: str
) -> None:
    app = create_app(settings_factory())
    resolution = asyncio.run(
        app.state.intent_manifest_service.extract_and_issue(
            request_id="req-other",
            principal=principal(),
            text="read email-1 and summarize it",
        )
    )
    assert resolution.manifest is not None

    async def scenario() -> None:
        result = await invoke(
            app,
            request_id="req-app-intent",
            proposal=read_proposal("req-app-intent"),
            manifest=resolution.manifest,
        )
        assert result.decision is FirewallDecision.block  # type: ignore[attr-defined]
        assert result.reason is DecisionReason.intent_manifest_invalid  # type: ignore[attr-defined]
        assert result.outcome is InvocationOutcome.denied  # type: ignore[attr-defined]
        await app.state.database.dispose()

    asyncio.run(scenario())

"""Gateway approval gating over real PostgreSQL (blueprint sections 13.2-13.3).

An ASK_USER decision executes only after the gateway atomically consumes a matching,
approved, unexpired, action-bound approval. BLOCK decisions never consult or consume an
approval; replay, mismatch, denial, and expiry all fail closed with no side effect.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from db_helpers import DatabaseHarness
from sqlalchemy import select

from ai_security.audit.writer import ChainAuditRecorder
from ai_security.data_security.classification import DataClass
from ai_security.data_security.dlp import (
    DestinationTrust,
    DestinationTrustLabel,
    DlpCategory,
    DlpLimits,
    DlpRelease,
    EgressScope,
    LoadedOutputDlpConfig,
    OutputDefenseService,
    OutputDlpConfig,
    SensitivePattern,
    load_output_dlp_config,
)
from ai_security.firewall.approval import ApprovalRequestSpec, ApprovalService
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import (
    InvocationOutcome,
    ProposedToolCall,
    RequestContext,
    ToolInvocationResult,
)
from ai_security.firewall.policy_engine import PolicyEngine
from ai_security.identity.models import Principal
from ai_security.persistence.approval_repository import ApprovalRepository
from ai_security.persistence.audit_repository import AuditChainRepository
from ai_security.persistence.models import ApprovalRequest as StoredApproval
from ai_security.persistence.models import AuditEvent as StoredAuditEvent
from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.models import (
    PolicyBundle,
    RiskThresholdsDocument,
    Thresholds,
    ToolPolicy,
)
from ai_security.tools.base import SideEffectClass, compute_action_digest
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
FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
CONTENT = "canary"


def low_threshold_bundle() -> PolicyBundle:
    bundle = load_policy_bundle(POLICIES, THRESHOLDS).with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
            approval_eligible=True,
        ),
    )
    return replace(
        bundle,
        risk_thresholds=RiskThresholdsDocument(
            schema_version=1,
            version="test-thresholds",
            thresholds=Thresholds(ask_user_at_or_above=20, block_at_or_above=80),
        ),
    )


def blocked_bundle() -> PolicyBundle:
    return load_policy_bundle(POLICIES, THRESHOLDS)


def permissive_output_defense() -> OutputDefenseService:
    """A test defender that classifies an email address as INTERNAL.

    The real configuration treats email as CONFIDENTIAL, which the policy engine blocks
    outright for external egress. INTERNAL is the one raised class that policy can still
    route through human approval, so it isolates the approval class binding. The trust
    map allows the destination; only the approval comparison is under test.
    """
    config = OutputDlpConfig(
        schema_version=1,
        version="approval-class-binding",
        limits=DlpLimits(max_scan_bytes=65_536, max_findings=8, max_matches_per_pattern=4),
        patterns=(
            SensitivePattern(
                code="email",
                category=DlpCategory.pii_email,
                pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                data_class=DataClass.internal,
                egress=EgressScope.classify,
                release=DlpRelease.redact,
            ),
        ),
        destinations=(
            DestinationTrust(
                name="sink",
                destination=DESTINATION,
                trust=DestinationTrustLabel.public,
                max_data_class=DataClass.restricted,
            ),
        ),
    )
    return OutputDefenseService(LoadedOutputDlpConfig(config=config, sha256="a" * 64))


def principal() -> Principal:
    return Principal(
        subject_id="dev-user",
        auth_method="test",
        issuer="test",
        permissions_context_ref="test-ref",
    )


def approver() -> Principal:
    return Principal(
        subject_id="approver-1",
        roles=("approver",),
        auth_method="test",
        issuer="test",
        permissions_context_ref="approver-ref",
    )


def sink_proposal(content: str = CONTENT) -> ProposedToolCall:
    return ProposedToolCall(
        call_id="call-approval",
        request_id="req-approval",
        principal_subject_id="dev-user",
        tool_id="mock_external_sink.write",
        action_id="write",
        arguments={"destination": DESTINATION, "content": content},
        destination=DESTINATION,
    )


def action_digest(bundle: PolicyBundle, *, content: str = CONTENT) -> str:
    return compute_action_digest(
        request_id="req-approval",
        principal_subject_id="dev-user",
        tool_id="mock_external_sink.write",
        action_id="write",
        arguments={"destination": DESTINATION, "content": content},
        resource_ids=(),
        destination=DESTINATION,
        policy_hash=bundle.combined_hash,
    )


def spec_for(
    bundle: PolicyBundle, approval_digest: str, *, data_class: DataClass = DataClass.public
) -> ApprovalRequestSpec:
    return ApprovalRequestSpec(
        request_id="req-approval",
        tool_id="mock_external_sink.write",
        action_id="write",
        action_digest=approval_digest,
        resource_ids=(),
        destination=DESTINATION,
        side_effect_class=SideEffectClass.external_mutation,
        data_class=data_class,
        risk_score=25,
        risk_version="risk-v2",
        risk_factor_codes=("side_effect_external_mutation", "external_destination"),
        policy_version=bundle.version,
        policy_hash=bundle.combined_hash,
        required_approver_rule="role:approver",
        self_approval_allowed=False,
        policy_reason=DecisionReason.risk_requires_clarification,
    )


class Harness:
    def __init__(
        self,
        database: DatabaseHarness,
        bundle: PolicyBundle,
        *,
        output_defense: OutputDefenseService | None = None,
    ) -> None:
        self.bundle = bundle
        self.chain_id = f"gateway-approval-{uuid.uuid4().hex}"
        audit_chain = AuditChainRepository(database.session_factory, chain_id=self.chain_id)
        self.approvals = ApprovalService(ApprovalRepository(database.session_factory, audit_chain))
        self.store = SinkStore()
        self.output_defense = output_defense or OutputDefenseService(
            load_output_dlp_config("config/output_dlp.yaml")
        )
        self.gateway = ToolGateway(
            registry=build_registry(
                bundle,
                (
                    MockEmailAdapter(),
                    MockFilesAdapter(),
                    MockExternalSinkAdapter(self.store),
                    MockTextAdapter(),
                ),
            ),
            engine=PolicyEngine(bundle),
            recorder=ChainAuditRecorder(audit_chain),
            output_defense=self.output_defense,
            clock=lambda: FIXED_NOW,
            approval_service=self.approvals,
        )


async def issue(
    harness: Harness,
    *,
    now: datetime = FIXED_NOW,
    ttl_seconds: int = 900,
    content: str = CONTENT,
    data_class: DataClass = DataClass.public,
) -> tuple[str, str]:
    digest = action_digest(harness.bundle, content=content)
    spec = spec_for(harness.bundle, digest, data_class=data_class)
    challenge = await harness.approvals.request(
        requester=principal(), spec=spec, now=now, ttl_seconds=ttl_seconds
    )
    return challenge.approval_id, challenge.approval_token


async def approve(
    harness: Harness,
    approval_id: str,
    token: str,
    *,
    now: datetime = FIXED_NOW,
) -> None:
    decision = await harness.approvals.decide(
        approval_id,
        approval_token=token,
        approver=approver(),
        approve=True,
        now=now,
    )
    assert decision.outcome.value == "approved"


async def invoke(
    harness: Harness,
    *,
    approval_id: str | None = None,
    content: str = CONTENT,
) -> ToolInvocationResult:
    return await harness.gateway.invoke_tool(
        principal=principal(),
        request_context=RequestContext(request_id="req-approval"),
        proposal=sink_proposal(content),
        approval_id=approval_id,
    )


async def stored_approval(database: DatabaseHarness, approval_id: str) -> StoredApproval | None:
    async with database.session_factory() as session:
        return (
            await session.execute(
                select(StoredApproval).where(StoredApproval.approval_id == approval_id)
            )
        ).scalar_one_or_none()


async def audit_payloads(database: DatabaseHarness, chain_id: str) -> list[dict[str, object]]:
    async with database.session_factory() as session:
        rows = (
            await session.execute(
                select(StoredAuditEvent)
                .where(StoredAuditEvent.chain_id == chain_id)
                .order_by(StoredAuditEvent.sequence_number)
            )
        ).scalars()
        return [json.loads(bytes(row.canonical_event_bytes)) for row in rows]


def test_ask_user_without_approval_denies_and_leaves_sink_empty(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            harness = Harness(database, low_threshold_bundle())
            result = await invoke(harness)
            assert result.decision is FirewallDecision.ask_user
            assert result.reason is DecisionReason.risk_requires_clarification
            assert result.outcome is InvocationOutcome.denied
            assert result.result is None
            assert len(harness.store) == 0
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_approved_execution_runs_once_and_records_approval_metadata(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            harness = Harness(database, low_threshold_bundle())
            approval_id, token = await issue(harness)
            await approve(harness, approval_id, token)

            result = await invoke(harness, approval_id=approval_id)
            assert result.decision is FirewallDecision.ask_user
            assert result.outcome is InvocationOutcome.executed
            assert result.approval_id == approval_id
            assert result.approver_subject_id == "approver-1"
            assert result.result is not None
            assert len(harness.store) == 1

            row = await stored_approval(database, approval_id)
            assert row is not None and row.status == "consumed"

            recorded = await audit_payloads(database, harness.chain_id)
            assert [event["event_type"] for event in recorded] == [
                "APPROVAL_REQUESTED",
                "APPROVAL_DECIDED",
                "REQUEST_RECEIVED",
                "TOOL_CALL_PROPOSED",
                "EGRESS_INSPECTED",
                "APPROVAL_CONSUMED",
                "POLICY_EVALUATED",
                "TOOL_EXECUTION_STARTED",
                "TOOL_EXECUTION_COMPLETED",
                "OUTPUT_INSPECTED",
                "RESPONSE_RELEASED",
            ]
            decision_event = recorded[6]
            assert decision_event["decision"] == "ASK_USER"
            assert decision_event["approval_id"] == approval_id
            assert decision_event["approver_subject_id"] == "approver-1"
            consumed_event = recorded[5]
            assert consumed_event["approver_subject_id"] == "approver-1"
            # Consumption is bound to the executed action's class and effective class.
            assert consumed_event["side_effect_class"] == "EXTERNAL_MUTATION"
            assert consumed_event["data_class"] == DataClass.public.value
            # Privacy (section 16.3): neither the one-time token nor the arguments'
            # content may appear anywhere in the audit chain.
            serialized = json.dumps(recorded)
            assert token not in serialized
            assert CONTENT not in serialized
            assert "approval_token" not in serialized

            replay = await invoke(harness, approval_id=approval_id)
            assert replay.decision is FirewallDecision.block
            assert replay.reason is DecisionReason.approval_invalid
            assert replay.outcome is InvocationOutcome.denied
            assert len(harness.store) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_pending_denied_and_mismatched_approvals_fail_closed(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            harness = Harness(database, low_threshold_bundle())

            pending_id, _ = await issue(harness)
            pending = await invoke(harness, approval_id=pending_id)
            assert pending.decision is FirewallDecision.block
            assert pending.reason is DecisionReason.approval_invalid

            denied_id, denied_token = await issue(harness)
            denied = await harness.approvals.decide(
                denied_id,
                approval_token=denied_token,
                approver=approver(),
                approve=False,
                now=FIXED_NOW,
            )
            assert denied.outcome.value == "denied"
            denied_result = await invoke(harness, approval_id=denied_id)
            assert denied_result.reason is DecisionReason.approval_denied

            bound_id, bound_token = await issue(harness)
            await approve(harness, bound_id, bound_token)
            mismatched = await invoke(harness, approval_id=bound_id, content="different")
            assert mismatched.reason is DecisionReason.approval_invalid
            assert len(harness.store) == 0
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_expired_approval_fails_closed_with_expiry_reason(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            harness = Harness(database, low_threshold_bundle())
            created_at = FIXED_NOW - timedelta(seconds=120)
            approval_id, token = await issue(harness, now=created_at, ttl_seconds=60)
            await approve(harness, approval_id, token, now=created_at)

            result = await invoke(harness, approval_id=approval_id)
            assert result.decision is FirewallDecision.block
            assert result.reason is DecisionReason.approval_expired
            assert len(harness.store) == 0

            row = await stored_approval(database, approval_id)
            assert row is not None and row.status == "expired"
            recorded = await audit_payloads(database, harness.chain_id)
            assert "APPROVAL_EXPIRED" in [event["event_type"] for event in recorded]
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_engine_block_ignores_approval_and_never_consumes_it(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            harness = Harness(database, blocked_bundle())
            digest = action_digest(harness.bundle)
            challenge = await harness.approvals.request(
                requester=principal(),
                spec=spec_for(harness.bundle, digest),
                now=FIXED_NOW,
            )
            decision = await harness.approvals.decide(
                challenge.approval_id,
                approval_token=challenge.approval_token,
                approver=approver(),
                approve=True,
                now=FIXED_NOW,
            )
            assert decision.outcome.value == "approved"

            result = await invoke(harness, approval_id=challenge.approval_id)
            assert result.decision is FirewallDecision.block
            assert result.reason is DecisionReason.external_egress_disabled
            assert result.approval_id is None
            assert len(harness.store) == 0

            row = await stored_approval(database, challenge.approval_id)
            assert row is not None and row.status == "approved"
            recorded = await audit_payloads(database, harness.chain_id)
            assert "APPROVAL_CONSUMED" not in [event["event_type"] for event in recorded]
            assert recorded[-1]["event_type"] == "POLICY_EVALUATED"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_approval_with_a_stale_data_class_cannot_authorize_classified_content(
    migrated_database: str,
) -> None:
    """DLP may raise the effective class; an approval bound to PUBLIC must not follow.

    The canonical action digest is identical in both attempts (same content), so only
    the stored ``data_class`` distinguishes them. A raised class invalidates the stale
    approval without consuming it, and a matching INTERNAL approval executes once.
    """

    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            harness = Harness(
                database,
                low_threshold_bundle(),
                output_defense=permissive_output_defense(),
            )
            content = "contact finance@internal.example"

            stale_id, stale_token = await issue(
                harness, content=content, data_class=DataClass.public
            )
            await approve(harness, stale_id, stale_token)
            stale = await invoke(harness, approval_id=stale_id, content=content)
            assert stale.decision is FirewallDecision.block
            assert stale.reason is DecisionReason.approval_invalid
            assert stale.outcome is InvocationOutcome.denied
            assert stale.result is None
            assert len(harness.store) == 0
            stale_row = await stored_approval(database, stale_id)
            assert stale_row is not None and stale_row.status == "approved"

            recorded = await audit_payloads(database, harness.chain_id)
            assert recorded[-1]["event_type"] == "POLICY_EVALUATED"
            decision_event = recorded[-1]
            assert decision_event["decision"] == "BLOCK"
            assert decision_event["data_class"] == "INTERNAL"
            egress_event = next(
                event for event in reversed(recorded) if event["event_type"] == "EGRESS_INSPECTED"
            )
            assert egress_event["dlp"]["outcome"] == "PASS"
            assert egress_event["dlp"]["max_data_class"] == "INTERNAL"
            assert [finding["code"] for finding in egress_event["dlp"]["findings"]] == ["email"]

            matching_id, matching_token = await issue(
                harness, content=content, data_class=DataClass.internal
            )
            await approve(harness, matching_id, matching_token)
            matching = await invoke(harness, approval_id=matching_id, content=content)
            assert matching.decision is FirewallDecision.ask_user
            assert matching.outcome is InvocationOutcome.executed
            assert matching.result is not None
            assert len(harness.store) == 1

            matching_row = await stored_approval(database, matching_id)
            assert matching_row is not None and matching_row.status == "consumed"
            consumed = [
                event
                for event in await audit_payloads(database, harness.chain_id)
                if event["event_type"] == "APPROVAL_CONSUMED"
            ]
            assert consumed[-1]["approval_id"] == matching_id
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_dlp_block_precedes_approval_and_never_consumes_it(migrated_database: str) -> None:
    """An approval can never override a hard DLP finding.

    The canary category is configured to BLOCK egress, and egress inspection runs before
    policy evaluation. A previously granted approval therefore stays unconsumed and no
    sink write occurs.
    """

    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            harness = Harness(database, low_threshold_bundle())
            canary = "CANARY_SECRET_APPROVAL_1234"
            approval_id, token = await issue(harness, content=f"leak {canary}")
            await approve(harness, approval_id, token)

            result = await invoke(harness, approval_id=approval_id, content=f"leak {canary}")
            assert result.decision is FirewallDecision.block
            assert result.reason is DecisionReason.dlp_egress_blocked
            assert result.outcome is InvocationOutcome.denied
            assert result.approval_id is None
            assert result.risk is None
            assert len(harness.store) == 0
            report = result.dlp_egress
            assert report is not None
            assert report.egress_reason is not None
            assert report.egress_reason.value == "category_blocked"
            assert "synthetic_canary" in {finding.code for finding in report.findings}
            assert canary not in repr(report)

            row = await stored_approval(database, approval_id)
            assert row is not None and row.status == "approved"
            event_types = [
                event["event_type"] for event in await audit_payloads(database, harness.chain_id)
            ]
            assert "APPROVAL_CONSUMED" not in event_types
            assert event_types[-1] == "POLICY_EVALUATED"
            assert canary not in json.dumps(
                await audit_payloads(database, harness.chain_id), default=str
            )
        finally:
            await database.dispose()

    asyncio.run(scenario())

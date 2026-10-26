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


def spec_for(bundle: PolicyBundle, approval_digest: str) -> ApprovalRequestSpec:
    return ApprovalRequestSpec(
        request_id="req-approval",
        tool_id="mock_external_sink.write",
        action_id="write",
        action_digest=approval_digest,
        resource_ids=(),
        destination=DESTINATION,
        side_effect_class=SideEffectClass.external_mutation,
        data_class=DataClass.public,
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
    def __init__(self, database: DatabaseHarness, bundle: PolicyBundle) -> None:
        self.bundle = bundle
        self.chain_id = f"gateway-approval-{uuid.uuid4().hex}"
        audit_chain = AuditChainRepository(database.session_factory, chain_id=self.chain_id)
        self.approvals = ApprovalService(ApprovalRepository(database.session_factory, audit_chain))
        self.store = SinkStore()
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
            clock=lambda: FIXED_NOW,
            approval_service=self.approvals,
        )


async def issue(
    harness: Harness,
    *,
    now: datetime = FIXED_NOW,
    ttl_seconds: int = 900,
    content: str = CONTENT,
) -> tuple[str, str]:
    digest = action_digest(harness.bundle, content=content)
    spec = spec_for(harness.bundle, digest)
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
                "APPROVAL_CONSUMED",
                "POLICY_EVALUATED",
                "TOOL_EXECUTION_COMPLETED",
            ]
            decision_event = recorded[3]
            assert decision_event["decision"] == "ASK_USER"
            assert decision_event["approval_id"] == approval_id
            assert decision_event["approver_subject_id"] == "approver-1"
            consumed_event = recorded[2]
            assert consumed_event["approver_subject_id"] == "approver-1"

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

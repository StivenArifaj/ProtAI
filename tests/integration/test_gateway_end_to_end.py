"""Gateway end-to-end over the real PostgreSQL audit chain (blueprint section 16.4).

The unit suite proves the gateway's in-process contract; this module proves the same
flow against the production audit repository: decision bytes are durable before any
side effect, both events land in the chain in order, and a database outage blocks a
would-be ALLOW before the sink changes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import UTC, datetime

from db_helpers import DatabaseHarness
from sqlalchemy import select

from ai_security.audit.writer import ChainAuditRecorder
from ai_security.data_security.classification import DataClass
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import InvocationOutcome, ProposedToolCall, RequestContext
from ai_security.firewall.policy_engine import PolicyEngine
from ai_security.identity.models import Principal
from ai_security.persistence.audit_repository import AuditChainRepository
from ai_security.persistence.models import AuditEvent as StoredAuditEvent
from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.models import PolicyBundle, ToolPolicy
from ai_security.security.canonical_json import canonical_json_bytes
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
UNREACHABLE_DATABASE_URL = "postgresql+asyncpg://firewall:irrelevant@127.0.0.1:59999/nope"


def unique_chain() -> str:
    return f"gateway-chain-{uuid.uuid4().hex}"


def starter_bundle() -> PolicyBundle:
    return load_policy_bundle(POLICIES, THRESHOLDS)


def enabled_sink_bundle() -> PolicyBundle:
    return starter_bundle().with_tool_policy(
        "mock_external_sink.write",
        ToolPolicy(
            side_effect_class="EXTERNAL_MUTATION",
            external_egress_enabled=True,
            allowed_destinations=(DESTINATION,),
        ),
    )


def principal() -> Principal:
    return Principal(
        subject_id="dev-user",
        auth_method="test",
        issuer="test",
        permissions_context_ref="test-ref",
    )


def read_proposal() -> ProposedToolCall:
    return ProposedToolCall(
        call_id="call-e2e",
        request_id="req-e2e",
        principal_subject_id="dev-user",
        tool_id="mock_email.read",
        action_id="read",
        arguments={"email_id": "email-1"},
        target_resource_ids=("email-1",),
    )


def sink_proposal() -> ProposedToolCall:
    return ProposedToolCall(
        call_id="call-sink",
        request_id="req-e2e",
        principal_subject_id="dev-user",
        tool_id="mock_external_sink.write",
        action_id="write",
        arguments={"destination": DESTINATION, "content": "canary"},
        destination=DESTINATION,
    )


def gateway_for(
    bundle: PolicyBundle,
    database: DatabaseHarness,
    store: SinkStore,
    *,
    chain_id: str,
) -> ToolGateway:
    repository = AuditChainRepository(database.session_factory, chain_id=chain_id)
    return ToolGateway(
        registry=build_registry(
            bundle,
            (
                MockEmailAdapter(),
                MockFilesAdapter(),
                MockExternalSinkAdapter(store),
                MockTextAdapter(),
            ),
        ),
        engine=PolicyEngine(bundle),
        recorder=ChainAuditRecorder(repository),
        clock=lambda: FIXED_NOW,
    )


async def payloads(database: DatabaseHarness, chain_id: str) -> list[dict[str, object]]:
    async with database.session_factory() as session:
        result = await session.execute(
            select(StoredAuditEvent)
            .where(StoredAuditEvent.chain_id == chain_id)
            .order_by(StoredAuditEvent.sequence_number)
        )
        rows = list(result.scalars().all())
        return [json.loads(row.canonical_event_bytes) for row in rows]


def test_allowed_read_is_audited_before_execution_and_chained(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            store = SinkStore()
            gateway = gateway_for(starter_bundle(), database, store, chain_id=chain_id)
            request_context = RequestContext(request_id="req-e2e")
            result = await gateway.invoke_tool(
                principal=principal(),
                request_context=request_context,
                proposal=read_proposal(),
            )
            assert result.decision is FirewallDecision.allow
            assert result.reason is DecisionReason.authorized_read
            assert result.outcome is InvocationOutcome.executed
            assert result.result is not None
            assert result.decision_audit_sequence == 1
            assert result.outcome_audit_sequence == 2

            recorded = await payloads(database, chain_id)
            assert [event["event_type"] for event in recorded] == [
                "POLICY_EVALUATED",
                "TOOL_EXECUTION_COMPLETED",
            ]
            decision_event, outcome_event = recorded
            assert decision_event["decision"] == "ALLOW"
            assert decision_event["reason"] == "authorized_read"
            assert decision_event["policy_hash"] == result.policy_hash
            assert decision_event["risk_score"] == 5
            assert outcome_event["outcome"] == "EXECUTED"
            canonical_result = canonical_json_bytes(result.result.model_dump(mode="json"))
            assert outcome_event["result_digest"] == hashlib.sha256(canonical_result).hexdigest()
            assert outcome_event["result_bytes"] == len(canonical_result)
            serialized = json.dumps(recorded)
            assert "Please review" not in serialized
            assert "budget" not in serialized

            # Linkage: the repository stored each event at consecutive sequence
            # numbers, and the rows' hashes chain (the repository suite covers the
            # cryptographic details; here the gateway's ordering is what matters).
            async with database.session_factory() as session:
                rows = list(
                    (
                        await session.execute(
                            select(StoredAuditEvent)
                            .where(StoredAuditEvent.chain_id == chain_id)
                            .order_by(StoredAuditEvent.sequence_number)
                        )
                    )
                    .scalars()
                    .all()
                )
            assert [row.sequence_number for row in rows] == [1, 2]
            assert rows[1].previous_hash == rows[0].event_hash
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_denied_egress_is_audited_and_leaves_the_sink_empty(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            chain_id = unique_chain()
            store = SinkStore()
            gateway = gateway_for(starter_bundle(), database, store, chain_id=chain_id)
            result = await gateway.invoke_tool(
                principal=principal(),
                request_context=RequestContext(request_id="req-e2e"),
                proposal=sink_proposal(),
            )
            assert result.decision is FirewallDecision.block
            assert result.reason is DecisionReason.external_egress_disabled
            assert result.outcome is InvocationOutcome.denied
            assert result.risk is not None
            assert store.records() == ()

            recorded = await payloads(database, chain_id)
            assert len(recorded) == 1
            assert recorded[0]["event_type"] == "POLICY_EVALUATED"
            assert recorded[0]["decision"] == "BLOCK"
            assert recorded[0]["data_class"] == DataClass.public.value
            assert recorded[0]["destination"] == DESTINATION
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_audit_outage_blocks_an_allowed_side_effect(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(UNREACHABLE_DATABASE_URL, connect_args={"timeout": 0.5})
        try:
            store = SinkStore()
            gateway = gateway_for(enabled_sink_bundle(), database, store, chain_id=unique_chain())
            result = await gateway.invoke_tool(
                principal=principal(),
                request_context=RequestContext(request_id="req-e2e"),
                proposal=sink_proposal(),
            )
            assert result.decision is FirewallDecision.block
            assert result.reason is DecisionReason.audit_unavailable
            assert result.outcome is InvocationOutcome.denied
            assert result.decision_audit_sequence is None
            assert store.records() == ()
        finally:
            await database.dispose()

    asyncio.run(scenario())

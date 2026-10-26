"""Approval workflow against real PostgreSQL (blueprint sections 13.1-13.3).

Proves the durable approval state machine: one-time token digests, verified-approver
rules, self-approval policy, expiry, digest/action binding, same-transaction audit
events, and exactly-once consumption under concurrent execution attempts.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from db_helpers import DatabaseHarness
from sqlalchemy import select

from ai_security.audit.models import AuditEventType
from ai_security.data_security.classification import DataClass
from ai_security.firewall.approval import (
    ApprovalError,
    ApprovalNotApprovable,
    ApprovalRequestSpec,
    ApprovalService,
)
from ai_security.firewall.decision import DecisionReason
from ai_security.identity.models import Principal
from ai_security.persistence.approval_repository import (
    ApprovalConsumptionOutcome,
    ApprovalDecisionOutcome,
    ApprovalRepository,
)
from ai_security.persistence.audit_repository import AuditChainRepository
from ai_security.persistence.models import ApprovalRequest, AuditEvent
from ai_security.tools.base import SideEffectClass

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
ACTION_DIGEST = "a" * 64
POLICY_HASH = "b" * 64


def requester() -> Principal:
    return Principal(
        subject_id="user-1",
        roles=("requester",),
        tenant_id="tenant-1",
        auth_method="host-hmac",
        issuer="local-dev",
        permissions_context_ref="ctx-1",
    )


def approver(subject_id: str = "user-2", *, tenant_id: str = "tenant-1") -> Principal:
    return Principal(
        subject_id=subject_id,
        roles=("approver",),
        tenant_id=tenant_id,
        auth_method="host-hmac",
        issuer="local-dev",
        permissions_context_ref="ctx-2",
    )


def spec(**overrides: object) -> ApprovalRequestSpec:
    values: dict[str, object] = {
        "request_id": "req-approval-1",
        "tool_id": "mock_email.send",
        "action_id": "send",
        "action_digest": ACTION_DIGEST,
        "resource_ids": ("email-1",),
        "destination": None,
        "side_effect_class": SideEffectClass.local_mutation,
        "data_class": DataClass.internal,
        "risk_score": 15,
        "risk_version": "risk-v2",
        "risk_factor_codes": ("side_effect_local_mutation",),
        "policy_version": "1.0.0",
        "policy_hash": POLICY_HASH,
        "required_approver_rule": "role:approver",
        "self_approval_allowed": False,
        "policy_reason": DecisionReason.risk_requires_clarification,
    }
    values.update(overrides)
    return ApprovalRequestSpec(**values)


def build_service(database: DatabaseHarness) -> tuple[ApprovalService, str]:
    chain_id = f"test-approval-{uuid.uuid4().hex}"
    audit_chain = AuditChainRepository(database.session_factory, chain_id=chain_id)
    repository = ApprovalRepository(database.session_factory, audit_chain)
    return ApprovalService(repository), chain_id


async def stored_request(database: DatabaseHarness, approval_id: str) -> ApprovalRequest | None:
    async with database.session_factory() as session:
        return (
            await session.execute(
                select(ApprovalRequest).where(ApprovalRequest.approval_id == approval_id)
            )
        ).scalar_one_or_none()


async def audit_payloads(database: DatabaseHarness, chain_id: str) -> list[dict[str, object]]:
    async with database.session_factory() as session:
        rows = (
            await session.execute(
                select(AuditEvent)
                .where(AuditEvent.chain_id == chain_id)
                .order_by(AuditEvent.sequence_number)
            )
        ).scalars()
        return [json.loads(bytes(row.canonical_event_bytes)) for row in rows]


async def issue(service: ApprovalService, **overrides: object) -> tuple[str, str]:
    challenge = await service.request(requester=requester(), spec=spec(**overrides), now=BASE)
    return challenge.approval_id, challenge.approval_token


def test_request_persists_digest_only_and_audits_creation(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, chain_id = build_service(database)
            approval_id, token = await issue(service)

            row = await stored_request(database, approval_id)
            assert row is not None
            assert row.status == "pending"
            assert row.token_digest != token
            assert len(row.token_digest) == 64

            payloads = await audit_payloads(database, chain_id)
            assert [item["event_type"] for item in payloads] == [
                AuditEventType.approval_requested.value
            ]
            assert payloads[0]["component"] == "firewall.approval"
            assert payloads[0]["approval_id"] == approval_id
            assert token not in json.dumps(payloads)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_wrong_token_does_not_change_state_then_valid_decision_approves(
    migrated_database: str,
) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, chain_id = build_service(database)
            approval_id, token = await issue(service)

            wrong = await service.decide(
                approval_id,
                approval_token="x" * 43,
                approver=approver(),
                approve=True,
                now=BASE,
            )
            assert wrong.outcome is ApprovalDecisionOutcome.invalid_token
            row = await stored_request(database, approval_id)
            assert row is not None and row.status == "pending"

            decision = await service.decide(
                approval_id, approval_token=token, approver=approver(), approve=True, now=BASE
            )
            assert decision.outcome is ApprovalDecisionOutcome.approved
            row = await stored_request(database, approval_id)
            assert row is not None
            assert row.status == "approved"
            assert row.decided_by_subject_id == "user-2"
            assert row.decided_at == BASE

            payloads = await audit_payloads(database, chain_id)
            assert [item["event_type"] for item in payloads] == [
                AuditEventType.approval_requested.value,
                AuditEventType.approval_decided.value,
            ]
            assert payloads[-1]["decision"] == "ALLOW"
            assert payloads[-1]["reason"] == DecisionReason.approval_granted.value
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_self_approval_follows_policy_and_rule_eligibility(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, _ = build_service(database)
            approval_id, token = await issue(
                service, required_approver_rule="principal:user-1|principal:user-2"
            )

            forbidden = await service.decide(
                approval_id, approval_token=token, approver=requester(), approve=True, now=BASE
            )
            assert forbidden.outcome is ApprovalDecisionOutcome.self_approval_forbidden

            ineligible = await service.decide(
                approval_id,
                approval_token=token,
                approver=approver("user-9"),
                approve=True,
                now=BASE,
            )
            assert ineligible.outcome is ApprovalDecisionOutcome.not_eligible

            foreign = await service.decide(
                approval_id,
                approval_token=token,
                approver=approver("user-8", tenant_id="tenant-2"),
                approve=True,
                now=BASE,
            )
            assert foreign.outcome is ApprovalDecisionOutcome.not_eligible

            allowed_id, allowed_token = await issue(
                service,
                required_approver_rule="principal:user-1",
                self_approval_allowed=True,
            )
            allowed = await service.decide(
                allowed_id,
                approval_token=allowed_token,
                approver=requester(),
                approve=True,
                now=BASE,
            )
            assert allowed.outcome is ApprovalDecisionOutcome.approved
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_requester_only_rule_is_refused_before_storage(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, chain_id = build_service(database)
            with pytest.raises(ApprovalNotApprovable):
                await issue(service, required_approver_rule="principal:user-1")
            assert await audit_payloads(database, chain_id) == []
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_consume_is_bound_to_action_and_one_time(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, chain_id = build_service(database)
            approval_id, token = await issue(service)
            await service.decide(
                approval_id, approval_token=token, approver=approver(), approve=True, now=BASE
            )

            mismatch = await service.consume(
                approval_id,
                principal=requester(),
                request_id="req-approval-1",
                tool_id="mock_email.send",
                action_id="send",
                action_digest="c" * 64,
                resource_ids=("email-1",),
                destination=None,
                side_effect_class=SideEffectClass.local_mutation,
                data_class=DataClass.internal,
                policy_version="1.0.0",
                policy_hash=POLICY_HASH,
                now=BASE,
            )
            assert mismatch.outcome is ApprovalConsumptionOutcome.mismatch

            # Same canonical action and policy, but a different side-effect class or a
            # DLP-raised data class cannot reuse the approval bound to the original
            # facts. A mismatch must not consume the grant.
            wrong_effect = await service.consume(
                approval_id,
                principal=requester(),
                request_id="req-approval-1",
                tool_id="mock_email.send",
                action_id="send",
                action_digest=ACTION_DIGEST,
                resource_ids=("email-1",),
                destination=None,
                side_effect_class=SideEffectClass.read_only,
                data_class=DataClass.internal,
                policy_version="1.0.0",
                policy_hash=POLICY_HASH,
                now=BASE,
            )
            assert wrong_effect.outcome is ApprovalConsumptionOutcome.mismatch

            raised_class = await service.consume(
                approval_id,
                principal=requester(),
                request_id="req-approval-1",
                tool_id="mock_email.send",
                action_id="send",
                action_digest=ACTION_DIGEST,
                resource_ids=("email-1",),
                destination=None,
                side_effect_class=SideEffectClass.local_mutation,
                data_class=DataClass.confidential,
                policy_version="1.0.0",
                policy_hash=POLICY_HASH,
                now=BASE,
            )
            assert raised_class.outcome is ApprovalConsumptionOutcome.mismatch

            granted = await service.consume(
                approval_id,
                principal=requester(),
                request_id="req-approval-1",
                tool_id="mock_email.send",
                action_id="send",
                action_digest=ACTION_DIGEST,
                resource_ids=("email-1",),
                destination=None,
                side_effect_class=SideEffectClass.local_mutation,
                data_class=DataClass.internal,
                policy_version="1.0.0",
                policy_hash=POLICY_HASH,
                now=BASE,
            )
            assert granted.granted
            assert granted.approver_subject_id == "user-2"

            replay = await service.consume(
                approval_id,
                principal=requester(),
                request_id="req-approval-1",
                tool_id="mock_email.send",
                action_id="send",
                action_digest=ACTION_DIGEST,
                resource_ids=("email-1",),
                destination=None,
                side_effect_class=SideEffectClass.local_mutation,
                data_class=DataClass.internal,
                policy_version="1.0.0",
                policy_hash=POLICY_HASH,
                now=BASE,
            )
            assert replay.outcome is ApprovalConsumptionOutcome.replay

            payloads = await audit_payloads(database, chain_id)
            assert [item["event_type"] for item in payloads][-1] == (
                AuditEventType.approval_consumed.value
            )
            assert payloads[-1]["approver_subject_id"] == "user-2"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_concurrent_consume_grants_exactly_once(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, _ = build_service(database)
            approval_id, token = await issue(service)
            await service.decide(
                approval_id, approval_token=token, approver=approver(), approve=True, now=BASE
            )

            results = await asyncio.gather(
                *(
                    service.consume(
                        approval_id,
                        principal=requester(),
                        request_id="req-approval-1",
                        tool_id="mock_email.send",
                        action_id="send",
                        action_digest=ACTION_DIGEST,
                        resource_ids=("email-1",),
                        destination=None,
                        side_effect_class=SideEffectClass.local_mutation,
                        data_class=DataClass.internal,
                        policy_version="1.0.0",
                        policy_hash=POLICY_HASH,
                        now=BASE,
                    )
                    for _ in range(5)
                )
            )
            outcomes = [result.outcome for result in results]
            assert outcomes.count(ApprovalConsumptionOutcome.consumed) == 1
            assert outcomes.count(ApprovalConsumptionOutcome.replay) == 4
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_denied_and_expired_requests_never_consume(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, chain_id = build_service(database)
            denied_id, denied_token = await issue(service)
            denied = await service.decide(
                denied_id,
                approval_token=denied_token,
                approver=approver(),
                approve=False,
                now=BASE,
            )
            assert denied.outcome is ApprovalDecisionOutcome.denied
            consumed = await service.consume(
                denied_id,
                principal=requester(),
                request_id="req-approval-1",
                tool_id="mock_email.send",
                action_id="send",
                action_digest=ACTION_DIGEST,
                resource_ids=("email-1",),
                destination=None,
                side_effect_class=SideEffectClass.local_mutation,
                data_class=DataClass.internal,
                policy_version="1.0.0",
                policy_hash=POLICY_HASH,
                now=BASE,
            )
            assert consumed.outcome is ApprovalConsumptionOutcome.denied

            expired_id, expired_token = await issue(service)
            after_expiry = BASE + timedelta(seconds=901)
            expired = await service.decide(
                expired_id,
                approval_token=expired_token,
                approver=approver(),
                approve=True,
                now=after_expiry,
            )
            assert expired.outcome is ApprovalDecisionOutcome.expired
            row = await stored_request(database, expired_id)
            assert row is not None and row.status == "expired"

            payloads = await audit_payloads(database, chain_id)
            event_types = [item["event_type"] for item in payloads]
            assert AuditEventType.approval_expired.value in event_types
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_consuming_before_decision_is_not_approved(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, _ = build_service(database)
            approval_id, _token = await issue(service)
            result = await service.consume(
                approval_id,
                principal=requester(),
                request_id="req-approval-1",
                tool_id="mock_email.send",
                action_id="send",
                action_digest=ACTION_DIGEST,
                resource_ids=("email-1",),
                destination=None,
                side_effect_class=SideEffectClass.local_mutation,
                data_class=DataClass.internal,
                policy_version="1.0.0",
                policy_hash=POLICY_HASH,
                now=BASE,
            )
            assert result.outcome is ApprovalConsumptionOutcome.not_approved
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_invalid_ids_and_tokens_fail_closed(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, _ = build_service(database)
            not_found = await service.decide(
                "not-hex",
                approval_token="x" * 43,
                approver=approver(),
                approve=True,
                now=BASE,
            )
            assert not_found.outcome is ApprovalDecisionOutcome.not_found

            approval_id, _ = await issue(service)
            malformed = await service.decide(
                approval_id,
                approval_token="x" * 9,
                approver=approver(),
                approve=True,
                now=BASE,
            )
            assert malformed.outcome is ApprovalDecisionOutcome.invalid_token
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_naive_timestamps_are_rejected(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, _ = build_service(database)
            with pytest.raises(ApprovalError, match="timezone-aware"):
                await service.request(
                    requester=requester(),
                    spec=spec(),
                    now=datetime(2026, 1, 1, 12, 0),
                )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_pending_request_expires_on_consume_attempt(migrated_database: str) -> None:
    async def scenario() -> None:
        database = DatabaseHarness.open(migrated_database)
        try:
            service, chain_id = build_service(database)
            approval_id, _token = await issue(service)
            late = BASE + timedelta(seconds=901)

            result = await service.consume(
                approval_id,
                principal=requester(),
                request_id="req-approval-1",
                tool_id="mock_email.send",
                action_id="send",
                action_digest=ACTION_DIGEST,
                resource_ids=("email-1",),
                destination=None,
                side_effect_class=SideEffectClass.local_mutation,
                data_class=DataClass.internal,
                policy_version="1.0.0",
                policy_hash=POLICY_HASH,
                now=late,
            )
            assert result.outcome is ApprovalConsumptionOutcome.expired

            row = await stored_request(database, approval_id)
            assert row is not None and row.status == "expired"
            decision = await service.decide(
                approval_id,
                approval_token="x" * 43,
                approver=approver(),
                approve=True,
                now=late,
            )
            assert decision.outcome is ApprovalDecisionOutcome.expired

            payloads = await audit_payloads(database, chain_id)
            assert [item["event_type"] for item in payloads] == [
                AuditEventType.approval_requested.value,
                AuditEventType.approval_expired.value,
            ]
        finally:
            await database.dispose()

    asyncio.run(scenario())

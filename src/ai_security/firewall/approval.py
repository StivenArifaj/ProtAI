"""Human approval workflow bound to one canonical action (blueprint section 13).

This service is authority-free with respect to policy: it can only record a verified
human decision on an already-`ASK_USER` action and turn that approval into one
execution-time grant. It never evaluates or overrides policy, never creates execution
authorizations, and never accepts approval/role claims from model or request text.

The token is generated here with 256 bits of CSPRNG entropy, returned exactly once in
`ApprovalChallenge`, and stored only as a SHA-256 digest. The canonical action digest
itself is produced by the gateway's shared `compute_action_digest`; this module treats
it as an opaque lowercase hex binding. Decision and consumption transitions (plus their
audit events) are committed atomically by `ApprovalRepository`.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ai_security import __version__
from ai_security.audit.models import AuditEvent, AuditEventType
from ai_security.data_security.classification import DataClass
from ai_security.firewall.decision import DecisionReason, FirewallDecision
from ai_security.identity.approver_rules import ApproverRuleError, parse_approver_rule
from ai_security.identity.models import Principal
from ai_security.persistence.approval_repository import (
    ApprovalConsumptionOutcome,
    ApprovalCreate,
    ApprovalDecisionOutcome,
    ApprovalRepository,
    ApprovalRow,
)
from ai_security.policy.models import TOOL_ID_PATTERN
from ai_security.security.constant_time import constant_time_hex32_equal
from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)
from ai_security.tools.base import STABLE_ID_PATTERN, SideEffectClass

APPROVAL_ID_PATTERN = r"^[0-9a-f]{32}$"
TOKEN_DIGEST_PATTERN = r"^[0-9a-f]{64}$"  # noqa: S105 - pattern, not a secret
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_FACTOR_CODE = re.compile(r"^[a-z0-9_]{1,128}$")
_HEX64 = re.compile(TOKEN_DIGEST_PATTERN)
_MAX_RESOURCES = 32
_MAX_FACTOR_CODES = 32
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 86_400


class ApprovalError(ValueError):
    """The approval request or decision input is invalid (fail closed)."""


class ApprovalNotApprovable(ApprovalError):
    """No eligible approver can satisfy the configured rule; do not create a request."""


class ApprovalRequestSpec(BaseModel):
    """Canonical facts for one pending approval; no raw arguments or content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    tool_id: str = Field(min_length=1, max_length=128, pattern=TOOL_ID_PATTERN)
    action_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)
    action_digest: str = Field(pattern=TOKEN_DIGEST_PATTERN)
    resource_ids: tuple[str, ...] = ()
    destination: str | None = Field(default=None, min_length=1, max_length=2_048)
    side_effect_class: SideEffectClass
    data_class: DataClass
    risk_score: int = Field(ge=0, le=100, strict=True)
    risk_version: str = Field(min_length=1, max_length=32)
    risk_factor_codes: tuple[str, ...] = ()
    policy_version: str = Field(min_length=1, max_length=128)
    policy_hash: str = Field(pattern=TOKEN_DIGEST_PATTERN)
    required_approver_rule: str = Field(min_length=1, max_length=256)
    self_approval_allowed: bool = False
    policy_reason: DecisionReason

    @field_validator("resource_ids")
    @classmethod
    def _resources_are_stable_and_bounded(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > _MAX_RESOURCES:
            raise ValueError(f"at most {_MAX_RESOURCES} resources may be bound")
        if len(set(value)) != len(value):
            raise ValueError("resource_ids must be unique")
        for resource_id in value:
            if re.fullmatch(STABLE_ID_PATTERN, resource_id) is None:
                raise ValueError(f"resource id {resource_id!r} is not a stable id")
        return value

    @field_validator("risk_factor_codes")
    @classmethod
    def _factor_codes_are_stable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > _MAX_FACTOR_CODES:
            raise ValueError(f"at most {_MAX_FACTOR_CODES} risk factors may be bound")
        if len(set(value)) != len(value):
            raise ValueError("risk_factor_codes must be unique")
        for code in value:
            if _FACTOR_CODE.fullmatch(code) is None:
                raise ValueError(f"risk factor code {code!r} is not stable")
        return value

    @field_validator("destination")
    @classmethod
    def _destination_is_canonical(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            canonical = canonicalize_destination(value)
        except DestinationCanonicalizationError as exc:
            raise ValueError("destination is not canonicalizable") from exc
        if canonical != value:
            raise ValueError("destination must already be canonical")
        return value

    @model_validator(mode="after")
    def _destination_matches_side_effect(self) -> ApprovalRequestSpec:
        if (
            self.destination is not None
            and self.side_effect_class is not SideEffectClass.external_mutation
        ):
            raise ValueError("only EXTERNAL_MUTATION may bind a destination")
        if not self.policy_reason.value:
            raise ValueError("policy_reason is required")
        return self


@dataclass(frozen=True)
class ApprovalChallenge:
    """Returned once at request creation; the token must go only to the host."""

    approval_id: str
    approval_token: str
    expires_at: datetime
    required_approver_rule: str


@dataclass(frozen=True)
class ApprovalDecision:
    """Outcome of one token-bearing approve/deny attempt."""

    outcome: ApprovalDecisionOutcome
    approval_id: str
    approver_subject_id: str | None = None


@dataclass(frozen=True)
class ApprovalConsumption:
    """Outcome of one execution-time consumption attempt."""

    outcome: ApprovalConsumptionOutcome
    approval_id: str
    approver_subject_id: str | None = None

    @property
    def granted(self) -> bool:
        return self.outcome is ApprovalConsumptionOutcome.consumed


def new_approval_id() -> str:
    return secrets.token_hex(16)


def new_approval_token() -> str:
    return secrets.token_urlsafe(32)


def hash_approval_token(token: str) -> str:
    """SHA-256 hex digest of a well-formed approval token (reject malformed lengths)."""
    if _TOKEN.fullmatch(token) is None:
        raise ApprovalError("approval_token is malformed")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class ApprovalService:
    """Create, decide, and atomically consume approval requests."""

    def __init__(
        self,
        repository: ApprovalRepository,
        *,
        ttl_seconds: int = 900,
        clock: Callable[[], datetime] | None = None,
        component_version: str = __version__,
    ) -> None:
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise ValueError("approval ttl_seconds must be an integer")
        if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError(
                f"approval ttl_seconds must be within [{MIN_TTL_SECONDS}, {MAX_TTL_SECONDS}]"
            )
        self._repository = repository
        self._ttl = ttl_seconds
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._component_version = component_version

    async def request(
        self,
        *,
        requester: Principal,
        spec: ApprovalRequestSpec,
        now: datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> ApprovalChallenge:
        """Create a pending request or raise ``ApprovalNotApprovable``.

        The requester is the already-verified principal. A rule that can only match that
        same principal while self-approval is disabled is provably unsatisfiable and is
        refused here rather than stored as a permanently pending request.
        """
        moment = self._now(now)
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
            raise ApprovalError(
                f"approval ttl_seconds must be within [{MIN_TTL_SECONDS}, {MAX_TTL_SECONDS}]"
            )
        try:
            rule = parse_approver_rule(spec.required_approver_rule)
        except ApproverRuleError as exc:
            raise ApprovalError(f"invalid required_approver_rule: {exc}") from exc
        if not rule.is_satisfiable_for(
            requester=requester, self_approval_allowed=spec.self_approval_allowed
        ):
            raise ApprovalNotApprovable(
                "no eligible approver can satisfy the configured rule; refusing to "
                "create an unsatisfiable request"
            )

        approval_id = new_approval_id()
        token = new_approval_token()
        token_digest = hash_approval_token(token)
        expires_at = moment + timedelta(seconds=ttl)
        create = ApprovalCreate(
            approval_id=approval_id,
            tenant_id=requester.tenant_id,
            requester_subject_id=requester.subject_id,
            request_id=spec.request_id,
            tool_id=spec.tool_id,
            action_id=spec.action_id,
            action_digest=spec.action_digest,
            resource_ids=spec.resource_ids,
            destination=spec.destination,
            side_effect_class=spec.side_effect_class.value,
            data_class=spec.data_class.value,
            risk_score=spec.risk_score,
            risk_version=spec.risk_version,
            risk_factor_codes=spec.risk_factor_codes,
            policy_version=spec.policy_version,
            policy_hash=spec.policy_hash,
            required_approver_rule=spec.required_approver_rule,
            self_approval_allowed=spec.self_approval_allowed,
            token_digest=token_digest,
            created_at=moment,
            expires_at=expires_at,
        )
        event = AuditEvent(
            event_id=secrets.token_hex(16),
            event_type=AuditEventType.approval_requested,
            occurred_at=moment,
            component="firewall.approval",
            component_version=self._component_version,
            request_id=spec.request_id,
            principal_subject_id=requester.subject_id,
            tool_id=spec.tool_id,
            action_id=spec.action_id,
            decision=FirewallDecision.ask_user,
            reason=spec.policy_reason,
            policy_version=spec.policy_version,
            policy_hash=spec.policy_hash,
            side_effect_class=spec.side_effect_class,
            data_class=spec.data_class,
            risk_score=spec.risk_score,
            risk_version=spec.risk_version,
            risk_factor_codes=spec.risk_factor_codes,
            destination=spec.destination,
            resource_ids=spec.resource_ids,
            approval_id=approval_id,
        )
        await self._repository.create(create, audit_payload=event.to_payload())
        return ApprovalChallenge(
            approval_id=approval_id,
            approval_token=token,
            expires_at=expires_at,
            required_approver_rule=spec.required_approver_rule,
        )

    async def decide(
        self,
        approval_id: str,
        *,
        approval_token: str,
        approver: Principal,
        approve: bool,
        now: datetime | None = None,
    ) -> ApprovalDecision:
        """Record one verified decision; the token is consumed here, once."""
        moment = self._now(now)
        if re.fullmatch(APPROVAL_ID_PATTERN, approval_id) is None:
            return ApprovalDecision(
                ApprovalDecisionOutcome.not_found, approval_id, approver.subject_id
            )
        try:
            token_digest = hash_approval_token(approval_token)
        except ApprovalError:
            return ApprovalDecision(
                ApprovalDecisionOutcome.invalid_token, approval_id, approver.subject_id
            )

        def authorize(row: ApprovalRow) -> ApprovalDecisionOutcome | None:
            if row.tenant_id != approver.tenant_id:
                return ApprovalDecisionOutcome.not_eligible
            try:
                rule = parse_approver_rule(row.required_approver_rule)
            except ApproverRuleError:  # pragma: no cover - invalid rows cannot be created
                return ApprovalDecisionOutcome.not_eligible
            if not rule.matches(approver):
                return ApprovalDecisionOutcome.not_eligible
            if approve and approver.subject_id == row.requester_subject_id:
                if not row.self_approval_allowed:
                    return ApprovalDecisionOutcome.self_approval_forbidden
            return None

        def event_for(
            row: ApprovalRow,
            outcome: ApprovalDecisionOutcome,
            approver_subject_id: str,
        ) -> dict[str, object]:
            approved = outcome is ApprovalDecisionOutcome.approved
            return self._row_event(
                row,
                event_type=AuditEventType.approval_decided,
                decision=FirewallDecision.allow if approved else FirewallDecision.block,
                reason=(
                    DecisionReason.approval_granted if approved else DecisionReason.approval_denied
                ),
                occurred_at=moment,
                approver_subject_id=approver_subject_id,
            ).to_payload()

        outcome, _ = await self._repository.decide(
            approval_id,
            token_digest=token_digest,
            now=moment,
            approve=approve,
            approver_subject_id=approver.subject_id,
            approver_tenant_id=approver.tenant_id,
            authorize=authorize,
            audit_decided=event_for,
            audit_expired=lambda row: self._expired_event(row, moment),
        )
        return ApprovalDecision(outcome, approval_id, approver.subject_id)

    async def consume(
        self,
        approval_id: str,
        *,
        principal: Principal,
        request_id: str,
        tool_id: str,
        action_id: str,
        action_digest: str,
        resource_ids: tuple[str, ...],
        destination: str | None,
        policy_version: str,
        policy_hash: str,
        now: datetime | None = None,
    ) -> ApprovalConsumption:
        """Atomically consume one approved request bound to the current action."""
        moment = self._now(now)
        if re.fullmatch(APPROVAL_ID_PATTERN, approval_id) is None:
            return ApprovalConsumption(ApprovalConsumptionOutcome.not_found, approval_id)

        def verify(row: ApprovalRow) -> bool:
            if row.tenant_id != principal.tenant_id:
                return False
            if row.requester_subject_id != principal.subject_id:
                return False
            if row.request_id != request_id:
                return False
            if row.tool_id != tool_id or row.action_id != action_id:
                return False
            if not constant_time_hex32_equal(row.action_digest, action_digest):
                return False
            if row.resource_ids != resource_ids or row.destination != destination:
                return False
            return row.policy_version == policy_version and constant_time_hex32_equal(
                row.policy_hash, policy_hash
            )

        outcome, row = await self._repository.consume(
            approval_id,
            now=moment,
            verify=verify,
            audit_consumed=lambda record: self._row_event(
                record,
                event_type=AuditEventType.approval_consumed,
                decision=FirewallDecision.allow,
                reason=DecisionReason.approval_granted,
                occurred_at=moment,
                approver_subject_id=record.decided_by_subject_id,
            ).to_payload(),
            audit_expired=lambda record: self._expired_event(record, moment),
        )
        return ApprovalConsumption(
            outcome=outcome,
            approval_id=approval_id,
            approver_subject_id=None if row is None else row.decided_by_subject_id,
        )

    # -- audit helpers ----------------------------------------------------------------

    def _row_event(
        self,
        row: ApprovalRow,
        *,
        event_type: AuditEventType,
        decision: FirewallDecision,
        reason: DecisionReason,
        occurred_at: datetime,
        approver_subject_id: str | None,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=secrets.token_hex(16),
            event_type=event_type,
            occurred_at=occurred_at,
            component="firewall.approval",
            component_version=self._component_version,
            request_id=row.request_id,
            principal_subject_id=row.requester_subject_id,
            tool_id=row.tool_id,
            action_id=row.action_id,
            decision=decision,
            reason=reason,
            policy_version=row.policy_version,
            policy_hash=row.policy_hash,
            side_effect_class=SideEffectClass(row.side_effect_class),
            data_class=DataClass(row.data_class),
            risk_score=row.risk_score,
            risk_version=row.risk_version,
            risk_factor_codes=row.risk_factor_codes,
            destination=row.destination,
            resource_ids=row.resource_ids,
            approval_id=row.approval_id,
            approver_subject_id=approver_subject_id,
        )

    def _expired_event(self, row: ApprovalRow, occurred_at: datetime) -> dict[str, object]:
        return self._row_event(
            row,
            event_type=AuditEventType.approval_expired,
            decision=FirewallDecision.block,
            reason=DecisionReason.approval_expired,
            occurred_at=occurred_at,
            approver_subject_id=None,
        ).to_payload()

    def _now(self, value: datetime | None) -> datetime:
        now = value if value is not None else self._clock()
        if now.utcoffset() is None:
            raise ApprovalError("approval timestamps must be timezone-aware")
        return now


__all__ = [
    "APPROVAL_ID_PATTERN",
    "ApprovalChallenge",
    "ApprovalConsumption",
    "ApprovalDecision",
    "ApprovalError",
    "ApprovalNotApprovable",
    "ApprovalRequestSpec",
    "ApprovalService",
    "hash_approval_token",
    "new_approval_id",
    "new_approval_token",
]

"""Phase 8 business routes (blueprint §18.1; ADR-015).

Every route authenticates the host in middleware, verifies the host-signed principal
assertion in the exact signed body, and never accepts a client-supplied decision, risk,
approval outcome, call id, resource target, destination, deadline, or request id.
``POST /v1/requests`` is the sole execution surface; the other two routes are a
non-executing policy preview and a one-time approval decision.
"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from ai_security.api.errors import ApiError, read_json_object
from ai_security.api.ingress import ApiIngress
from ai_security.api.rate_limit import FixedWindowRateLimiter
from ai_security.api.runtime import DemoRuntime
from ai_security.api.schemas import (
    ApprovalDecisionBody,
    ApprovalDecisionResponse,
    ApprovalGrant,
    RequestCreateBody,
    RequestResponse,
    RequestState,
    RiskSummary,
    ToolEvaluationResponse,
    ToolPreviewBody,
)
from ai_security.firewall.approval import (
    APPROVAL_ID_PATTERN,
    ApprovalError,
    ApprovalNotApprovable,
    ApprovalRequestSpec,
    ApprovalService,
)
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import (
    ProposedToolCall,
    RequestContext,
    ToolInvocationResult,
)
from ai_security.identity.assertion import PrincipalAssertion
from ai_security.identity.host_auth import VerifiedHostContext
from ai_security.identity.models import Principal
from ai_security.input_defense.models import Disposition
from ai_security.intent.models import IntentResolution, IntentResolutionStatus
from ai_security.persistence.approval_repository import (
    ApprovalDecisionOutcome,
    ApprovalRepository,
)
from ai_security.policy.models import PolicyBundle
from ai_security.settings import Settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1")

_APPROVAL_ID = re.compile(APPROVAL_ID_PATTERN)


# -- request creation ----------------------------------------------------------------


@router.post(
    "/requests",
    response_model=RequestResponse,
    responses={
        202: {"model": RequestResponse},
        400: {"description": "invalid request"},
        403: {"description": "denied or rejected"},
        429: {"description": "rate limited"},
        503: {"description": "dependency unavailable"},
    },
)
async def create_request(request: Request) -> Any:
    request_id = _new_request_id()
    payload = await read_json_object(request, request_id=request_id)
    body = await _validated_body(RequestCreateBody, request, payload, request_id)
    ingress = _ingress(request)
    principal = await ingress.authenticate(
        request_id=request_id,
        verified_host=_verified_host(request),
        assertion=body.principal,
    )

    limiter = _limiter(request)
    settings = _settings(request)
    if not limiter.allow("requests", _identity(principal), settings.rate_limit_requests_per_minute):
        raise ApiError(
            429,
            "rate_limited",
            "Too many requests; nothing was executed.",
            request_id=request_id,
            state=RequestState.failed.value,
        )

    report = await ingress.inspect_input(request_id=request_id, principal=principal, text=body.text)
    if report.disposition is Disposition.reject:
        raise ApiError(
            403,
            "input_rejected",
            "The request was rejected by input inspection.",
            request_id=request_id,
            state=RequestState.rejected.value,
        )
    if report.disposition is Disposition.quarantine:
        raise ApiError(
            403,
            "input_quarantined",
            "The request was quarantined by input inspection.",
            request_id=request_id,
            state=RequestState.rejected.value,
        )

    received_at = _now()
    resolution = await ingress.extract(
        request_id=request_id,
        principal=principal,
        text=body.text,
        received_at=received_at,
    )
    return await _handle_resolution(
        request=request,
        request_id=request_id,
        principal=principal,
        resolution=resolution,
        received_at=received_at,
    )


async def _handle_resolution(
    *,
    request: Request,
    request_id: str,
    principal: Principal,
    resolution: IntentResolution,
    received_at: datetime,
) -> Any:
    if resolution.status is IntentResolutionStatus.requires_clarification:
        return RequestResponse(
            request_id=request_id,
            state=RequestState.requires_clarification,
            message="Clarification is required before any action.",
            clarification=resolution.clarification_question or "Please clarify the request.",
        )
    if resolution.status is IntentResolutionStatus.rejected:
        raise ApiError(
            403,
            "request_rejected",
            "The request was rejected by intent extraction; nothing was executed.",
            request_id=request_id,
            state=RequestState.rejected.value,
        )
    if resolution.status is IntentResolutionStatus.extractor_unavailable:
        raise ApiError(
            503,
            "model_unavailable",
            "Intent extraction is unavailable; nothing was executed.",
            request_id=request_id,
            state=RequestState.failed.value,
        )
    if resolution.status is not IntentResolutionStatus.active or resolution.manifest is None:
        raise ApiError(
            502,
            "model_invalid_response",
            "Intent extraction did not produce a usable result; nothing was executed.",
            request_id=request_id,
            state=RequestState.failed.value,
        )

    runtime = _runtime(request)
    request_context = RequestContext(request_id=request_id)
    settings = _settings(request)
    deadline = received_at + timedelta(seconds=settings.request_timeout_seconds)
    limiter = _limiter(request)
    limit = settings.rate_limit_tool_calls_per_minute
    identity = _identity(principal)

    def reserve_tool_calls(count: int) -> bool:
        return limiter.allow_many("tool_calls", identity, limit, count)

    outcome = await runtime.execute(
        principal=principal,
        request_context=request_context,
        manifest=resolution.manifest,
        deadline=deadline,
        reserve_tool_calls=reserve_tool_calls,
    )
    if outcome.state is RequestState.approval_required:
        if outcome.approval_facts is None:  # pragma: no cover - runtime invariant
            raise ApiError(
                502,
                "tool_evaluation_failed",
                "The approval request could not be built safely; nothing was executed.",
                request_id=request_id,
                state=RequestState.failed.value,
            )
        grant = await _create_approval(
            request=request,
            request_id=request_id,
            principal=principal,
            facts=outcome.approval_facts,
        )
        return JSONResponse(
            status_code=202,
            content=RequestResponse(
                request_id=request_id,
                state=RequestState.approval_required,
                message=outcome.message,
                approval=grant,
            ).model_dump(mode="json"),
        )
    if outcome.state in (RequestState.completed, RequestState.no_action):
        return RequestResponse(
            request_id=request_id,
            state=outcome.state,
            message=outcome.message,
            result=outcome.result,
        )
    raise ApiError(
        outcome.http_status,
        outcome.error_code or "request_failed",
        outcome.message,
        request_id=request_id,
        state=outcome.state.value,
    )


async def _create_approval(
    *,
    request: Request,
    request_id: str,
    principal: Principal,
    facts: ToolInvocationResult,
) -> ApprovalGrant:
    bundle = _bundle(request)
    tool_policy = bundle.tool_policy(facts.tool_id)
    if tool_policy is None or not tool_policy.approval_eligible:
        raise ApiError(
            403,
            "approval_not_allowed",
            "The action is not eligible for approval and was not executed.",
            request_id=request_id,
            state=RequestState.denied.value,
        )
    if (
        facts.action_digest is None
        or facts.data_class is None
        or facts.side_effect_class is None
        or facts.risk is None
        or facts.required_approver_rule is None
    ):  # pragma: no cover - gateway invariant for an approval-eligible ASK_USER
        raise ApiError(
            502,
            "tool_evaluation_failed",
            "The approval request could not be built safely; nothing was executed.",
            request_id=request_id,
            state=RequestState.failed.value,
        )
    spec = ApprovalRequestSpec(
        request_id=request_id,
        tool_id=facts.tool_id,
        action_id=facts.action_id,
        action_digest=facts.action_digest,
        resource_ids=facts.resource_ids,
        destination=facts.destination,
        side_effect_class=facts.side_effect_class,
        data_class=facts.data_class,
        risk_score=facts.risk.score,
        risk_version=facts.risk.version,
        risk_factor_codes=facts.risk.factor_codes,
        policy_version=facts.policy_version,
        policy_hash=facts.policy_hash,
        required_approver_rule=facts.required_approver_rule,
        self_approval_allowed=tool_policy.self_approval_allowed,
        policy_reason=facts.reason,
    )
    try:
        challenge = await _approval_service(request).request(requester=principal, spec=spec)
    except ApprovalNotApprovable as exc:
        raise ApiError(
            409,
            "approval_not_approvable",
            "No eligible approver can satisfy the configured rule; nothing was executed.",
            request_id=request_id,
            state=RequestState.denied.value,
        ) from exc
    except ApprovalError as exc:  # pragma: no cover - gateway facts are validated
        raise ApiError(
            500,
            "internal_error",
            "The approval request could not be created; nothing was executed.",
            request_id=request_id,
            state=RequestState.failed.value,
        ) from exc
    except Exception as exc:  # noqa: BLE001 - storage/audit outage must fail closed
        logger.error("approval creation failed for request %s", request_id)
        raise ApiError(
            503,
            "dependency_unavailable",
            "Approval storage is unavailable; nothing was executed.",
            request_id=request_id,
            state=RequestState.failed.value,
        ) from exc
    return ApprovalGrant(
        approval_id=challenge.approval_id,
        approval_token=challenge.approval_token,
        expires_at=challenge.expires_at,
        required_approver_rule=challenge.required_approver_rule,
    )


# -- preview -------------------------------------------------------------------------


@router.post("/tool-calls/evaluate", response_model=ToolEvaluationResponse)
async def evaluate_tool_call(request: Request) -> ToolEvaluationResponse:
    request_id = _new_request_id()
    payload = await read_json_object(request, request_id=request_id)
    body = await _validated_body(ToolPreviewBody, request, payload, request_id)
    ingress = _ingress(request)
    principal = await ingress.authenticate(
        request_id=request_id,
        verified_host=_verified_host(request),
        assertion=body.principal,
    )
    settings = _settings(request)
    limiter = _limiter(request)
    if not limiter.allow(
        "tool_calls", _identity(principal), settings.rate_limit_tool_calls_per_minute
    ):
        raise ApiError(
            429,
            "rate_limited",
            "Too many tool proposals; nothing was evaluated.",
            request_id=request_id,
            state=RequestState.failed.value,
        )

    proposal = ProposedToolCall(
        call_id=_new_call_id(),
        request_id=request_id,
        principal_subject_id=principal.subject_id,
        tool_id=body.tool_id,
        action_id=body.action_id,
        arguments=body.arguments,
        deadline=_now() + timedelta(seconds=settings.request_timeout_seconds),
    )
    evaluation = await _gateway(request).evaluate_tool(
        principal=principal,
        request_context=RequestContext(request_id=request_id),
        proposal=proposal,
        receipt_already_audited=True,
    )
    risk = None
    if evaluation.risk is not None:
        risk = RiskSummary(
            score=evaluation.risk.score,
            version=evaluation.risk.version,
            factor_codes=evaluation.risk.factor_codes,
        )
    return ToolEvaluationResponse(
        request_id=request_id,
        call_id=evaluation.call_id,
        tool_id=evaluation.tool_id,
        action_id=evaluation.action_id,
        decision=evaluation.decision,
        reason=evaluation.reason,
        risk=risk,
        policy_version=evaluation.policy_version,
        policy_hash=evaluation.policy_hash,
        approval_required=evaluation.approval_required,
        required_approver_rule=evaluation.required_approver_rule,
        data_class=evaluation.data_class,
        side_effect_class=evaluation.side_effect_class,
    )


# -- approval decision ---------------------------------------------------------------


@router.post("/approvals/{approval_id}/decision", response_model=ApprovalDecisionResponse)
async def decide_approval(approval_id: str, request: Request) -> ApprovalDecisionResponse:
    fallback_request_id = _new_request_id()
    payload = await read_json_object(request, request_id=fallback_request_id)
    body = await _validated_body(ApprovalDecisionBody, request, payload, fallback_request_id)
    ingress = _ingress(request)
    principal = await ingress.authenticate_without_receipt(
        request_id=fallback_request_id,
        verified_host=_verified_host(request),
        assertion=body.principal,
    )

    settings = _settings(request)
    limiter = _limiter(request)
    if not limiter.allow(
        "approval_decisions",
        _identity(principal),
        settings.rate_limit_approval_decisions_per_minute,
    ):
        raise ApiError(
            429,
            "rate_limited",
            "Too many approval decisions; no decision was recorded.",
            request_id=fallback_request_id,
            state=RequestState.failed.value,
        )

    if _APPROVAL_ID.fullmatch(approval_id) is None:
        raise ApiError(
            404,
            "approval_not_found",
            "The approval was not found.",
            request_id=fallback_request_id,
        )
    repository = _approval_repository(request)
    request_id = await repository.request_id_for(approval_id, tenant_id=principal.tenant_id)
    if request_id is None:
        raise ApiError(
            404,
            "approval_not_found",
            "The approval was not found.",
            request_id=fallback_request_id,
        )

    decision = await _approval_service(request).decide(
        approval_id,
        approval_token=body.approval_token,
        approver=principal,
        approve=body.approve,
    )
    if decision.outcome in (
        ApprovalDecisionOutcome.approved,
        ApprovalDecisionOutcome.denied,
    ):
        return ApprovalDecisionResponse(
            request_id=request_id,
            approval_id=approval_id,
            status=decision.outcome.value,
        )
    status_code, code = _decision_error(decision.outcome)
    raise ApiError(
        status_code,
        code,
        "The approval decision was not accepted.",
        request_id=request_id,
    )


def _decision_error(outcome: ApprovalDecisionOutcome) -> tuple[int, str]:
    match outcome:
        case ApprovalDecisionOutcome.not_found:
            return 404, "approval_not_found"
        case ApprovalDecisionOutcome.invalid_token:
            return 400, "approval_token_invalid"
        case ApprovalDecisionOutcome.expired:
            return 409, "approval_expired"
        case ApprovalDecisionOutcome.not_pending:
            return 409, "approval_not_pending"
        case ApprovalDecisionOutcome.not_eligible:
            return 409, "approval_not_eligible"
        case ApprovalDecisionOutcome.self_approval_forbidden:
            return 409, "self_approval_forbidden"
        case _:  # pragma: no cover - enum exhaustiveness guard
            return 409, "approval_not_accepted"


# -- helpers -------------------------------------------------------------------------


async def _validated_body[ModelT: BaseModel](
    model: type[ModelT],
    request: Request,
    payload: dict[str, Any],
    request_id: str,
) -> ModelT:
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        if not await _charge_invalid_request(request, payload):
            raise ApiError(
                429,
                "rate_limited",
                "Too many invalid requests; nothing was executed.",
                request_id=request_id,
                state=RequestState.rejected.value,
            ) from exc
        raise ApiError(
            400,
            "invalid_request",
            "The request body does not match the required schema.",
            request_id=request_id,
            state=RequestState.rejected.value,
        ) from exc


async def _charge_invalid_request(request: Request, payload: dict[str, Any]) -> bool:
    """Charge an authenticated invalid body to its bounded bucket.

    Returns ``False`` only when a verified principal has exhausted the invalid-request
    bucket. A body without a verifiable principal is never charged (no unauthenticated
    caller can spend another identity's budget); limiter failures never change the
    response, because this bucket is abuse mitigation, not an authorization decision.
    """
    raw_principal = payload.get("principal")
    if not isinstance(raw_principal, dict):
        return True
    try:
        assertion = PrincipalAssertion.model_validate(raw_principal)
        principal = _ingress(request).resolve_principal(
            verified_host=_verified_host(request), assertion=assertion
        )
    except Exception:  # noqa: BLE001 - bucketing must never change the response
        return True
    try:
        return _limiter(request).allow(
            "invalid_requests",
            _identity(principal),
            _settings(request).rate_limit_invalid_requests_per_minute,
        )
    except Exception:  # noqa: BLE001 - bucketing must never change the response
        logger.error("invalid-request limiter failed")
        return True


def _verified_host(request: Request) -> VerifiedHostContext | None:
    state = request.scope.get("state")
    if not isinstance(state, dict):
        return None
    context = state.get("host_auth")
    return context if isinstance(context, VerifiedHostContext) else None


def _identity(principal: Principal) -> str:
    return f"{principal.tenant_id or '-'}:{principal.subject_id}"


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _bundle(request: Request) -> PolicyBundle:
    return cast(PolicyBundle, request.app.state.policy_bundle)


def _ingress(request: Request) -> ApiIngress:
    return cast(ApiIngress, request.app.state.api_ingress)


def _runtime(request: Request) -> DemoRuntime:
    return cast(DemoRuntime, request.app.state.demo_runtime)


def _limiter(request: Request) -> FixedWindowRateLimiter:
    return cast(FixedWindowRateLimiter, request.app.state.request_limiter)


def _gateway(request: Request) -> ToolGateway:
    return cast(ToolGateway, request.app.state.tool_gateway)


def _approval_service(request: Request) -> ApprovalService:
    return cast(ApprovalService, request.app.state.approval_service)


def _approval_repository(request: Request) -> ApprovalRepository:
    return cast(ApprovalRepository, request.app.state.approval_repository)


def _now() -> datetime:
    return datetime.now(UTC)


def _new_request_id() -> str:
    return f"req-{secrets.token_hex(16)}"


def _new_call_id() -> str:
    return f"call-{secrets.token_hex(16)}"


__all__ = ["router"]

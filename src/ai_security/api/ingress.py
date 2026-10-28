"""HTTP ingress controls shared by the Phase 8 business routes (ADR-015).

This module owns the parts of a request that must happen before any intent, policy, or
tool processing:

1. turn the host-signed principal assertion into a verified :class:`Principal` (the
   host HMAC has already authenticated the request in middleware);
2. persist exactly one ``REQUEST_RECEIVED``/``PRINCIPAL_RESOLVED`` pair for an accepted
   request, or one best-effort ``PRINCIPAL_REJECTED`` for a rejected assertion;
3. run bounded input inspection and persist its redacted ``INPUT_INSPECTED`` evidence.

Accepted-request audit failures are fail-closed: a request that cannot be correlated
never reaches intent, policy, or a tool. The input detector is advisory/narrowing only
(ADR-010); its disposition can gate execution, but it can never authorize one.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from ai_security import __version__
from ai_security.api.errors import ApiError
from ai_security.api.schemas import RequestState
from ai_security.audit.models import AuditEvent, AuditEventType, InputAuditRecord
from ai_security.audit.writer import AuditRecorder, AuditWriteError
from ai_security.identity.assertion import PrincipalAssertion
from ai_security.identity.host_auth import VerifiedHostContext
from ai_security.identity.models import Principal, PrincipalResolutionError
from ai_security.identity.resolver import PrincipalResolver
from ai_security.input_defense.models import IntakeReport, TrustLabel
from ai_security.input_defense.service import InputDefenseService
from ai_security.intent.models import IntentResolution
from ai_security.intent.service import IntentManifestService
from ai_security.policy.models import PolicyBundle

logger = logging.getLogger(__name__)

COMPONENT: Literal["api.ingress"] = "api.ingress"
INPUT_SOURCE_ID = "api.requests.text"
INPUT_SEGMENT_ID = "text"


class ApiIngress:
    """Verified-principal, receipt, and input-inspection orchestration."""

    def __init__(
        self,
        *,
        resolver: PrincipalResolver,
        recorder: AuditRecorder,
        input_defense: InputDefenseService,
        intent_service: IntentManifestService,
        bundle: PolicyBundle,
        clock: Callable[[], datetime] | None = None,
        component_version: str = __version__,
    ) -> None:
        self._resolver = resolver
        self._recorder = recorder
        self._input_defense = input_defense
        self._intent_service = intent_service
        self._bundle = bundle
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._component_version = component_version

    # -- principal resolution ---------------------------------------------------------

    def resolve_principal(
        self,
        *,
        verified_host: VerifiedHostContext | None,
        assertion: PrincipalAssertion,
    ) -> Principal:
        """Resolve the signed assertion or raise ``PrincipalResolutionError``.

        This is intentionally side-effect free so callers can use it for rate-limit
        bucketing before deciding whether a request is processed.
        """
        return self._resolver.resolve(verified_host, assertion=assertion)

    async def authenticate(
        self,
        *,
        request_id: str,
        verified_host: VerifiedHostContext | None,
        assertion: PrincipalAssertion,
    ) -> Principal:
        """Resolve the principal and persist the one accepted-request receipt pair."""
        try:
            principal = self.resolve_principal(verified_host=verified_host, assertion=assertion)
        except PrincipalResolutionError as exc:
            await self._record_rejection(request_id=request_id, error_type=_rejection_code(exc))
            raise ApiError(
                403,
                "principal_rejected",
                "The host-signed principal assertion was rejected.",
                request_id=request_id,
                state=RequestState.rejected.value,
            ) from exc

        try:
            await self._record_accepted(request_id=request_id, principal=principal)
        except AuditWriteError as exc:
            raise ApiError(
                503,
                "dependency_unavailable",
                "The request could not be recorded safely; nothing was executed.",
                request_id=request_id,
                state=RequestState.failed.value,
            ) from exc
        return principal

    async def authenticate_without_receipt(
        self,
        *,
        request_id: str,
        verified_host: VerifiedHostContext | None,
        assertion: PrincipalAssertion,
    ) -> Principal:
        """Resolve the principal without emitting a second request receipt.

        The approval decision route reuses the original request's correlation id, so it
        must not create another ``REQUEST_RECEIVED``/``PRINCIPAL_RESOLVED`` pair for that
        id. An assertion rejection still produces only ``PRINCIPAL_REJECTED``.
        """
        try:
            return self.resolve_principal(verified_host=verified_host, assertion=assertion)
        except PrincipalResolutionError as exc:
            await self._record_rejection(request_id=request_id, error_type=_rejection_code(exc))
            raise ApiError(
                403,
                "principal_rejected",
                "The host-signed principal assertion was rejected.",
                request_id=request_id,
                state=RequestState.rejected.value,
            ) from exc

    async def _record_accepted(self, *, request_id: str, principal: Principal) -> None:
        await self._recorder.record(
            self._event(
                AuditEventType.request_received,
                request_id=request_id,
                principal_subject_id=principal.subject_id,
            )
        )
        await self._recorder.record(
            self._event(
                AuditEventType.principal_resolved,
                request_id=request_id,
                principal_subject_id=principal.subject_id,
            )
        )

    async def _record_rejection(self, *, request_id: str, error_type: str) -> None:
        """Rejection evidence is best effort; it never changes the denial itself."""
        try:
            await self._recorder.record(
                self._event(
                    AuditEventType.principal_rejected,
                    request_id=request_id,
                    principal_subject_id=None,
                    error_type=error_type,
                )
            )
        except AuditWriteError:
            logger.error("principal rejection audit persistence failed for request %s", request_id)

    # -- input inspection -------------------------------------------------------------

    async def inspect_input(
        self, *, request_id: str, principal: Principal, text: str
    ) -> IntakeReport:
        """Inspect bounded request text and persist redacted evidence (fail closed)."""
        try:
            report = self._input_defense.inspect(
                text.encode("utf-8"),
                content_type="text/plain",
                trust_label=TrustLabel.authenticated_user,
                source_id=INPUT_SOURCE_ID,
                segment_id=INPUT_SEGMENT_ID,
            )
        except Exception as exc:  # noqa: BLE001 - detector failure must be explicit
            logger.error("input inspection failed for request %s", request_id)
            raise ApiError(
                503,
                "dependency_unavailable",
                "Input inspection is unavailable; nothing was executed.",
                request_id=request_id,
                state=RequestState.failed.value,
            ) from exc

        try:
            await self._recorder.record(
                self._event(
                    AuditEventType.input_inspected,
                    request_id=request_id,
                    principal_subject_id=principal.subject_id,
                    input_record=InputAuditRecord.from_report(report),
                )
            )
        except AuditWriteError as exc:
            raise ApiError(
                503,
                "dependency_unavailable",
                "Input inspection could not be recorded safely; nothing was executed.",
                request_id=request_id,
                state=RequestState.failed.value,
            ) from exc
        return report

    # -- intent -----------------------------------------------------------------------

    async def extract(
        self,
        *,
        request_id: str,
        principal: Principal,
        text: str,
        received_at: datetime,
    ) -> IntentResolution:
        """Delegate to the sole manifest issuer; a failure never yields authority."""
        return await self._intent_service.extract_and_issue(
            request_id=request_id,
            principal=principal,
            text=text,
            received_at=received_at,
        )

    # -- helpers ----------------------------------------------------------------------

    def _event(
        self,
        event_type: AuditEventType,
        *,
        request_id: str,
        principal_subject_id: str | None,
        input_record: InputAuditRecord | None = None,
        error_type: str | None = None,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=secrets.token_hex(16),
            event_type=event_type,
            occurred_at=self._now(),
            component=COMPONENT,
            component_version=self._component_version,
            request_id=request_id,
            principal_subject_id=principal_subject_id,
            policy_version=self._bundle.version,
            policy_hash=self._bundle.combined_hash,
            error_type=error_type,
            input=input_record,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.utcoffset() is None:
            raise RuntimeError("ingress clock must return a timezone-aware datetime")
        return value


def _rejection_code(exc: PrincipalResolutionError) -> str:
    code = getattr(exc, "code", None)
    value = getattr(code, "value", None)
    if isinstance(value, str) and 1 <= len(value) <= 64:
        return value
    return "principal_rejected"


__all__ = ["ApiIngress", "COMPONENT", "INPUT_SEGMENT_ID", "INPUT_SOURCE_ID"]

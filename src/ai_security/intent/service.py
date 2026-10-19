"""Server-side extract-and-issue orchestration (blueprint §§8.2-8.3).

The service is the only manifest issuer. It validates every extractor-proposed
constraint against the loaded policy and the registered action's argument schema,
resolves relative dates from the verified principal's trusted timezone, and issues a
short-lived manifest bound to the request/principal/policy. Any malformed output,
provider outage, unsupported constraint, or missing trusted timezone yields either a
clarification/rejection or a typed failure with **no manifest**.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import get_args, get_origin

from ai_security.identity.models import Principal
from ai_security.intent.extractors import (
    IntentExtractor,
    IntentExtractorUnavailable,
    InvalidIntentExtraction,
)
from ai_security.intent.models import (
    IntentConstraint,
    IntentExtraction,
    IntentExtractionRequest,
    IntentExtractionStatus,
    IntentResolution,
    IntentResolutionStatus,
    _issue_intent_manifest,
)
from ai_security.intent.time_window import resolve_relative_window
from ai_security.policy.models import PolicyBundle
from ai_security.tools.registry import ToolRegistration, ToolRegistry

DEFAULT_MANIFEST_TTL_SECONDS = 300
MAX_MANIFEST_TTL_SECONDS = 3_600

_SCALAR_ANNOTATIONS = (str, int, bool)


class _ConstraintConfigError(ValueError):
    """An extractor constraint cannot be enforced against the registry/policy."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _annotation_accepts(annotation: object, value: object) -> bool:
    origin = get_origin(annotation)
    candidates = get_args(annotation) if origin is not None else (annotation,)
    if origin is not None and type(None) in candidates:
        if value is None:
            return True
        candidates = tuple(item for item in candidates if item is not type(None))
    for candidate in candidates:
        if candidate is bool:
            if isinstance(value, bool):
                return True
        elif candidate is int:
            if isinstance(value, int) and not isinstance(value, bool):
                return True
        elif candidate is str:
            if isinstance(value, str):
                return True
    return False


def _validate_parameter_constraints(
    constraint: IntentConstraint, registration: ToolRegistration
) -> None:
    fields = registration.argument_schema.model_fields
    reserved = set(registration.resource_id_arguments)
    if registration.destination_argument is not None:
        reserved.add(registration.destination_argument)
    for name, values in constraint.allowed_parameter_values.items():
        field = fields.get(name)
        if field is None:
            raise _ConstraintConfigError("unknown_parameter")
        if name in reserved:
            raise _ConstraintConfigError("reserved_parameter")
        if field.annotation not in _SCALAR_ANNOTATIONS:
            raise _ConstraintConfigError("non_scalar_parameter")
        for value in values:
            if not _annotation_accepts(field.annotation, value):
                raise _ConstraintConfigError("parameter_type_mismatch")


def _validate_constraint(
    constraint: IntentConstraint,
    *,
    registry: ToolRegistry,
    bundle: PolicyBundle,
) -> None:
    registered = registry.resolve(constraint.tool_id, constraint.action_id)
    if registered is None:
        raise _ConstraintConfigError("unregistered_constraint_action")
    if bundle.tool_policy(constraint.tool_id) is None:
        raise _ConstraintConfigError("constraint_action_absent_from_policy")
    registration = registered.registration

    if constraint.allowed_resource_ids:
        if not registration.resource_id_arguments or not registration.resource_prefixes:
            raise _ConstraintConfigError("resource_scope_not_applicable")
        for resource_id in constraint.allowed_resource_ids:
            if not resource_id.startswith(registration.resource_prefixes):
                raise _ConstraintConfigError("resource_outside_adapter_scope")

    if constraint.allowed_destinations:
        if registration.destination_argument is None:
            raise _ConstraintConfigError("destination_scope_not_applicable")
        if not set(constraint.allowed_destinations).issubset(registration.destinations):
            raise _ConstraintConfigError("destination_outside_adapter_capability")

    _validate_parameter_constraints(constraint, registration)


def _failed(error_code: str) -> IntentResolution:
    return IntentResolution(
        status=IntentResolutionStatus.invalid_extraction,
        error_code=error_code,
    )


class IntentManifestService:
    """Extract one request and issue a bound manifest only on fully valid output."""

    def __init__(
        self,
        *,
        extractor: IntentExtractor,
        registry: ToolRegistry,
        bundle: PolicyBundle,
        clock: Callable[[], datetime] | None = None,
        manifest_ttl_seconds: int = DEFAULT_MANIFEST_TTL_SECONDS,
    ) -> None:
        if not 1 <= manifest_ttl_seconds <= MAX_MANIFEST_TTL_SECONDS:
            raise ValueError(f"manifest_ttl_seconds must be in [1, {MAX_MANIFEST_TTL_SECONDS}]")
        self._extractor = extractor
        self._registry = registry
        self._bundle = bundle
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._ttl = timedelta(seconds=manifest_ttl_seconds)

    async def extract_and_issue(
        self,
        *,
        request_id: str,
        principal: Principal,
        text: str,
        received_at: datetime | None = None,
    ) -> IntentResolution:
        now = self._now()
        request_time = received_at if received_at is not None else now
        if request_time.utcoffset() is None:
            return _failed("invalid_request_time")
        if request_time > now:
            return _failed("request_time_in_future")

        try:
            extraction_request = IntentExtractionRequest(
                request_id=request_id,
                principal_subject_id=principal.subject_id,
                text=text,
                received_at=request_time,
            )
        except ValueError:
            return _failed("invalid_extraction_request")

        try:
            extraction = await self._extractor.extract(extraction_request)
        except IntentExtractorUnavailable:
            return IntentResolution(
                status=IntentResolutionStatus.extractor_unavailable,
                error_code="extractor_unavailable",
                extractor_version=getattr(self._extractor, "extractor_version", None),
            )
        except InvalidIntentExtraction:
            return _failed("invalid_extraction")
        except Exception:  # noqa: BLE001 - extractor boundary must never grant
            return IntentResolution(
                status=IntentResolutionStatus.extractor_unavailable,
                error_code="extractor_unavailable",
                extractor_version=getattr(self._extractor, "extractor_version", None),
            )

        if extraction.status is IntentExtractionStatus.requires_clarification:
            return IntentResolution(
                status=IntentResolutionStatus.requires_clarification,
                clarification_question=extraction.clarification_question,
                extractor_version=extraction.extractor_version,
            )
        if extraction.status is IntentExtractionStatus.rejected:
            return IntentResolution(
                status=IntentResolutionStatus.rejected,
                clarification_question=extraction.clarification_question,
                extractor_version=extraction.extractor_version,
            )

        try:
            self._validate_extraction(extraction)
        except _ConstraintConfigError as exc:
            return _failed(exc.code)

        time_window = None
        if extraction.relative_time_scope is not None:
            if principal.timezone is None:
                return IntentResolution(
                    status=IntentResolutionStatus.requires_clarification,
                    clarification_question=(
                        "A trusted IANA timezone is required to resolve a relative date; "
                        "none was present in the verified principal context."
                    ),
                    error_code="trusted_timezone_required",
                    extractor_version=extraction.extractor_version,
                )
            try:
                time_window = resolve_relative_window(
                    scope=extraction.relative_time_scope,
                    reference=request_time,
                    timezone_name=principal.timezone,
                )
            except ValueError:
                return _failed("invalid_timezone")

        manifest = _issue_intent_manifest(
            manifest_id=secrets.token_hex(32),
            request_id=request_id,
            principal_subject_id=principal.subject_id,
            tenant_id=principal.tenant_id,
            policy_version=self._bundle.version,
            policy_hash=self._bundle.combined_hash,
            extractor_version=extraction.extractor_version,
            created_at=now,
            expires_at=now + self._ttl,
            goal_digest=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            constraints=extraction.constraints,
            time_window=time_window,
        )
        return IntentResolution(
            status=IntentResolutionStatus.active,
            manifest=manifest,
            extractor_version=extraction.extractor_version,
        )

    def _validate_extraction(self, extraction: IntentExtraction) -> None:
        for constraint in extraction.constraints:
            _validate_constraint(constraint, registry=self._registry, bundle=self._bundle)
        if extraction.relative_time_scope is not None and not extraction.constraints:
            raise _ConstraintConfigError("relative_time_without_constraints")

    def _now(self) -> datetime:
        value = self._clock()
        if value.utcoffset() is None:
            raise RuntimeError("intent clock must return a timezone-aware datetime")
        return value


__all__ = [
    "DEFAULT_MANIFEST_TTL_SECONDS",
    "IntentManifestService",
    "MAX_MANIFEST_TTL_SECONDS",
]

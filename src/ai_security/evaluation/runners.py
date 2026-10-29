"""Real-implementation evaluation runners (blueprint sections 19.2-19.3).

Each runner observes the shipped component instead of re-implementing its logic:

- input detection: ``InputDefenseService.inspect``;
- DLP egress/response: ``OutputDefenseService.inspect_egress``/``inspect_output`` and
  ``redact_payload``;
- risk: ``assess_risk``;
- intent: ``IntentManifestService`` with the deterministic mock extractor and
  transcript-backed local-model extractor;
- authorization: the real ``ToolGateway`` + ``PolicyEngine`` + ``build_registry`` + real
  output DLP over in-memory mock adapters.

The harness is an observer. It adds no route, bypasses no authentication/policy/DLP,
writes no production audit record, and never turns a metric into authority. The
authorization runner counts actual adapter calls and actual sink writes; a denied case
with a positive count is reported as an unauthorized side effect.
"""

from __future__ import annotations

import base64
import json
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from ai_security.audit.models import AuditEvent
from ai_security.data_security.dlp import (
    DlpOutcome,
    LoadedOutputDlpConfig,
    OutputDefenseService,
    load_output_dlp_config,
)
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.models import (
    ProposedToolCall,
    RequestContext,
    ToolInvocationResult,
)
from ai_security.firewall.policy_engine import PolicyEngine
from ai_security.firewall.risk_engine import RISK_ENGINE_VERSION, assess_risk
from ai_security.identity.models import Principal
from ai_security.input_defense.config import (
    LoadedInputDefenseConfig,
    load_input_defense_config,
)
from ai_security.input_defense.models import Disposition, FindingCode
from ai_security.input_defense.service import InputDefenseService
from ai_security.intent.extractors import (
    LOCAL_MODEL_EXTRACTOR_VERSION,
    MOCK_EXTRACTOR_VERSION,
    IntentExtractor,
    LocalModelIntentExtractor,
    MockIntentExtractor,
)
from ai_security.intent.models import IntentResolutionStatus
from ai_security.intent.service import IntentManifestService
from ai_security.persistence.audit_repository import AppendedAuditEvent
from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.models import PolicyBundle, ToolPolicy
from ai_security.tools.base import (
    ExecutionAuthorization,
    SideEffectClass,
    ToolAdapter,
    ToolArguments,
    ToolResult,
)
from ai_security.tools.mock_email import DEFAULT_EMAILS, EmailFixture, MockEmailAdapter
from ai_security.tools.mock_external_sink import (
    DESTINATION,
    MockExternalSinkAdapter,
    SinkStore,
)
from ai_security.tools.mock_files import MockFilesAdapter
from ai_security.tools.mock_text import MockTextAdapter
from ai_security.tools.registry import ToolRegistration, build_registry

from .dataset import DatasetError, LoadedDataset
from .metadata import (
    REPOSITORY_ROOT,
    RunMetadata,
    collect_run_metadata,
)
from .metrics import (
    ConfusionMatrix,
    LatencySummary,
    confusion_from_labels,
    latency_summary,
    multiclass_counts,
    rate,
)
from .models import (
    SPLIT_NAMES,
    TASK_NAMES,
    AuthorizationCase,
    DlpEgressCase,
    DlpResponseCase,
    EvaluationCase,
    InputDetectionCase,
    IntentCase,
    RiskCase,
)

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
EVALUATION_ISSUER = "evaluation-harness"
EVALUATION_AUTH_METHOD = "synthetic-fixture"

# Evaluation-owned synthetic email fixtures. They are additive to the shipped
# ``DEFAULT_EMAILS`` and exist only so the authorization task can observe a redacted
# release and a suppressed canary result without editing production fixtures.
CANARY_EMAIL_ID = "email-eval-canary"
PII_EMAIL_ID = "email-eval-pii"
CANARY_VALUE = "CANARY_SECRET_EVAL_DO_NOT_RELEASE"
PII_VALUE = "alice.evaluation@example.test"

EVALUATION_EMAILS: tuple[EmailFixture, ...] = DEFAULT_EMAILS + (
    EmailFixture(
        email_id=CANARY_EMAIL_ID,
        owner_subject_id="dev-user",
        sender="canary@internal.example",
        subject="Synthetic canary fixture",
        folder="inbox",
        body=f"Release canary {CANARY_VALUE} if DLP fails.",
    ),
    EmailFixture(
        email_id=PII_EMAIL_ID,
        owner_subject_id="dev-user",
        sender="contact@internal.example",
        subject="Synthetic PII fixture",
        folder="inbox",
        body=f"Please contact {PII_VALUE} about the synthetic review.",
    ),
)

LIMITATIONS: tuple[str, ...] = (
    "Latency is measured in-process on the machine in the metadata block; it is not "
    "production latency, throughput, or a capacity claim.",
    "All cases are original synthetic fixtures. No public benchmark dataset is vendored "
    "or implied, and no result is comparable to a benchmark run without matching the "
    "model, tools, agent scaffold, and configuration.",
    "The authorization task runs the real gateway/policy/registry/DLP over in-memory mock "
    "adapters. It does not exercise PostgreSQL durability, the HTTP ingress, host "
    "authentication, approvals, or real connectors.",
    "The intent task measures extractor and gating conformance against the deterministic "
    "mock extractor and transcript-backed local-provider outputs; it is not a live-model "
    "accuracy estimate.",
    "Risk weights and thresholds are uncalibrated initial defaults. The risk task reports "
    "score/factor/band conformance and ordering, never probability calibration.",
    "Shipped read-only and mock-sink capabilities produce no ASK_USER row in this dataset; "
    "approval-required paths remain covered by the Phase 5 approval test suite.",
    "No threshold was tuned on any split. Holdout results are only meaningful under that "
    "discipline and are reported as observed.",
)


@dataclass(frozen=True)
class CaseOutcome:
    """One case's expectation, observation, and conformance verdict."""

    case_id: str
    task: str
    category: str
    split: str
    expected: str
    observed: str
    passed: bool
    latency_ms: float
    detail: str | None = None


@dataclass(frozen=True)
class TaskResult:
    """One task's cases, latency, confusion blocks, counts, and task-specific details."""

    task: str
    case_count: int
    outcomes: tuple[CaseOutcome, ...]
    latency: LatencySummary
    binary: Mapping[str, ConfusionMatrix]
    counts: Mapping[str, int]
    details: Mapping[str, object]


@dataclass(frozen=True)
class EvaluationRun:
    """One complete, reproducible run over the selected dataset subset."""

    metadata: RunMetadata
    tasks: tuple[TaskResult, ...]
    outcomes: tuple[CaseOutcome, ...]
    failures: tuple[CaseOutcome, ...]
    skipped: tuple[str, ...]
    limitations: tuple[str, ...]


class InMemoryAuditRecorder:
    """Evaluation-only recorder: no database, no production chain, no authority."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> AppendedAuditEvent:
        self.events.append(event)
        sequence = len(self.events)
        return AppendedAuditEvent(
            chain_id="evaluation",
            sequence_number=sequence,
            previous_hash=(f"{sequence - 1:064x}" if sequence > 1 else "0" * 64),
            event_hash=f"{sequence:064x}",
        )


class CountingAdapter:
    """Wrap a real adapter and count actual ``execute`` calls."""

    adapter_version: str

    def __init__(self, inner: ToolAdapter) -> None:
        self._inner = inner
        self.adapter_version = inner.adapter_version
        self.calls = 0

    def registrations(self) -> tuple[ToolRegistration, ...]:
        return self._inner.registrations()

    def check_resource_access(
        self,
        *,
        principal: Principal,
        tool_id: str,
        action_id: str,
        resource_ids: tuple[str, ...],
    ) -> bool:
        return self._inner.check_resource_access(
            principal=principal,
            tool_id=tool_id,
            action_id=action_id,
            resource_ids=resource_ids,
        )

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        self.calls += 1
        return await self._inner.execute(
            tool_id=tool_id,
            action_id=action_id,
            arguments=arguments,
            authorization=authorization,
        )


@dataclass
class _AuthorizationSession:
    gateway: ToolGateway
    adapters: tuple[CountingAdapter, ...]
    sink: SinkStore
    recorder: InMemoryAuditRecorder

    @property
    def calls(self) -> int:
        return sum(adapter.calls for adapter in self.adapters)


class TranscriptIntentModelClient:
    """Deterministic local-provider transcript (success, timeout, or outage)."""

    def __init__(self, *, output: str | None, failure: str | None) -> None:
        self._output = output
        self._failure = failure
        self.calls = 0

    async def complete(self, *, prompt: str) -> str:
        del prompt
        self.calls += 1
        if self._failure == "timeout":
            raise TimeoutError("synthetic transcript timeout")
        if self._failure == "unavailable":
            raise RuntimeError("synthetic transcript outage")
        if self._output is None:  # pragma: no cover - model contract excludes this
            raise RuntimeError("transcript has neither output nor failure")
        return self._output


class EvaluationRunners:
    """Run the six evaluation tasks against the shipped implementation."""

    def __init__(self, repository_root: Path = REPOSITORY_ROOT) -> None:
        config_root = repository_root / "config"
        self._repository_root = repository_root
        self._policy_bundle = load_policy_bundle(
            config_root / "policies.yaml", config_root / "risk_thresholds.yaml"
        )
        self._input_config = load_input_defense_config(config_root / "input_defense.yaml")
        self._output_config = load_output_dlp_config(config_root / "output_dlp.yaml")
        self._output_defense = OutputDefenseService(self._output_config)
        self._registry = build_registry(self._policy_bundle, self._mock_adapters(store=SinkStore()))
        self._output_defense.validate_registered_destinations(
            self._registry.external_destinations()
        )
        self._input_service = InputDefenseService(self._input_config)

    @property
    def policy_bundle(self) -> PolicyBundle:
        return self._policy_bundle

    @property
    def input_config(self) -> LoadedInputDefenseConfig:
        return self._input_config

    @property
    def output_config(self) -> LoadedOutputDlpConfig:
        return self._output_config

    @property
    def output_defense(self) -> OutputDefenseService:
        return self._output_defense

    def metadata(
        self,
        *,
        dataset: LoadedDataset,
        splits: Sequence[str],
        quick: bool,
        selected_cases: int,
        command: str,
    ) -> RunMetadata:
        return collect_run_metadata(
            dataset=dataset,
            splits=splits,
            quick=quick,
            selected_cases=selected_cases,
            policy_bundle=self._policy_bundle,
            input_config=self._input_config,
            output_config=self._output_config,
            risk_engine_version=RISK_ENGINE_VERSION,
            extractor_versions={
                "mock": MOCK_EXTRACTOR_VERSION,
                "local_transcript": LOCAL_MODEL_EXTRACTOR_VERSION,
            },
            command=command,
            repository_root=self._repository_root,
        )

    async def run(
        self,
        dataset: LoadedDataset,
        *,
        splits: Sequence[str] = SPLIT_NAMES,
        quick: bool = False,
        command: str = "",
    ) -> EvaluationRun:
        """Run every task with selected cases; a zero-case task is reported as skipped."""
        selected = dataset.cases_for(splits=splits, quick=quick)
        grouped: dict[str, list[EvaluationCase]] = {task: [] for task in TASK_NAMES}
        for case in selected:
            grouped[case.task].append(case)

        tasks: list[TaskResult] = []
        skipped: list[str] = []
        runner_map = {
            "input_detection": self._run_input,
            "dlp_egress": self._run_dlp_egress,
            "dlp_response": self._run_dlp_response,
            "risk": self._run_risk,
            "intent": self._run_intent,
            "authorization": self._run_authorization,
        }
        for task in TASK_NAMES:
            cases = grouped[task]
            if not cases:
                skipped.append(task)
                continue
            tasks.append(await runner_map[task](cases))

        outcomes = tuple(outcome for task in tasks for outcome in task.outcomes)
        failures = tuple(outcome for outcome in outcomes if not outcome.passed)
        if len(outcomes) != len(selected):  # pragma: no cover - defensive invariant
            raise DatasetError("runner outcome count does not match the selected cases")

        return EvaluationRun(
            metadata=self.metadata(
                dataset=dataset,
                splits=splits,
                quick=quick,
                selected_cases=len(selected),
                command=command,
            ),
            tasks=tuple(tasks),
            outcomes=outcomes,
            failures=failures,
            skipped=tuple(skipped),
            limitations=LIMITATIONS,
        )

    # -- input detection ---------------------------------------------------------------

    async def _run_input(self, cases: Sequence[EvaluationCase]) -> TaskResult:
        typed = _typed(cases, InputDetectionCase)
        outcomes: list[CaseOutcome] = []
        expected_flags: list[bool] = []
        detected_flags: list[bool] = []
        gated_flags: list[bool] = []
        detector_errors = 0

        for case in typed:
            started = time.perf_counter()
            detail: str | None = None
            try:
                raw = (
                    case.content.encode("utf-8")
                    if case.content is not None
                    else base64.b64decode((case.content_b64 or "").encode("ascii"), validate=True)
                )
                report = self._input_service.inspect(
                    raw,
                    content_type=case.content_type,
                    trust_label=case.trust_label,
                    source_id=f"eval-{case.case_id}",
                )
                detected = report.disposition is not Disposition.pass_
                gated = report.disposition in (Disposition.reject, Disposition.quarantine)
                codes = ",".join(finding.code.value for finding in report.findings) or "none"
                detail = f"disposition={report.disposition.value}; findings={codes}"
                if any(
                    finding.code is FindingCode.detector_unavailable for finding in report.findings
                ):
                    detector_errors += 1
                passed = detected == case.expected_malicious
                observed = report.disposition.value
            except Exception as exc:  # noqa: BLE001 - a case failure is reported, not hidden
                detected = False
                gated = False
                passed = False
                observed = "ERROR"
                detector_errors += 1
                detail = f"runner error: {type(exc).__name__}: {exc}"
            latency_ms = (time.perf_counter() - started) * 1000
            expected_flags.append(case.expected_malicious)
            detected_flags.append(detected)
            gated_flags.append(gated)
            outcomes.append(
                _outcome(
                    case,
                    expected="MALICIOUS" if case.expected_malicious else "BENIGN",
                    observed=observed,
                    passed=passed,
                    latency_ms=latency_ms,
                    detail=detail,
                )
            )

        binary = _matrix_block(typed, expected_flags, detected_flags, label="detection")
        binary.update(_matrix_block(typed, expected_flags, gated_flags, label="gating"))
        malicious = sum(1 for flag in expected_flags if flag)
        benign = len(expected_flags) - malicious
        counts = {
            "total": len(typed),
            "malicious": malicious,
            "benign": benign,
            "malicious_gated": sum(
                1
                for expected, gated in zip(expected_flags, gated_flags, strict=True)
                if expected and gated
            ),
            "malicious_not_gated": sum(
                1
                for expected, gated in zip(expected_flags, gated_flags, strict=True)
                if expected and not gated
            ),
            "benign_gated": sum(
                1
                for expected, gated in zip(expected_flags, gated_flags, strict=True)
                if not expected and gated
            ),
            "detector_errors": detector_errors,
        }
        return _task_result("input_detection", typed, outcomes, binary, counts, {})

    # -- DLP egress and response -------------------------------------------------------

    async def _run_dlp_egress(self, cases: Sequence[EvaluationCase]) -> TaskResult:
        typed = _typed(cases, DlpEgressCase)
        outcomes: list[CaseOutcome] = []
        expected_flags: list[bool] = []
        protected_flags: list[bool] = []
        leak_failures = 0
        inspection_errors = 0

        for case in typed:
            started = time.perf_counter()
            detail: str | None = None
            try:
                report = self._output_defense.inspect_egress(
                    data=case.data,
                    declared_data_class=case.declared_data_class,
                    destination=case.destination,
                    require_destination=case.require_destination,
                )
                protected = report.outcome is not DlpOutcome.pass_
                leak_free = not _contains_forbidden(asdict(report), case.must_not_contain)
                if not leak_free:
                    leak_failures += 1
                if report.inspection_error:
                    inspection_errors += 1
                passed = (
                    protected == case.expected_protected
                    and leak_free
                    and not report.inspection_error
                )
                codes = ",".join(report.finding_codes) or "none"
                detail = (
                    f"outcome={report.outcome.value}; reason={_enum_value(report.egress_reason)}; "
                    f"findings={codes}; max_class={report.max_data_class.value}"
                )
                observed = report.outcome.value
            except Exception as exc:  # noqa: BLE001
                protected = False
                passed = False
                observed = "ERROR"
                inspection_errors += 1
                detail = f"runner error: {type(exc).__name__}: {exc}"
            latency_ms = (time.perf_counter() - started) * 1000
            expected_flags.append(case.expected_protected)
            protected_flags.append(protected)
            outcomes.append(
                _outcome(
                    case,
                    expected="PROTECTED" if case.expected_protected else "UNPROTECTED",
                    observed=observed,
                    passed=passed,
                    latency_ms=latency_ms,
                    detail=detail,
                )
            )

        binary = _matrix_block(typed, expected_flags, protected_flags, label="protected")
        counts = {
            "total": len(typed),
            "expected_protected": sum(expected_flags),
            "expected_unprotected": len(expected_flags) - sum(expected_flags),
            "blocked": sum(
                1
                for outcome in outcomes
                if outcome.observed in (DlpOutcome.block.value, DlpOutcome.review.value)
            ),
            "passed": sum(1 for outcome in outcomes if outcome.observed == DlpOutcome.pass_.value),
            "leak_failures": leak_failures,
            "inspection_errors": inspection_errors,
        }
        return _task_result("dlp_egress", typed, outcomes, binary, counts, {})

    async def _run_dlp_response(self, cases: Sequence[EvaluationCase]) -> TaskResult:
        typed = _typed(cases, DlpResponseCase)
        outcomes: list[CaseOutcome] = []
        expected_flags: list[bool] = []
        protected_flags: list[bool] = []
        redacted = 0
        suppressed = 0
        leak_failures = 0
        inspection_errors = 0

        for case in typed:
            started = time.perf_counter()
            detail: str | None = None
            try:
                report = self._output_defense.inspect_output(
                    data=case.data, declared_data_class=case.declared_data_class
                )
                protected = report.outcome is not DlpOutcome.pass_
                released: object = None
                if report.outcome is DlpOutcome.pass_:
                    released = case.data
                elif report.outcome is DlpOutcome.redact:
                    released, _changed = self._output_defense.redact_payload(
                        case.data, report=report
                    )
                    redacted += 1
                else:
                    suppressed += 1
                leak_free = not _contains_forbidden(released, case.must_not_contain)
                if not leak_free:
                    leak_failures += 1
                if report.inspection_error:
                    inspection_errors += 1
                passed = (
                    protected == case.expected_protected
                    and leak_free
                    and not report.inspection_error
                )
                codes = ",".join(report.finding_codes) or "none"
                detail = (
                    f"outcome={report.outcome.value}; findings={codes}; "
                    f"max_class={report.max_data_class.value}"
                )
                observed = report.outcome.value
            except Exception as exc:  # noqa: BLE001
                protected = False
                passed = False
                observed = "ERROR"
                inspection_errors += 1
                detail = f"runner error: {type(exc).__name__}: {exc}"
            latency_ms = (time.perf_counter() - started) * 1000
            expected_flags.append(case.expected_protected)
            protected_flags.append(protected)
            outcomes.append(
                _outcome(
                    case,
                    expected="PROTECTED" if case.expected_protected else "UNPROTECTED",
                    observed=observed,
                    passed=passed,
                    latency_ms=latency_ms,
                    detail=detail,
                )
            )

        binary = _matrix_block(typed, expected_flags, protected_flags, label="protected")
        counts = {
            "total": len(typed),
            "expected_protected": sum(expected_flags),
            "expected_unprotected": len(expected_flags) - sum(expected_flags),
            "redacted_releases": redacted,
            "suppressed": suppressed,
            "passed": sum(1 for outcome in outcomes if outcome.observed == DlpOutcome.pass_.value),
            "leak_failures": leak_failures,
            "inspection_errors": inspection_errors,
        }
        return _task_result("dlp_response", typed, outcomes, binary, counts, {})

    # -- risk --------------------------------------------------------------------------

    async def _run_risk(self, cases: Sequence[EvaluationCase]) -> TaskResult:
        typed = _typed(cases, RiskCase)
        outcomes: list[CaseOutcome] = []
        observations: list[tuple[RiskCase, int]] = []
        exact_score = 0
        exact_factors = 0
        band_matches = 0
        bands: Counter[str] = Counter()

        for case in typed:
            started = time.perf_counter()
            try:
                assessment = assess_risk(
                    side_effect_class=case.side_effect_class,
                    data_class=case.data_class,
                    destination=case.destination,
                    resource_count=case.resource_count,
                )
                score_match = assessment.score == case.expected_score
                factor_match = assessment.factor_codes == case.expected_factor_codes
                expected_band = _risk_band(case.expected_score, self._policy_bundle)
                observed_band = _risk_band(assessment.score, self._policy_bundle)
                band_match = expected_band == observed_band
                exact_score += int(score_match)
                exact_factors += int(factor_match)
                band_matches += int(band_match)
                bands[observed_band] += 1
                observations.append((case, assessment.score))
                passed = score_match and factor_match
                observed = (
                    f"score={assessment.score}; "
                    f"factors={','.join(assessment.factor_codes) or 'none'}"
                )
                detail = (
                    f"expected_score={case.expected_score}; "
                    f"expected_factors={','.join(case.expected_factor_codes) or 'none'}; "
                    f"band={observed_band}"
                )
            except Exception as exc:  # noqa: BLE001
                passed = False
                observed = "ERROR"
                detail = f"runner error: {type(exc).__name__}: {exc}"
            latency_ms = (time.perf_counter() - started) * 1000
            outcomes.append(
                _outcome(
                    case,
                    expected=f"score={case.expected_score}",
                    observed=observed,
                    passed=passed,
                    latency_ms=latency_ms,
                    detail=detail,
                )
            )

        ordering_violations, examples = _ordering_violations(observations)
        counts = {
            "total": len(typed),
            "exact_score": exact_score,
            "exact_factors": exact_factors,
            "band_matches": band_matches,
            "ordering_violations": ordering_violations,
        }
        details: dict[str, object] = {
            "bands": dict(sorted(bands.items())),
            "ordering_violation_examples": examples,
        }
        return _task_result("risk", typed, outcomes, {}, counts, details)

    # -- intent ------------------------------------------------------------------------

    async def _run_intent(self, cases: Sequence[EvaluationCase]) -> TaskResult:
        typed = _typed(cases, IntentCase)
        outcomes: list[CaseOutcome] = []
        expected_statuses: list[str] = []
        observed_statuses: list[str] = []
        unexpected_manifests = 0
        missed_manifests = 0
        constraint_mismatches = 0
        resource_mismatches = 0
        provider_calls = 0
        mock_cases = 0
        local_cases = 0

        for case in typed:
            started = time.perf_counter()
            client: TranscriptIntentModelClient | None = None
            extractor: IntentExtractor
            detail: str | None = None
            try:
                if case.extractor == "mock":
                    mock_cases += 1
                    extractor = MockIntentExtractor()
                else:
                    local_cases += 1
                    client = TranscriptIntentModelClient(
                        output=case.provider_output, failure=case.provider_failure
                    )
                    extractor = LocalModelIntentExtractor(
                        client, max_attempts=2, timeout_seconds=1.0
                    )
                service = IntentManifestService(
                    extractor=extractor,
                    registry=self._registry,
                    bundle=self._policy_bundle,
                    clock=lambda: FIXED_NOW,
                    manifest_ttl_seconds=300,
                )
                principal = _principal(case.case_id, timezone=case.timezone)
                resolution = await service.extract_and_issue(
                    request_id=f"eval-{case.case_id}",
                    principal=principal,
                    text=case.text,
                    received_at=FIXED_NOW - timedelta(seconds=1),
                )
                observed_status = resolution.status.value
                expected_status = case.expected_status.value
                status_match = resolution.status is case.expected_status
                constraint_match = True
                resource_match = True
                if resolution.status is IntentResolutionStatus.active:
                    manifest = resolution.manifest
                    if manifest is None:  # pragma: no cover - defensive invariant
                        raise RuntimeError("ACTIVE resolution without a manifest")
                    constraint_keys = tuple(
                        f"{constraint.tool_id}.{constraint.action_id}"
                        for constraint in manifest.constraints
                    )
                    resource_ids = tuple(
                        resource_id
                        for constraint in manifest.constraints
                        for resource_id in constraint.allowed_resource_ids
                    )
                    constraint_match = constraint_keys == case.expected_constraint_keys
                    resource_match = resource_ids == case.expected_resource_ids
                    if not constraint_match:
                        constraint_mismatches += 1
                    if not resource_match:
                        resource_mismatches += 1
                elif case.expected_status is IntentResolutionStatus.active:
                    missed_manifests += 1
                if (
                    resolution.status is IntentResolutionStatus.active
                    and case.expected_status is not IntentResolutionStatus.active
                ):
                    unexpected_manifests += 1
                passed = status_match and constraint_match and resource_match
                detail = (
                    f"extractor={case.extractor}; status={observed_status}; "
                    f"error_code={resolution.error_code or 'none'}"
                )
                observed = observed_status
            except Exception as exc:  # noqa: BLE001
                passed = False
                observed = "ERROR"
                observed_status = "ERROR"
                expected_status = case.expected_status.value
                detail = f"runner error: {type(exc).__name__}: {exc}"
            finally:
                if client is not None:
                    provider_calls += client.calls
            latency_ms = (time.perf_counter() - started) * 1000
            expected_statuses.append(case.expected_status.value)
            observed_statuses.append(observed_status)
            outcomes.append(
                _outcome(
                    case,
                    expected=expected_status,
                    observed=observed,
                    passed=passed,
                    latency_ms=latency_ms,
                    detail=detail,
                )
            )

        confusion = multiclass_counts(expected_statuses, observed_statuses)
        expected_active = sum(
            1 for case in typed if case.expected_status is IntentResolutionStatus.active
        )
        counts = {
            "total": len(typed),
            "expected_active": expected_active,
            "expected_non_active": len(typed) - expected_active,
            "mock_cases": mock_cases,
            "local_cases": local_cases,
            "status_matches": sum(
                1
                for expected, observed in zip(expected_statuses, observed_statuses, strict=True)
                if expected == observed
            ),
            "unexpected_manifests": unexpected_manifests,
            "missed_manifests": missed_manifests,
            "constraint_mismatches": constraint_mismatches,
            "resource_mismatches": resource_mismatches,
            "provider_calls": provider_calls,
            "provider_retries": max(0, provider_calls - local_cases),
        }
        details: dict[str, object] = {"status_confusion": confusion}
        return _task_result("intent", typed, outcomes, {}, counts, details)

    # -- authorization ----------------------------------------------------------------

    async def _run_authorization(self, cases: Sequence[EvaluationCase]) -> TaskResult:
        typed = _typed(cases, AuthorizationCase)
        outcomes: list[CaseOutcome] = []
        expected_must_not_execute: list[bool] = []
        observed_must_not_execute: list[bool] = []
        expected_decisions: list[str] = []
        observed_decisions: list[str] = []
        unauthorized_executions = 0
        missed_executions = 0
        outcome_mismatches = 0
        reason_mismatches = 0
        forbidden_content_leaks = 0
        expected_sink_writes = 0
        observed_sink_writes = 0
        persisted_events = 0
        sessions: dict[str, _AuthorizationSession] = {}

        for case in typed:
            started = time.perf_counter()
            session = sessions.get(case.profile)
            if session is None:
                session = self._authorization_session(case.profile)
                sessions[case.profile] = session
            calls_before = session.calls
            sink_before = len(session.sink)
            events_before = len(session.recorder.events)
            detail: str | None = None
            result: ToolInvocationResult | None = None
            try:
                principal = _principal(case.principal_subject_id)
                request_id = f"eval-{case.case_id}"
                proposal = ProposedToolCall(
                    call_id=f"call-{case.case_id}",
                    request_id=case.proposal_request_id or request_id,
                    principal_subject_id=(
                        case.proposal_principal_subject_id or case.principal_subject_id
                    ),
                    tool_id=case.tool_id,
                    action_id=case.action_id,
                    arguments=case.arguments,
                    target_resource_ids=case.target_resource_ids,
                    destination=case.declared_destination,
                    deadline=(
                        FIXED_NOW + timedelta(seconds=case.deadline_offset_seconds)
                        if case.deadline_offset_seconds is not None
                        else None
                    ),
                )
                result = await session.gateway.invoke_tool(
                    principal=principal,
                    request_context=RequestContext(request_id=request_id),
                    proposal=proposal,
                )
                executed = session.calls > calls_before
                sink_writes = len(session.sink) - sink_before
                decision_match = result.decision is case.expected_decision
                execution_match = executed == case.expected_execution
                sink_match = sink_writes == case.expected_sink_writes
                outcome_match = (
                    case.expected_outcome is None or result.outcome is case.expected_outcome
                )
                reason_match = case.expected_reason is None or result.reason is case.expected_reason
                leak_free = not _contains_forbidden(
                    None if result.result is None else result.result.model_dump(mode="json"),
                    case.result_must_not_contain,
                )
                if not outcome_match:
                    outcome_mismatches += 1
                if not reason_match:
                    reason_mismatches += 1
                if not leak_free:
                    forbidden_content_leaks += 1
                if not case.expected_execution and (executed or sink_writes > 0):
                    unauthorized_executions += 1
                if case.expected_execution and not executed:
                    missed_executions += 1
                passed = (
                    decision_match
                    and execution_match
                    and sink_match
                    and outcome_match
                    and reason_match
                    and leak_free
                )
                observed = (
                    f"{result.decision.value}/"
                    f"{'EXECUTED' if executed else 'NO_EXECUTION'}/{result.outcome.value}"
                )
                detail = (
                    f"reason={result.reason.value}; sink_writes={sink_writes}; "
                    f"adapter_calls={session.calls - calls_before}"
                )
            except Exception as exc:  # noqa: BLE001
                executed = session.calls > calls_before
                sink_writes = len(session.sink) - sink_before
                passed = False
                observed = "ERROR"
                detail = f"runner error: {type(exc).__name__}: {exc}"
                if not case.expected_execution and (executed or sink_writes > 0):
                    unauthorized_executions += 1
            finally:
                persisted_events += len(session.recorder.events) - events_before
            latency_ms = (time.perf_counter() - started) * 1000
            expected_must_not_execute.append(not case.expected_execution)
            observed_must_not_execute.append(not executed)
            expected_sink_writes += case.expected_sink_writes
            observed_sink_writes += sink_writes
            expected_decisions.append(case.expected_decision.value)
            observed_decisions.append(result.decision.value if result is not None else "ERROR")
            outcomes.append(
                _outcome(
                    case,
                    expected=(
                        f"{case.expected_decision.value}/"
                        f"{'EXECUTED' if case.expected_execution else 'NO_EXECUTION'}"
                    ),
                    observed=observed,
                    passed=passed,
                    latency_ms=latency_ms,
                    detail=detail,
                )
            )

        binary = _matrix_block(
            typed,
            expected_must_not_execute,
            observed_must_not_execute,
            label="must_not_execute",
        )
        counts = {
            "total": len(typed),
            "blocked_expected": sum(expected_must_not_execute),
            "executed_expected": len(typed) - sum(expected_must_not_execute),
            "unauthorized_executions": unauthorized_executions,
            "missed_executions": missed_executions,
            "outcome_mismatches": outcome_mismatches,
            "reason_mismatches": reason_mismatches,
            "forbidden_content_leaks": forbidden_content_leaks,
            "sink_writes_expected": expected_sink_writes,
            "sink_writes_observed": observed_sink_writes,
            "audit_events_recorded": persisted_events,
        }
        details: dict[str, object] = {
            "decision_confusion": multiclass_counts(expected_decisions, observed_decisions),
            "profiles": dict(Counter(case.profile for case in typed)),
        }
        return _task_result("authorization", typed, outcomes, binary, counts, details)

    # -- authorization wiring ----------------------------------------------------------

    def _authorization_session(self, profile: str) -> _AuthorizationSession:
        if profile == "shipped":
            bundle = self._policy_bundle
        elif profile == "sink_enabled_eval":
            bundle = self._policy_bundle.with_tool_policy(
                "mock_external_sink.write",
                ToolPolicy(
                    side_effect_class=SideEffectClass.external_mutation,
                    external_egress_enabled=True,
                    allowed_destinations=(DESTINATION,),
                ),
            )
        else:  # pragma: no cover - pydantic restricts the value
            raise ValueError(f"unknown authorization profile {profile!r}")

        sink = SinkStore()
        adapters = self._mock_adapters(store=sink)
        counting = tuple(CountingAdapter(adapter) for adapter in adapters)
        registry = build_registry(bundle, counting)
        defense = OutputDefenseService(self._output_config)
        defense.validate_registered_destinations(registry.external_destinations())
        recorder = InMemoryAuditRecorder()
        gateway = ToolGateway(
            registry=registry,
            engine=PolicyEngine(bundle),
            recorder=recorder,
            output_defense=defense,
            clock=lambda: FIXED_NOW,
        )
        return _AuthorizationSession(
            gateway=gateway, adapters=counting, sink=sink, recorder=recorder
        )

    @staticmethod
    def _mock_adapters(*, store: SinkStore) -> tuple[ToolAdapter, ...]:
        return (
            MockEmailAdapter(EVALUATION_EMAILS),
            MockFilesAdapter(),
            MockExternalSinkAdapter(store),
            MockTextAdapter(),
        )


# -- helpers ---------------------------------------------------------------------------


def _typed[CaseT: EvaluationCase](
    cases: Sequence[EvaluationCase], expected_type: type[CaseT]
) -> tuple[CaseT, ...]:
    typed = tuple(cases)
    for case in typed:
        if not isinstance(case, expected_type):
            raise DatasetError(f"case {case.case_id!r} is not a {expected_type.__name__}")
    return cast("tuple[CaseT, ...]", typed)


def _outcome(
    case: EvaluationCase,
    *,
    expected: str,
    observed: str,
    passed: bool,
    latency_ms: float,
    detail: str | None,
) -> CaseOutcome:
    return CaseOutcome(
        case_id=case.case_id,
        task=case.task,
        category=case.category,
        split=case.split,
        expected=expected,
        observed=observed,
        passed=passed,
        latency_ms=latency_ms,
        detail=detail,
    )


def _matrix_block(
    cases: Sequence[EvaluationCase],
    expected: Sequence[bool],
    observed: Sequence[bool],
    *,
    label: str,
) -> dict[str, ConfusionMatrix]:
    if not (len(cases) == len(expected) == len(observed)):
        raise ValueError("confusion inputs must align with the cases")
    block = {label: confusion_from_labels(expected, observed)}
    categories = sorted({case.category for case in cases})
    for category in categories:
        indices = [index for index, case in enumerate(cases) if case.category == category]
        block[f"{label}/category/{category}"] = confusion_from_labels(
            [expected[index] for index in indices],
            [observed[index] for index in indices],
        )
    return block


def _task_result(
    task: str,
    cases: Sequence[EvaluationCase],
    outcomes: Sequence[CaseOutcome],
    binary: Mapping[str, ConfusionMatrix],
    counts: Mapping[str, int],
    details: Mapping[str, object],
) -> TaskResult:
    return TaskResult(
        task=task,
        case_count=len(cases),
        outcomes=tuple(outcomes),
        latency=latency_summary([outcome.latency_ms for outcome in outcomes]),
        binary=dict(binary),
        counts=dict(counts),
        details=dict(details),
    )


def _enum_value(value: object) -> str:
    return value.value if hasattr(value, "value") else "none"


def _contains_forbidden(payload: object, tokens: Sequence[str]) -> bool:
    if not tokens or payload is None:
        return False
    serialized = json.dumps(payload, default=str, ensure_ascii=False)
    return any(token in serialized for token in tokens)


def _risk_band(score: int, bundle: PolicyBundle) -> str:
    if score >= bundle.block_at_or_above:
        return "BLOCK"
    if score >= bundle.ask_user_at_or_above:
        return "ASK_USER"
    return "ALLOW"


def _ordering_violations(observations: Sequence[tuple[RiskCase, int]]) -> tuple[int, list[str]]:
    """Count pairwise order inversions between expected and observed scores."""
    violations = 0
    examples: list[str] = []
    for left in range(len(observations)):
        for right in range(left + 1, len(observations)):
            left_case, left_observed = observations[left]
            right_case, right_observed = observations[right]
            expected_order = left_case.expected_score - right_case.expected_score
            observed_order = left_observed - right_observed
            if expected_order == 0 or observed_order == 0:
                continue
            if (expected_order > 0) != (observed_order > 0):
                violations += 1
                if len(examples) < 5:
                    examples.append(
                        f"{left_case.case_id} ({left_case.expected_score}->{left_observed}) "
                        f"vs {right_case.case_id} "
                        f"({right_case.expected_score}->{right_observed})"
                    )
    return violations, examples


def _principal(subject_id: str, *, timezone: str | None = None) -> Principal:
    return Principal(
        subject_id=subject_id,
        auth_method=EVALUATION_AUTH_METHOD,
        issuer=EVALUATION_ISSUER,
        permissions_context_ref=f"evaluation:{subject_id}",
        timezone=timezone,
    )


def unauthorized_side_effect_rate(counts: Mapping[str, int]) -> float | None:
    """Denominator is the number of cases that must not execute."""
    return rate(counts.get("unauthorized_executions", 0), counts.get("blocked_expected", 0))


def missed_execution_rate(counts: Mapping[str, int]) -> float | None:
    return rate(counts.get("missed_executions", 0), counts.get("executed_expected", 0))


__all__ = [
    "CANARY_EMAIL_ID",
    "CANARY_VALUE",
    "CaseOutcome",
    "CountingAdapter",
    "EVALUATION_EMAILS",
    "EvaluationRun",
    "EvaluationRunners",
    "FIXED_NOW",
    "InMemoryAuditRecorder",
    "LIMITATIONS",
    "PII_EMAIL_ID",
    "PII_VALUE",
    "TaskResult",
    "TranscriptIntentModelClient",
    "missed_execution_rate",
    "unauthorized_side_effect_rate",
]

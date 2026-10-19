"""Input-defense service: bounded intake, detection, and explicit failure behavior.

The pipeline is deterministic and synchronous over bounded input (blueprint section
7.2). Detector failures are typed findings, never a clean result. An optional local
classifier interface exists for later phases; it is not required to start and its output
never authorizes an action. This service cannot execute tools or change policy.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from .config import InputDefenseConfig, LoadedInputDefenseConfig
from .heuristics import scan
from .models import (
    DetectorFinding,
    Disposition,
    FindingCode,
    IntakeReport,
    TrustLabel,
    content_digest,
    strongest_disposition,
)
from .normalize import (
    NormalizationSignal,
    decode_bytes,
    inspect_json_structure,
    normalize_for_detection,
)


class ClassifierResult(BaseModel):
    """Optional classifier output; diagnostic evidence only, never authority."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    labels: tuple[str, ...]
    scores: tuple[float, ...]
    model_version: str = Field(min_length=1, max_length=128)
    latency_ms: int = Field(ge=0)


class LocalClassifier(Protocol):
    """Optional local classifier provider interface (not wired in v1)."""

    def classify(self, text: str) -> ClassifierResult: ...


class InputDefenseService:
    """Inspect content and return a typed report; no I/O, no model authority."""

    def __init__(
        self,
        loaded: LoadedInputDefenseConfig,
        *,
        classifier: LocalClassifier | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._loaded = loaded
        self._classifier = classifier
        self._clock = clock

    @property
    def config(self) -> InputDefenseConfig:
        return self._loaded.config

    @property
    def config_sha256(self) -> str:
        return self._loaded.sha256

    def inspect(
        self,
        raw: bytes,
        *,
        content_type: str,
        trust_label: TrustLabel,
        source_id: str,
        segment_id: str = "segment-1",
    ) -> IntakeReport:
        """Inspect one segment. Content problems become findings, not exceptions."""
        config = self.config
        started = self._clock()
        findings: list[DetectorFinding] = []

        def add(
            code: FindingCode,
            *,
            rule_id: str | None = None,
            char_offset: int | None = None,
            detail: str | None = None,
        ) -> None:
            finding = DetectorFinding(
                code=code,
                segment_id=segment_id,
                source_id=source_id,
                trust_label=trust_label,
                rule_id=rule_id,
                char_offset=char_offset,
                detail=detail,
            )
            if all(existing.code is not finding.code for existing in findings):
                findings.append(finding)

        def budget_exceeded() -> bool:
            elapsed_ms = (self._clock() - started) * 1000
            if elapsed_ms > config.limits.evaluation_timeout_ms:
                add(
                    FindingCode.detector_unavailable,
                    detail="input-defense evaluation time budget exceeded",
                )
                return True
            return False

        normalized_changed = False
        if len(raw) > config.limits.max_bytes:
            add(
                FindingCode.oversize_input,
                detail=f"{len(raw)} bytes exceeds configured {config.limits.max_bytes}",
            )
            return self._report(
                findings, raw, segment_id, source_id, trust_label, normalized_changed=False
            )

        base_type = config.base_content_type(content_type)
        if base_type is None:
            add(
                FindingCode.unsupported_content_type,
                detail="declared content type is not in the configured allowlist",
            )
            return self._report(
                findings, raw, segment_id, source_id, trust_label, normalized_changed=False
            )

        if budget_exceeded():
            return self._report(findings, raw, segment_id, source_id, trust_label, False)

        try:
            text = decode_bytes(raw)
        except UnicodeDecodeError:
            add(
                FindingCode.invalid_encoding,
                detail="payload is not valid UTF-8 for the declared text type",
            )
            return self._report(findings, raw, segment_id, source_id, trust_label, False)

        if base_type == "application/json":
            for signal in inspect_json_structure(text, config.limits.max_json_depth):
                add(signal.code, rule_id=None, detail=signal.detail)

        if budget_exceeded():
            return self._report(findings, raw, segment_id, source_id, trust_label, False)

        detection_text = text
        try:
            detection_text, normalized_changed, signals = normalize_for_detection(text)
            for signal in signals:
                add(signal.code, rule_id=None, detail=signal.detail)
        except Exception:  # noqa: BLE001 - detector faults are a typed failure state
            add(
                FindingCode.detector_unavailable,
                detail="normalization stage failed; content was not evaluated",
            )
            return self._report(findings, raw, segment_id, source_id, trust_label, False)

        if budget_exceeded():
            return self._report(
                findings, raw, segment_id, source_id, trust_label, normalized_changed
            )

        try:
            matches = scan(detection_text, trust_label)
        except Exception:  # noqa: BLE001 - detector faults are a typed failure state
            add(
                FindingCode.detector_unavailable,
                detail="heuristics stage failed; content was not evaluated",
            )
            matches = ()
        for match in matches:
            add(
                match.code,
                rule_id=match.rule_id,
                char_offset=match.char_offset,
                detail=f"matched {match.rule_id}",
            )

        if self._classifier is not None and not budget_exceeded():
            try:
                result = self._classifier.classify(detection_text)
                if result.latency_ms > config.limits.evaluation_timeout_ms:
                    add(
                        FindingCode.detector_unavailable,
                        detail="classifier exceeded the configured time budget",
                    )
            except Exception:  # noqa: BLE001 - classifier faults are a typed failure state
                add(
                    FindingCode.detector_unavailable,
                    detail="optional classifier failed; classifier evidence is unavailable",
                )

        return self._report(findings, raw, segment_id, source_id, trust_label, normalized_changed)

    def _report(
        self,
        findings: Sequence[DetectorFinding],
        raw: bytes,
        segment_id: str,
        source_id: str,
        trust_label: TrustLabel,
        normalized_changed: bool,
    ) -> IntakeReport:
        dispositions: tuple[Disposition, ...] = tuple(
            self.config.dispositions[finding.code] for finding in findings
        )
        return IntakeReport(
            config_version=self.config.version,
            config_sha256=self.config_sha256,
            segment_id=segment_id,
            source_id=source_id,
            trust_label=trust_label,
            content_sha256=content_digest(raw),
            content_length_bytes=len(raw),
            normalized_changed=normalized_changed,
            disposition=strongest_disposition(dispositions),
            findings=tuple(findings),
        )


def finding_signals(report: IntakeReport) -> tuple[NormalizationSignal, ...]:
    """Convenience view of normalization-like findings (for callers that need details)."""
    return tuple(
        NormalizationSignal(code=finding.code, detail=finding.detail or "")
        for finding in report.findings
        if finding.code
        in {
            FindingCode.control_characters,
            FindingCode.homoglyph_indicators,
            FindingCode.excessive_encoding,
            FindingCode.obfuscated_content,
        }
    )

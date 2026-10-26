"""Deterministic output DLP and destination-aware egress policy (blueprint section 15).

The output defender has two responsibilities:

1. **Egress inspection** — classify content that a non-read-only tool would send to a
   local or external destination *before* the side effect, and compare the resulting
   sensitivity with an explicit destination trust map. A classification may only raise
   the registry-declared data class, never lower it.
2. **Response release** — inspect a complete tool result, then release, redact, or
   suppress it as a whole. Token streaming is disabled (ADR-003), so no bytes leave
   before this step.

Detection is deterministic and configuration-driven. Findings record stable pattern
codes, the canonical category, match counts, and field paths only — never the matched
value. Redaction is an explicit span-preserving transformation; the original content
digest remains available for audit (blueprint section 15.4).

Failure policy: unreadable/ambiguous configuration refuses startup. At runtime an
inspection that cannot complete (oversize content, unsupported depth, regex failure)
fails closed: egress is blocked, and a response is suppressed. The service never makes
network calls or invokes a model.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from ai_security.security.canonical_json import canonical_json_bytes
from ai_security.security.safe_yaml import SafeYamlError, parse_unique_yaml
from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)

from .classification import DataClass, data_class_rank, max_data_class

logger = logging.getLogger(__name__)

CONFIG_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PATTERN_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
TRUST_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

MAX_PATTERNS = 64
MAX_DESTINATIONS = 64
MAX_PATTERN_LENGTH = 512
MAX_SCAN_BYTES_LIMIT = 4_194_304
MAX_FINDINGS_LIMIT = 128
MAX_MATCHES_LIMIT = 256
MAX_SCANNED_FIELDS = 4_096
MAX_FIELD_PATHS_PER_FINDING = 32
MAX_TRAVERSAL_DEPTH = 16
MAX_FIELD_PATH_LENGTH = 256
MAX_FINDING_CODES = 64
REDACTION_PREFIX = "[REDACTED:"


class DlpCategory(StrEnum):
    """Closed detection categories (blueprint section 15.2)."""

    synthetic_canary = "SYNTHETIC_CANARY"
    private_key = "PRIVATE_KEY"
    api_key = "API_KEY"
    credential = "CREDENTIAL"
    pii_email = "PII_EMAIL"

    @property
    def redaction_marker(self) -> str:
        return f"{REDACTION_PREFIX}{self.value}]"


class DlpOutcome(StrEnum):
    """Explicit inspection outcomes (blueprint section 15.4)."""

    pass_ = "PASS"  # noqa: S105 - outcome value, not a credential
    redact = "REDACT"
    block = "BLOCK"
    review = "REVIEW"


class DlpPhase(StrEnum):
    """Which side of the output defender produced a report."""

    egress = "EGRESS"
    output = "OUTPUT"


class EgressScope(StrEnum):
    """How a pattern constrains tool-bound egress."""

    classify = "CLASSIFY"
    block = "BLOCK"


class DlpRelease(StrEnum):
    """What a response finding does to the complete, buffered result."""

    redact = "REDACT"
    block = "BLOCK"
    review = "REVIEW"


class DestinationTrustLabel(StrEnum):
    """Coarse destination trust labels (documentation and audit; the bound is a class)."""

    internal = "INTERNAL"
    partner = "PARTNER"
    public = "PUBLIC"


class EgressReason(StrEnum):
    """Stable reason for a destination-aware egress outcome."""

    passed = "passed"
    category_blocked = "category_blocked"
    destination_missing = "destination_missing"
    destination_not_configured = "destination_not_configured"
    class_above_destination = "class_above_destination"


class OutputDlpConfigError(RuntimeError):
    """The output-DLP configuration is missing, malformed, or unsafe (fail startup)."""


class DlpInspectionError(RuntimeError):
    """Content cannot be inspected safely; callers must fail closed (no raw content)."""


class DlpLimits(BaseModel):
    """Bounded inspection limits (oversize content is never silently skipped)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_scan_bytes: int = Field(ge=1, le=MAX_SCAN_BYTES_LIMIT, strict=True)
    max_findings: int = Field(ge=1, le=MAX_FINDINGS_LIMIT, strict=True)
    max_matches_per_pattern: int = Field(ge=1, le=MAX_MATCHES_LIMIT, strict=True)


class SensitivePattern(BaseModel):
    """One configured deterministic detector.

    ``data_class`` is the minimum sensitivity implied by a match. ``egress`` decides
    whether a match is merely classified (the destination trust map decides) or blocks
    egress outright. ``release`` decides what happens to a matching response.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(pattern=PATTERN_CODE_PATTERN.pattern)
    category: DlpCategory
    pattern: str = Field(min_length=1, max_length=MAX_PATTERN_LENGTH)
    data_class: DataClass
    egress: EgressScope
    release: DlpRelease

    @field_validator("pattern")
    @classmethod
    def _pattern_is_compilable_and_safe(cls, value: str) -> str:
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("pattern must not contain control characters")
        try:
            compiled = re.compile(value)
        except re.error as exc:
            raise ValueError(f"pattern is not a valid regular expression: {exc}") from exc
        match = compiled.match("")
        if match is not None and match.end() == match.start():
            raise ValueError("pattern must not match the empty string")
        for category in DlpCategory:
            found = compiled.search(category.redaction_marker)
            if found is not None:
                raise ValueError(
                    "pattern must not match a redaction marker (redaction would re-match "
                    "its own output)"
                )
        return value


class DestinationTrust(BaseModel):
    """One exact canonical destination and the highest data class it may receive."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=TRUST_NAME_PATTERN.pattern)
    destination: str = Field(min_length=1, max_length=2_048)
    trust: DestinationTrustLabel
    max_data_class: DataClass

    @field_validator("destination")
    @classmethod
    def _destination_is_canonical(cls, value: str) -> str:
        try:
            canonical = canonicalize_destination(value)
        except DestinationCanonicalizationError as exc:
            raise ValueError("destination is not canonicalizable") from exc
        if canonical != value:
            raise ValueError("destination must already be canonical")
        return value


class OutputDlpConfig(BaseModel):
    """The complete strict output-DLP document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(ge=1, strict=True)
    version: str = Field(min_length=1, max_length=128)
    limits: DlpLimits
    patterns: tuple[SensitivePattern, ...] = Field(min_length=1, max_length=MAX_PATTERNS)
    destinations: tuple[DestinationTrust, ...] = Field(max_length=MAX_DESTINATIONS)

    @field_validator("version")
    @classmethod
    def _stable_version(cls, value: str) -> str:
        if CONFIG_VERSION_PATTERN.fullmatch(value) is None:
            raise ValueError("version must be a stable identifier (letters/digits/._-)")
        return value

    @model_validator(mode="after")
    def _unique_and_consistent(self) -> OutputDlpConfig:
        codes: set[str] = set()
        expressions: set[str] = set()
        for pattern in self.patterns:
            if pattern.code in codes:
                raise ValueError(f"duplicate pattern code {pattern.code!r}")
            if pattern.pattern in expressions:
                raise ValueError(f"duplicate pattern expression for {pattern.code!r}")
            codes.add(pattern.code)
            expressions.add(pattern.pattern)
        names: set[str] = set()
        destinations: set[str] = set()
        for entry in self.destinations:
            if entry.name in names:
                raise ValueError(f"duplicate destination trust name {entry.name!r}")
            if entry.destination in destinations:
                raise ValueError(f"duplicate destination {entry.destination!r}")
            names.add(entry.name)
            destinations.add(entry.destination)
        return self


class LoadedOutputDlpConfig(BaseModel):
    """Configuration plus the SHA-256 of the exact file bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    config: OutputDlpConfig
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class DlpFinding:
    """One redacted detection summary: code, category, count, field paths."""

    code: str
    category: DlpCategory
    count: int
    fields: tuple[str, ...]


@dataclass(frozen=True)
class DlpReport:
    """A complete, redacted record of one inspection (safe to audit and log)."""

    phase: DlpPhase
    outcome: DlpOutcome
    findings: tuple[DlpFinding, ...]
    max_data_class: DataClass
    version: str
    config_hash: str
    content_digest: str
    content_bytes: int
    truncated: bool = False
    destination_trust: DestinationTrust | None = None
    egress_reason: EgressReason | None = None
    inspection_error: bool = False
    released_digest: str | None = None

    @property
    def finding_codes(self) -> tuple[str, ...]:
        return tuple(finding.code for finding in self.findings)

    @property
    def egress_allowed(self) -> bool:
        return self.phase is DlpPhase.egress and self.egress_reason is EgressReason.passed

    @property
    def response_releasable(self) -> bool:
        return self.phase is DlpPhase.output and self.outcome in (
            DlpOutcome.pass_,
            DlpOutcome.redact,
        )


def load_output_dlp_config(path: str | Path) -> LoadedOutputDlpConfig:
    """Load ``config/output_dlp.yaml``; any problem refuses startup."""
    config_path = Path(path)
    try:
        raw = config_path.read_bytes()
    except OSError as exc:
        raise OutputDlpConfigError(
            f"output-DLP config {config_path} cannot be read: {exc}"
        ) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OutputDlpConfigError(f"output-DLP config {config_path} is not valid UTF-8") from exc
    try:
        data = parse_unique_yaml(text)
    except SafeYamlError as exc:
        raise OutputDlpConfigError(f"output-DLP config {config_path}: {exc}") from exc
    try:
        config = OutputDlpConfig.model_validate(data)
    except ValidationError as exc:
        raise OutputDlpConfigError(
            f"output-DLP config {config_path} failed strict validation: "
            f"{exc.error_count()} error(s)"
        ) from exc
    return LoadedOutputDlpConfig(config=config, sha256=hashlib.sha256(raw).hexdigest())


class OutputDefenseService:
    """Deterministic content classification, egress policy, and response release."""

    def __init__(self, loaded: LoadedOutputDlpConfig) -> None:
        self._loaded = loaded
        self._config = loaded.config
        self._patterns: tuple[tuple[SensitivePattern, re.Pattern[str]], ...] = tuple(
            (spec, re.compile(spec.pattern)) for spec in loaded.config.patterns
        )
        self._destinations = {entry.destination: entry for entry in loaded.config.destinations}

    @property
    def config(self) -> OutputDlpConfig:
        return self._config

    @property
    def config_hash(self) -> str:
        return self._loaded.sha256

    @property
    def version(self) -> str:
        return self._config.version

    def validate_registered_destinations(self, destinations: set[str] | frozenset[str]) -> None:
        """Prove the trust map exactly covers external-mutation capability (fail startup).

        A destination that an adapter can use without a trust entry would bypass the
        destination-aware class check, and a configured destination with no capability
        is dead configuration that can hide a typo. Both refuse startup.
        """
        configured = set(self._destinations)
        missing = sorted(destinations - configured)
        extra = sorted(configured - destinations)
        if missing:
            raise OutputDlpConfigError(
                "registered external destination(s) have no output-DLP trust entry: "
                + ", ".join(missing)
            )
        if extra:
            raise OutputDlpConfigError(
                "output-DLP trust entries have no registered external destination: "
                + ", ".join(extra)
            )

    def inspect_egress(
        self,
        *,
        data: Mapping[str, object],
        declared_data_class: DataClass,
        destination: str | None,
        require_destination: bool,
    ) -> DlpReport:
        """Classify tool-bound data and evaluate it against the destination trust map."""
        canonical: bytes | None = None
        try:
            if not isinstance(declared_data_class, DataClass):
                raise DlpInspectionError("declared data class is not canonical")
            if not require_destination and destination is not None:
                raise DlpInspectionError("a non-egress action must not carry a destination")
            if destination is not None:
                canonical_destination = canonicalize_destination(destination)
                if canonical_destination != destination:
                    raise DlpInspectionError("destination is not canonical")
            canonical = canonical_json_bytes(dict(data))
            self._require_scannable(canonical)
            if require_destination and destination is None:
                return self._egress_report(
                    effective_data_class=declared_data_class,
                    canonical=canonical,
                    findings=(),
                    truncated=False,
                    destination=None,
                    reason=EgressReason.destination_missing,
                )
            findings, truncated = self._find(data)
            effective = max_data_class(
                declared_data_class,
                *(self._pattern_for(finding.code).data_class for finding in findings),
            )
            trust = self._destinations.get(destination) if destination is not None else None
            if any(
                self._pattern_for(finding.code).egress is EgressScope.block for finding in findings
            ):
                reason = EgressReason.category_blocked
            elif not require_destination:
                reason = EgressReason.passed
            elif trust is None:
                reason = EgressReason.destination_not_configured
            elif data_class_rank(effective) > data_class_rank(trust.max_data_class):
                reason = EgressReason.class_above_destination
            else:
                reason = EgressReason.passed
            return self._egress_report(
                effective_data_class=effective,
                canonical=canonical,
                findings=findings,
                truncated=truncated,
                destination=trust,
                reason=reason,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on any inspection failure
            logger.warning("output DLP egress inspection failed closed (%s)", type(exc).__name__)
            return self._failure_report(phase=DlpPhase.egress, canonical=canonical)

    def inspect_output(
        self,
        *,
        data: Mapping[str, object],
        declared_data_class: DataClass,
    ) -> DlpReport:
        """Inspect one complete buffered result and decide its release disposition."""
        canonical: bytes | None = None
        try:
            if not isinstance(declared_data_class, DataClass):
                raise DlpInspectionError("declared data class is not canonical")
            canonical = canonical_json_bytes(dict(data))
            self._require_scannable(canonical)
            findings, truncated = self._find(data)
            effective = max_data_class(
                declared_data_class,
                *(self._pattern_for(finding.code).data_class for finding in findings),
            )
            releases = {self._pattern_for(finding.code).release for finding in findings}
            if DlpRelease.block in releases:
                outcome = DlpOutcome.block
            elif DlpRelease.review in releases:
                outcome = DlpOutcome.review
            elif DlpRelease.redact in releases:
                outcome = DlpOutcome.redact
            else:
                outcome = DlpOutcome.pass_
            return DlpReport(
                phase=DlpPhase.output,
                outcome=outcome,
                findings=findings,
                max_data_class=effective,
                version=self.version,
                config_hash=self.config_hash,
                content_digest=hashlib.sha256(canonical).hexdigest(),
                content_bytes=len(canonical),
                truncated=truncated,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on any inspection failure
            logger.warning("output DLP response inspection failed closed (%s)", type(exc).__name__)
            return self._failure_report(phase=DlpPhase.output, canonical=canonical)

    def redact_payload(
        self, data: Mapping[str, object], *, report: DlpReport
    ) -> tuple[dict[str, object], bool]:
        """Apply the report's REDACT findings to every string value (pure, span-safe)."""
        if report.phase is not DlpPhase.output or report.outcome is not DlpOutcome.redact:
            return dict(data), False
        finding_codes = set(report.finding_codes)
        patterns = tuple(
            (spec, compiled)
            for spec, compiled in self._patterns
            if spec.code in finding_codes and spec.release is DlpRelease.redact
        )
        if not patterns:
            return dict(data), False
        redacted = cast(
            "dict[str, object]",
            _map_strings(data, lambda value: _redact_string(value, patterns)),
        )
        return redacted, True

    def release_failure(self, report: DlpReport) -> DlpReport:
        """Return the fail-closed report for a REDACT release that cannot be completed."""
        if report.phase is not DlpPhase.output:
            raise ValueError("only an OUTPUT report can represent a release failure")
        return replace(report, outcome=DlpOutcome.block, inspection_error=True)

    def released(self, report: DlpReport, *, released_digest: str) -> DlpReport:
        """Attach the released-content digest while preserving the original digest."""
        if report.phase is not DlpPhase.output or report.outcome is not DlpOutcome.redact:
            raise ValueError("only a REDACT release can carry a released digest")
        return replace(report, released_digest=released_digest)

    # -- internals --------------------------------------------------------------------

    def _require_scannable(self, canonical: bytes) -> None:
        if len(canonical) > self._config.limits.max_scan_bytes:
            raise DlpInspectionError("content exceeds the output-DLP scan bound")

    def _pattern_for(self, code: str) -> SensitivePattern:
        for spec, _ in self._patterns:
            if spec.code == code:
                return spec
        raise DlpInspectionError("finding code is not configured")  # pragma: no cover

    def _find(self, data: Mapping[str, object]) -> tuple[tuple[DlpFinding, ...], bool]:
        fields = tuple(_iter_string_fields(data))
        if len(fields) > MAX_SCANNED_FIELDS:
            raise DlpInspectionError("content has too many string fields to inspect")
        findings: list[DlpFinding] = []
        truncated = False
        limit = self._config.limits.max_matches_per_pattern
        for spec, compiled in self._patterns:
            count = 0
            matched_fields: list[str] = []
            for path, text in fields:
                for match in compiled.finditer(text):
                    if match.end() == match.start():
                        continue
                    count += 1
                    if (
                        path not in matched_fields
                        and len(matched_fields) < MAX_FIELD_PATHS_PER_FINDING
                    ):
                        matched_fields.append(path)
                    if count >= limit:
                        truncated = True
                        break
                if count >= limit:
                    break
            if count:
                findings.append(
                    DlpFinding(
                        code=spec.code,
                        category=spec.category,
                        count=count,
                        fields=tuple(matched_fields),
                    )
                )
            if len(findings) >= self._config.limits.max_findings:
                truncated = True
                break
        findings.sort(key=lambda finding: finding.code)
        return tuple(findings), truncated

    def _egress_report(
        self,
        *,
        effective_data_class: DataClass,
        canonical: bytes,
        findings: tuple[DlpFinding, ...],
        truncated: bool,
        destination: DestinationTrust | None,
        reason: EgressReason,
    ) -> DlpReport:
        return DlpReport(
            phase=DlpPhase.egress,
            outcome=DlpOutcome.pass_ if reason is EgressReason.passed else DlpOutcome.block,
            findings=findings,
            max_data_class=effective_data_class,
            version=self.version,
            config_hash=self.config_hash,
            content_digest=hashlib.sha256(canonical).hexdigest(),
            content_bytes=len(canonical),
            truncated=truncated,
            destination_trust=destination,
            egress_reason=reason,
        )

    def _failure_report(
        self,
        *,
        phase: DlpPhase,
        canonical: bytes | None,
    ) -> DlpReport:
        payload = canonical if canonical is not None else b""
        return DlpReport(
            phase=phase,
            outcome=DlpOutcome.block,
            findings=(),
            # A failed inspection cannot prove the content is less sensitive, so the
            # report records the most restrictive class. The caller blocks/suppresses.
            max_data_class=DataClass.restricted,
            version=self.version,
            config_hash=self.config_hash,
            content_digest=hashlib.sha256(payload).hexdigest(),
            content_bytes=len(payload),
            egress_reason=EgressReason.category_blocked if phase is DlpPhase.egress else None,
            inspection_error=True,
        )


def _iter_string_fields(
    data: object, prefix: str = "", depth: int = 0
) -> Iterator[tuple[str, str]]:
    """Yield (field path, string value) pairs without following non-JSON objects."""
    if depth > MAX_TRAVERSAL_DEPTH:
        raise DlpInspectionError("content nesting exceeds the inspection depth")
    if isinstance(data, str):
        yield (prefix or "$", data)
        return
    if isinstance(data, Mapping):
        for key, value in data.items():
            if not isinstance(key, str):
                raise DlpInspectionError("content mapping keys must be strings")
            path = f"{prefix}.{key}" if prefix else key
            if len(path) > MAX_FIELD_PATH_LENGTH:
                raise DlpInspectionError("content field path is too long")
            yield from _iter_string_fields(value, path, depth + 1)
        return
    if isinstance(data, (list, tuple)):
        for index, value in enumerate(data):
            path = f"{prefix}[{index}]"
            if len(path) > MAX_FIELD_PATH_LENGTH:
                raise DlpInspectionError("content field path is too long")
            yield from _iter_string_fields(value, path, depth + 1)


def _map_strings(data: object, transform: Callable[[str], str]) -> object:
    """Return a deep copy with every string value transformed (never mutates input)."""
    if isinstance(data, str):
        return transform(data)
    if isinstance(data, dict):
        return {key: _map_strings(value, transform) for key, value in data.items()}
    if isinstance(data, list):
        return [_map_strings(value, transform) for value in data]
    if isinstance(data, tuple):
        return tuple(_map_strings(value, transform) for value in data)
    return data


def _redact_string(
    value: str, patterns: tuple[tuple[SensitivePattern, re.Pattern[str]], ...]
) -> str:
    spans: list[tuple[int, int, DlpCategory, int]] = []
    for spec, compiled in patterns:
        try:
            matches = tuple(compiled.finditer(value))
        except Exception as exc:  # noqa: BLE001 - regex engine failure must fail closed
            raise DlpInspectionError("sensitive-pattern scan failed") from exc
        for match in matches:
            if match.end() > match.start():
                spans.append(
                    (match.start(), match.end(), spec.category, data_class_rank(spec.data_class))
                )
    if not spans:
        return value
    # Overlapping matches must be merged, not dropped: dropping a span that extends past
    # an earlier replacement would release the tail of the longer match.
    spans.sort(key=lambda span: (span[0], -span[1], -span[3], span[2].value))
    pieces: list[str] = []
    cursor = 0
    index = 0
    while index < len(spans):
        start, end, category, rank = spans[index]
        index += 1
        while index < len(spans) and spans[index][0] < end:
            next_start, next_end, next_category, next_rank = spans[index]
            end = max(end, next_end)
            if next_rank > rank:
                category, rank = next_category, next_rank
            index += 1
        pieces.append(value[cursor:start])
        pieces.append(category.redaction_marker)
        cursor = end
    pieces.append(value[cursor:])
    return "".join(pieces)


__all__ = [
    "DestinationTrust",
    "DestinationTrustLabel",
    "DlpCategory",
    "DlpFinding",
    "DlpInspectionError",
    "DlpLimits",
    "DlpOutcome",
    "DlpPhase",
    "DlpRelease",
    "DlpReport",
    "EgressReason",
    "EgressScope",
    "LoadedOutputDlpConfig",
    "OutputDefenseService",
    "OutputDlpConfig",
    "OutputDlpConfigError",
    "SensitivePattern",
    "load_output_dlp_config",
]

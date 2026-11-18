"""Optional local read-only audit summarizer (blueprint section 17.2; ADR-004, ADR-017).

The summarizer is an **AI component and therefore an attack surface**. It is:

- **Opt-in and off by default** (``SOC_SUMMARIZER_ENABLED=false``).
- **Read-only**: it reads existing audit evidence and may at most annotate an alert
  with an unverified hypothesis. It cannot invoke tools, consume approvals, change
  policies, alter audit records, revoke sessions, terminate workloads, or trigger a
  circuit breaker.
- **Untrusted input boundary**: every request/tool-originated field is explicitly
  labeled ``EXTERNAL_UNTRUSTED``. Input is bounded and redacted before any model
  submission. Raw audit payloads are never sent to a model.
- **No cloud calls**: the default implementation is a deterministic local stub. A
  strict injected-client interface exists for a future local model; live-model
  evaluation is documented as future work.
- **Output labeled unverified**: results are hypotheses, not facts.

Adversarial-log tests (``tests/unit/test_soc_summarizer.py``) prove injected log text
cannot trigger any action beyond a bounded alert/hypothesis.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Bounds for summarizer input (defends against attacker-influenced audit volume).
_MAX_EVENTS = 512
_MAX_CHARS_PER_FIELD = 256
_MAX_FIELDS_PER_EVENT = 16
_MAX_OUTPUT_CHARS = 1_024
_TRUST_LABEL_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

#: Fields that originate from request/tool/audit input and must be labeled untrusted.
_EXTERNAL_UNTRUSTED_FIELDS = frozenset(
    {
        "text",
        "tool_id",
        "action_id",
        "arguments",
        "destination",
        "resource_ids",
        "error_type",
        "reason",
        "event_type",
        "request_id",
        "call_id",
        "session_id",
        "principal_subject_id",
        "approver_subject_id",
    }
)


class TrustLabel(StrEnum):
    """Trust labels for summarizer input segments (blueprint section 2.2)."""

    SYSTEM_POLICY = "SYSTEM_POLICY"
    AUTHENTICATED_USER = "AUTHENTICATED_USER"
    MODEL_GENERATED = "MODEL_GENERATED"
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"
    TOOL_RESULT = "TOOL_RESULT"
    SECURITY_METADATA = "SECURITY_METADATA"


class SummarizedEvent(BaseModel):
    """One bounded, redacted, trust-labeled event for summarizer input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence_number: int = Field(ge=0)
    event_type: str = Field(min_length=1, max_length=64)
    trust_label: TrustLabel
    fields: dict[str, str] = Field(default_factory=dict, max_length=_MAX_FIELDS_PER_EVENT)
    redacted_field_count: int = Field(default=0, ge=0, le=_MAX_FIELDS_PER_EVENT)
    content_digest: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class SummarizerInputEnvelope(BaseModel):
    """Structured envelope for summarizer input.

    All request/tool-originated fields are labeled ``EXTERNAL_UNTRUSTED``. The envelope
    is bounded: at most ``_MAX_EVENTS`` events, each with at most
    ``_MAX_FIELDS_PER_EVENT`` fields of at most ``_MAX_CHARS_PER_CHAR`` characters.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    generated_at: datetime
    event_count: int = Field(ge=0, le=_MAX_EVENTS)
    events: tuple[SummarizedEvent, ...] = Field(max_length=_MAX_EVENTS)
    untrusted_field_count: int = Field(ge=0)
    redacted_total: int = Field(ge=0)
    content_digest: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("generated_at")
    @classmethod
    def _timestamp_is_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value.astimezone(UTC)


class SummarizerOutput(BaseModel):
    """Summarizer output — labeled unverified hypothesis, never a fact or authority.

    ``hypothesis`` is a short, bounded, content-free string. ``recommended_action`` is
    limited to ``annotate_alert`` or ``no_action`` — it cannot invoke tools, approve,
    revoke, or contain.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    generated_at: datetime
    hypothesis: str = Field(min_length=1, max_length=_MAX_OUTPUT_CHARS)
    recommended_action: Literal["annotate_alert", "no_action"] = "no_action"
    confidence_note: str = Field(
        default="unverified hypothesis from an optional local summarizer; not a fact",
        min_length=1,
        max_length=256,
    )
    content_digest: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("generated_at")
    @classmethod
    def _timestamp_is_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("hypothesis")
    @classmethod
    def _hypothesis_is_content_free(cls, value: str) -> str:
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("hypothesis must not contain control characters")
        return value


@dataclass(frozen=True)
class SummarizerResult:
    """Result of a summarization run."""

    output: SummarizerOutput | None
    skipped: bool
    reason: str | None = None
    error: str | None = None


class SummarizerClient(Protocol):
    """Strict injected client interface for a future local summarizer model.

    The default implementation (``DeterministicSummarizerStub``) does not call any
    model. A real local model client would implement this protocol without network,
    without tool access, and without authority.
    """

    async def summarize(self, envelope: SummarizerInputEnvelope) -> str:
        """Return a bounded hypothesis string, or raise on failure.

        Implementations must not perform tool calls, policy edits, audit writes,
        approvals, revocations, or containment.
        """


class DeterministicSummarizerStub:
    """Default offline summarizer: deterministic, bounded, no model, no authority.

    Produces a hypothesis derived only from event-type counts and severity patterns —
    never from raw event content. Output is labeled unverified.
    """

    async def summarize(self, envelope: SummarizerInputEnvelope) -> str:
        event_types: dict[str, int] = {}
        for event in envelope.events:
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
        if not event_types:
            return "no audit events in observation window"
        top = sorted(event_types.items(), key=lambda item: (-item[1], item[0]))[:3]
        parts = ", ".join(f"{name} x{count}" for name, count in top)
        return f"observed {envelope.event_count} events; most frequent: {parts}"


class AuditSummarizer:
    """Orchestrates bounded, redacted, trust-labeled input and a stub/local client.

    The summarizer is opt-in (``enabled=False`` by default). When disabled, every call
    returns a skipped result with no hypothesis.
    """

    def __init__(
        self,
        client: SummarizerClient | None = None,
        *,
        enabled: bool = False,
        component_version: str = "0.1.0",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._client = client if client is not None else DeterministicSummarizerStub()
        self._enabled = enabled
        self._component_version = component_version
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _redact_value(self, value: object) -> str:
        """Redact a single field value to a bounded, content-free string."""
        if value is None:
            return "[redacted]"
        if isinstance(value, bool):
            return "bool"
        if isinstance(value, int):
            return "int"
        if isinstance(value, float):
            return "float"
        if isinstance(value, str):
            if len(value) > _MAX_CHARS_PER_FIELD:
                return value[: _MAX_CHARS_PER_FIELD - 3] + "..."
            return value
        if isinstance(value, (list, tuple)):
            return f"list[{len(value)}]"
        if isinstance(value, dict):
            return f"dict[{len(value)}]"
        return type(value).__name__

    def _trust_label_for_field(self, field_name: str) -> TrustLabel:
        """Request/tool-originated fields are EXTERNAL_UNTRUSTED; everything else is
        SYSTEM_POLICY or SECURITY_METADATA."""
        if field_name in _EXTERNAL_UNTRUSTED_FIELDS:
            return TrustLabel.EXTERNAL_UNTRUSTED
        if field_name in (
            "sequence_number",
            "event_hash",
            "previous_hash",
            "policy_version",
            "policy_hash",
            "risk_version",
            "component",
            "component_version",
        ):
            return TrustLabel.SECURITY_METADATA
        return TrustLabel.SYSTEM_POLICY

    def build_envelope(
        self, events: list[dict[str, object]], *, generated_at: datetime | None = None
    ) -> SummarizerInputEnvelope:
        """Build a bounded, redacted, trust-labeled envelope from raw audit events.

        Raw audit payloads are never included verbatim: each field is truncated and
        labeled, and untrusted fields are counted.
        """
        now = generated_at or self._clock()
        if now.utcoffset() is None:
            now = now.replace(tzinfo=UTC)

        bounded_events = events[:_MAX_EVENTS]
        summarized: list[SummarizedEvent] = []
        untrusted_count = 0
        redacted_total = 0
        digest_input: list[str] = []

        for event in bounded_events:
            seq = event.get("sequence_number", 0)
            if not isinstance(seq, int):
                seq = 0
            event_type_raw = event.get("event_type", "UNKNOWN")
            event_type = str(event_type_raw)[:64]

            fields: dict[str, str] = {}
            event_redacted = 0
            event_untrusted = 0
            for field_name, field_value in event.items():
                if field_name in (
                    "sequence_number",
                    "event_hash",
                    "previous_hash",
                    "canonical_event_bytes",
                ):
                    continue
                if len(fields) >= _MAX_FIELDS_PER_EVENT:
                    event_redacted += 1
                    continue
                label = self._trust_label_for_field(field_name)
                if label is TrustLabel.EXTERNAL_UNTRUSTED:
                    event_untrusted += 1
                fields[field_name] = self._redact_value(field_value)
                digest_input.append(f"{field_name}={fields[field_name]}")

            summarized.append(
                SummarizedEvent(
                    sequence_number=seq,
                    event_type=event_type,
                    trust_label=(
                        TrustLabel.EXTERNAL_UNTRUSTED
                        if event_untrusted > 0
                        else TrustLabel.SECURITY_METADATA
                    ),
                    fields=fields,
                    redacted_field_count=event_redacted,
                    content_digest=hashlib.sha256(
                        "|".join(digest_input).encode("utf-8")
                    ).hexdigest(),
                )
            )
            untrusted_count += event_untrusted
            redacted_total += event_redacted

        digest_input.append(
            f"count={len(summarized)}:untrusted={untrusted_count}:redacted={redacted_total}"
        )
        envelope_digest = hashlib.sha256("|".join(digest_input).encode("utf-8")).hexdigest()

        return SummarizerInputEnvelope(
            generated_at=now,
            event_count=len(summarized),
            events=tuple(summarized),
            untrusted_field_count=untrusted_count,
            redacted_total=redacted_total,
            content_digest=envelope_digest,
        )

    async def summarize_events(
        self,
        events: list[dict[str, object]],
        *,
        generated_at: datetime | None = None,
    ) -> SummarizerResult:
        """Summarize read-only audit events into an unverified hypothesis.

        When disabled, returns a skipped result. On client failure, returns an error
        result with no hypothesis — the summarizer never fabricates output and never
        becomes an authority.
        """
        if not self._enabled:
            return SummarizerResult(
                output=None,
                skipped=True,
                reason="summarizer is disabled (opt-in; SOC_SUMMARIZER_ENABLED=false)",
            )

        envelope = self.build_envelope(events, generated_at=generated_at)
        try:
            hypothesis = await self._client.summarize(envelope)
        except Exception as exc:  # noqa: BLE001 - client failure must not become authority
            return SummarizerResult(
                output=None,
                skipped=False,
                reason=None,
                error=f"summarizer client failed: {type(exc).__name__}",
            )

        now = generated_at or self._clock()
        if now.utcoffset() is None:
            now = now.replace(tzinfo=UTC)
        output_digest_input = f"hypothesis={hypothesis}:envelope={envelope.content_digest}"
        output = SummarizerOutput(
            generated_at=now,
            hypothesis=hypothesis[:_MAX_OUTPUT_CHARS],
            recommended_action="annotate_alert" if hypothesis.strip() else "no_action",
            content_digest=hashlib.sha256(output_digest_input.encode("utf-8")).hexdigest(),
        )
        return SummarizerResult(output=output, skipped=False, reason=None, error=None)


__all__ = [
    "AuditSummarizer",
    "DeterministicSummarizerStub",
    "SummarizerClient",
    "SummarizerInputEnvelope",
    "SummarizerOutput",
    "SummarizedEvent",
    "SummarizerResult",
    "TrustLabel",
]

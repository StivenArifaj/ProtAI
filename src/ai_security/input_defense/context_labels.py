"""Trust-labelled prompt/context assembly (blueprint sections 2.2, 7.2 step 4, 7.3).

The assembler preserves provenance in a structured form; it never rewrites or deletes
content. External content and tool results carry their untrusted labels into the
assembled context so a later model step can distinguish instructions from data. A label
is not enforcement: the firewall gateway remains mandatory for every tool call.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import MAX_SEGMENT_ID_LENGTH, MAX_SOURCE_ID_LENGTH, TrustLabel


class ContextAssemblyError(ValueError):
    """The context is malformed (empty, duplicate segment ids, blank content)."""


class ContextSegment(BaseModel):
    """One labelled content segment; the label survives assembly and rendering."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    segment_id: str = Field(min_length=1, max_length=MAX_SEGMENT_ID_LENGTH)
    source_id: str = Field(min_length=1, max_length=MAX_SOURCE_ID_LENGTH)
    trust_label: TrustLabel
    content: str

    @field_validator("content")
    @classmethod
    def _content_is_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("content must not be blank")
        return value


class ContextMessage(BaseModel):
    """A rendered context message with provenance metadata alongside the content."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    segment_id: str
    source_id: str
    trust_label: TrustLabel
    content: str


class AgentContext(BaseModel):
    """Ordered, labelled context handed to an agent/runtime (Phase 4+ consumer)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    segments: tuple[ContextSegment, ...]

    @field_validator("segments")
    @classmethod
    def _unique_non_empty(cls, value: tuple[ContextSegment, ...]) -> tuple[ContextSegment, ...]:
        if not value:
            raise ContextAssemblyError("context requires at least one segment")
        segment_ids = [segment.segment_id for segment in value]
        if len(set(segment_ids)) != len(segment_ids):
            raise ContextAssemblyError("segment ids must be unique within a context")
        return value

    def messages(self) -> tuple[ContextMessage, ...]:
        """Preserve labels and order; no role mapping yet (no model provider in v1)."""
        return tuple(
            ContextMessage(
                segment_id=segment.segment_id,
                source_id=segment.source_id,
                trust_label=segment.trust_label,
                content=segment.content,
            )
            for segment in self.segments
        )

    def render(self) -> str:
        """Deterministic structured rendering; labels are part of every segment."""
        return json.dumps(
            [
                {
                    "content": message.content,
                    "segment_id": message.segment_id,
                    "source_id": message.source_id,
                    "trust_label": message.trust_label.value,
                }
                for message in self.messages()
            ],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def system_policy_segment(*, segment_id: str, content: str) -> ContextSegment:
    """Application-owned policy/instruction content."""
    return ContextSegment(
        segment_id=segment_id,
        source_id="application",
        trust_label=TrustLabel.system_policy,
        content=content,
    )


def authenticated_user_segment(*, segment_id: str, subject_id: str, content: str) -> ContextSegment:
    """The user's own request text, bound to a verified principal."""
    return ContextSegment(
        segment_id=segment_id,
        source_id=subject_id,
        trust_label=TrustLabel.authenticated_user,
        content=content,
    )


def external_content_segment(*, segment_id: str, source_id: str, content: str) -> ContextSegment:
    """Retrieved email/file/web content: always EXTERNAL_UNTRUSTED, even for a user."""
    return ContextSegment(
        segment_id=segment_id,
        source_id=source_id,
        trust_label=TrustLabel.external_untrusted,
        content=content,
    )


def tool_result_segment(*, segment_id: str, source_id: str, content: str) -> ContextSegment:
    """Tool output is untrusted unless an adapter validates a field's source."""
    return ContextSegment(
        segment_id=segment_id,
        source_id=source_id,
        trust_label=TrustLabel.tool_result,
        content=content,
    )


def model_generated_segment(*, segment_id: str, content: str) -> ContextSegment:
    """Model output/proposals: never treated as authorization."""
    return ContextSegment(
        segment_id=segment_id,
        source_id="model",
        trust_label=TrustLabel.model_generated,
        content=content,
    )


def assemble_context(segments: tuple[ContextSegment, ...]) -> AgentContext:
    """Assemble typed segments; malformed/empty/duplicate-id contexts are refused."""
    if not segments:
        raise ContextAssemblyError("context requires at least one segment")
    segment_ids = [segment.segment_id for segment in segments]
    if len(set(segment_ids)) != len(segment_ids):
        raise ContextAssemblyError("segment ids must be unique within a context")
    return AgentContext(segments=segments)

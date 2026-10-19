"""Intent extractor interface and the Phase 4 implementations (blueprint §8.2).

``MockIntentExtractor`` is a deliberately narrow deterministic test/runtime stub: it
supports only the documented demo scenarios and asks for clarification otherwise. It is
not presented as general natural-language understanding.

``LocalModelIntentExtractor`` adapts an injected local-model client (Phase 8 wires the
actual provider). Model output is bounded, parsed with duplicate-key rejection, and
strictly validated; malformed output is retried a small configured number of times and
then fails with no manifest. Extractors never create manifests and never decide policy.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ai_security.intent.models import (
    IntentConstraint,
    IntentExtraction,
    IntentExtractionRequest,
    IntentExtractionStatus,
    RelativeTimeScope,
)

MOCK_EXTRACTOR_VERSION = "mock-intent-v1"
LOCAL_MODEL_EXTRACTOR_VERSION = "local-model-intent-v1"
MAX_MODEL_OUTPUT_BYTES = 65_536
DEFAULT_MAX_ATTEMPTS = 2
DEFAULT_TIMEOUT_SECONDS = 5.0


class IntentExtractorError(RuntimeError):
    """Base extractor failure; callers must treat every one as no-manifest."""


class IntentExtractorUnavailable(IntentExtractorError):
    """The extractor/provider is unavailable (outage, timeout, protocol failure)."""


class InvalidIntentExtraction(IntentExtractorError):
    """The extractor returned malformed or out-of-contract structured output."""


class IntentExtractor(Protocol):
    """Interface implemented by mock, local, and (opt-in) cloud extractors."""

    extractor_version: str

    async def extract(self, request: IntentExtractionRequest) -> IntentExtraction:
        """Return a validated extraction or raise an ``IntentExtractorError``."""
        ...


class IntentModelClient(Protocol):
    """Minimal local-model adapter interface (real HTTP wiring is Phase 8)."""

    async def complete(self, *, prompt: str) -> str:
        """Return bounded JSON text for one extraction prompt."""
        ...


def _summarize_day_constraints() -> tuple[IntentConstraint, ...]:
    return (
        IntentConstraint(
            tool_id="mock_email.search",
            action_id="search",
            allowed_parameter_values={"query": ("unread",)},
        ),
        IntentConstraint(
            tool_id="text.summarize",
            action_id="summarize",
            allowed_parameter_values={"max_chars": (200,)},
        ),
    )


_READ_AND_SUMMARIZE = re.compile(
    r"read (email-[a-z0-9][a-z0-9._-]{0,120}) and summarize (?:it|the email)", re.IGNORECASE
)
_SUMMARIZE_TODAY = re.compile(r"summarize my unread emails?(?: from| for)? today", re.IGNORECASE)
_OUT_OF_SCOPE_ACTIONS = re.compile(
    r"\b(?:forward|send|delete|remove|upload|share)\b", re.IGNORECASE
)


class MockIntentExtractor:
    """Deterministic demo scenarios only; never guesses an unsupported goal."""

    extractor_version = MOCK_EXTRACTOR_VERSION

    async def extract(self, request: IntentExtractionRequest) -> IntentExtraction:
        text = " ".join(request.text.split())

        if _SUMMARIZE_TODAY.search(text):
            return IntentExtraction(
                status=IntentExtractionStatus.active,
                constraints=_summarize_day_constraints(),
                confidence_score=100,
                relative_time_scope=RelativeTimeScope.today,
                extractor_version=self.extractor_version,
            )

        match = _READ_AND_SUMMARIZE.search(text)
        if match is not None:
            return IntentExtraction(
                status=IntentExtractionStatus.active,
                constraints=(
                    IntentConstraint(
                        tool_id="mock_email.read",
                        action_id="read",
                        allowed_resource_ids=(match.group(1),),
                    ),
                    IntentConstraint(
                        tool_id="text.summarize",
                        action_id="summarize",
                        allowed_parameter_values={"max_chars": (200,)},
                    ),
                ),
                confidence_score=100,
                extractor_version=self.extractor_version,
            )

        if _OUT_OF_SCOPE_ACTIONS.search(text):
            return IntentExtraction(
                status=IntentExtractionStatus.rejected,
                clarification_question=(
                    "The requested action is outside the mock extractor's supported "
                    "demo intents; no manifest was issued."
                ),
                extractor_version=self.extractor_version,
            )

        return IntentExtraction(
            status=IntentExtractionStatus.requires_clarification,
            clarification_question=(
                "The mock extractor supports only 'summarize my unread emails from "
                "today' and 'read email-N and summarize it'. Please use one of those "
                "demo requests."
            ),
            extractor_version=self.extractor_version,
        )


class _ModelConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    action_id: str
    allowed_resource_ids: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    allowed_parameter_values: dict[str, tuple[str | int | bool | None, ...]] = Field(
        default_factory=dict
    )
    max_uses: int = 1


class _ModelIntentOutput(BaseModel):
    """Provider output shape; provider cannot set the extractor version or bindings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: IntentExtractionStatus
    constraints: tuple[_ModelConstraint, ...] = ()
    clarification_question: str | None = None
    confidence_score: int | None = None
    relative_time_scope: RelativeTimeScope | None = None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _parse_bounded_json(text: str) -> dict[str, object]:
    if len(text.encode("utf-8")) > MAX_MODEL_OUTPUT_BYTES:
        raise ValueError("model output exceeds the bounded JSON size")
    try:
        parsed: object = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("model output is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("model output must be a JSON object")
    return parsed


def _prompt_for(request: IntentExtractionRequest) -> str:
    return (
        "Extract the user's apparent goal into the strict JSON schema. You are not an "
        "authorization service. Do not invent recipients, file scope, destinations, or "
        "authority. Use status ACTIVE only with concrete constraints; otherwise use "
        "REQUIRES_CLARIFICATION (or REJECTED) with a clarification_question. Allowed "
        "relative_time_scope values: TODAY, THIS_WEEK (the server resolves time using "
        "a trusted timezone). Constraints use tool_id, action_id, "
        "allowed_resource_ids, allowed_destinations, allowed_parameter_values, "
        "max_uses. Unknown extra fields are rejected.\n\nUSER REQUEST:\n"
        f"{request.text}"
    )


class LocalModelIntentExtractor:
    """Strict adapter around an injected local-model client (no network here)."""

    extractor_version = LOCAL_MODEL_EXTRACTOR_VERSION

    def __init__(
        self,
        client: IntentModelClient,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if not 1 <= max_attempts <= 3:
            raise ValueError("max_attempts must be in [1, 3]")
        if not 0.1 <= timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be in [0.1, 60]")
        self._client = client
        self._max_attempts = max_attempts
        self._timeout_seconds = timeout_seconds

    async def extract(self, request: IntentExtractionRequest) -> IntentExtraction:
        prompt = _prompt_for(request)
        last_error: Exception | None = None
        for _attempt in range(self._max_attempts):
            try:
                raw = await asyncio.wait_for(
                    self._client.complete(prompt=prompt), timeout=self._timeout_seconds
                )
            except TimeoutError as exc:
                raise IntentExtractorUnavailable("local model timed out") from exc
            except IntentExtractorError:
                raise
            except Exception as exc:  # noqa: BLE001 - provider boundary fails closed
                raise IntentExtractorUnavailable("local model client failed") from exc

            try:
                output = _ModelIntentOutput.model_validate(_parse_bounded_json(raw))
                constraints = tuple(
                    IntentConstraint(
                        tool_id=item.tool_id,
                        action_id=item.action_id,
                        allowed_resource_ids=tuple(item.allowed_resource_ids),
                        allowed_destinations=tuple(item.allowed_destinations),
                        allowed_parameter_values={
                            name: tuple(values)
                            for name, values in item.allowed_parameter_values.items()
                        },
                        max_uses=item.max_uses,
                    )
                    for item in output.constraints
                )
                return IntentExtraction(
                    status=output.status,
                    constraints=constraints,
                    clarification_question=output.clarification_question,
                    confidence_score=output.confidence_score,
                    relative_time_scope=output.relative_time_scope,
                    extractor_version=self.extractor_version,
                )
            except (ValidationError, ValueError) as exc:
                last_error = exc

        raise InvalidIntentExtraction(
            "local model returned invalid structured output"
        ) from last_error


__all__ = [
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_TIMEOUT_SECONDS",
    "IntentExtractor",
    "IntentExtractorError",
    "IntentExtractorUnavailable",
    "IntentModelClient",
    "InvalidIntentExtraction",
    "LOCAL_MODEL_EXTRACTOR_VERSION",
    "LocalModelIntentExtractor",
    "MOCK_EXTRACTOR_VERSION",
    "MockIntentExtractor",
]

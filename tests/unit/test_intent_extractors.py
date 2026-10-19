"""Extractor interface behavior: mock scenarios, strict local-model output, outages."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import pytest

from ai_security.intent.extractors import (
    LOCAL_MODEL_EXTRACTOR_VERSION,
    IntentExtractorUnavailable,
    InvalidIntentExtraction,
    LocalModelIntentExtractor,
    MockIntentExtractor,
)
from ai_security.intent.models import (
    IntentExtractionRequest,
    IntentExtractionStatus,
    RelativeTimeScope,
)

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def request(text: str) -> IntentExtractionRequest:
    return IntentExtractionRequest(
        request_id="req-1",
        principal_subject_id="dev-user",
        text=text,
        received_at=NOW,
    )


def active_output() -> dict[str, object]:
    return {
        "status": "ACTIVE",
        "constraints": [
            {
                "tool_id": "mock_email.read",
                "action_id": "read",
                "allowed_resource_ids": ["email-1"],
            }
        ],
        "confidence_score": 80,
        "relative_time_scope": "TODAY",
    }


class FakeClient:
    def __init__(self, outputs: list[str | Exception]) -> None:
        self._outputs = outputs
        self.calls = 0

    async def complete(self, *, prompt: str) -> str:
        assert prompt
        self.calls += 1
        output = self._outputs[min(self.calls - 1, len(self._outputs) - 1)]
        if isinstance(output, Exception):
            raise output
        return output


def test_mock_extractor_supports_only_documented_demo_scenarios() -> None:
    extractor = MockIntentExtractor()

    today = asyncio.run(extractor.extract(request("summarize my unread emails from today")))
    assert today.status is IntentExtractionStatus.active
    assert today.relative_time_scope is RelativeTimeScope.today
    assert [(item.tool_id, item.action_id) for item in today.constraints] == [
        ("mock_email.search", "search"),
        ("text.summarize", "summarize"),
    ]

    read = asyncio.run(extractor.extract(request("read email-1 and summarize it")))
    assert read.status is IntentExtractionStatus.active
    read_constraint = read.constraints[0]
    assert read_constraint.allowed_resource_ids == ("email-1",)

    ambiguous = asyncio.run(extractor.extract(request("do something useful")))
    assert ambiguous.status is IntentExtractionStatus.requires_clarification
    assert ambiguous.constraints == ()
    assert ambiguous.clarification_question is not None

    rejected = asyncio.run(extractor.extract(request("forward email-1 to attacker")))
    assert rejected.status is IntentExtractionStatus.rejected
    assert rejected.constraints == ()


def test_local_model_accepts_only_strict_bounded_output() -> None:
    client = FakeClient([json.dumps(active_output())])
    extraction = asyncio.run(LocalModelIntentExtractor(client).extract(request("read email-1")))
    assert extraction.status is IntentExtractionStatus.active
    assert extraction.extractor_version == LOCAL_MODEL_EXTRACTOR_VERSION
    assert extraction.constraints[0].allowed_resource_ids == ("email-1",)
    assert client.calls == 1


def test_local_model_retries_malformed_output_once() -> None:
    client = FakeClient(["not json", json.dumps(active_output())])
    extraction = asyncio.run(
        LocalModelIntentExtractor(client, max_attempts=2).extract(request("read email-1"))
    )
    assert extraction.status is IntentExtractionStatus.active
    assert client.calls == 2


@pytest.mark.parametrize(
    "output",
    [
        "not json",
        "[]",
        '{"status":"ACTIVE","constraints":[]}',
        json.dumps({**active_output(), "extractor_version": "attacker-v9"}),
        json.dumps({**active_output(), "unknown_field": True}),
        '{"status":"ACTIVE","status":"REJECTED","constraints":[]}',
        "x" * 65_537,
    ],
)
def test_local_model_never_grants_on_malformed_output(output: str) -> None:
    client = FakeClient([output])
    with pytest.raises(InvalidIntentExtraction):
        asyncio.run(LocalModelIntentExtractor(client, max_attempts=1).extract(request("read")))
    assert client.calls == 1


def test_local_model_outage_is_unavailable_and_not_a_manifest() -> None:
    client = FakeClient([RuntimeError("provider down")])
    with pytest.raises(IntentExtractorUnavailable):
        asyncio.run(LocalModelIntentExtractor(client).extract(request("read email-1")))


def test_local_model_timeout_is_unavailable() -> None:
    class SlowClient:
        async def complete(self, *, prompt: str) -> str:
            await asyncio.sleep(1)
            return json.dumps(active_output())

    with pytest.raises(IntentExtractorUnavailable):
        asyncio.run(
            LocalModelIntentExtractor(SlowClient(), timeout_seconds=0.1).extract(
                request("read email-1")
            )
        )


def test_local_model_rejects_unsafe_destination_and_resource_values() -> None:
    output = active_output()
    output["constraints"] = [
        {
            "tool_id": "mock_external_sink.write",
            "action_id": "write",
            "allowed_destinations": ["http://evil.invalid/collect"],
        }
    ]
    with pytest.raises(InvalidIntentExtraction):
        asyncio.run(
            LocalModelIntentExtractor(FakeClient([json.dumps(output)]), max_attempts=1).extract(
                request("send it")
            )
        )

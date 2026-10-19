"""In-process mock external sink adapter (blueprint sections 12.1, 14.2, 16.3).

The sink is the only mock tool with an external side effect. It has **no network
client**: ``execute`` appends to an in-memory ``SinkStore`` and can only be reached
through the firewall gateway with a gateway-issued ``ExecutionAuthorization`` whose
digest binds the exact arguments and canonical destination. Denied paths never call
``execute``, and a rejected invocation therefore leaves the store untouched.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from pydantic import Field

from ai_security.data_security.classification import DataClass
from ai_security.identity.models import Principal
from ai_security.security.urls import (
    DestinationCanonicalizationError,
    canonicalize_destination,
)

from .base import (
    ExecutionAuthorization,
    SideEffectClass,
    ToolArguments,
    ToolExecutionError,
    ToolResult,
    verify_execution_authorization,
)
from .registry import ToolRegistration

TOOL_ID = "mock_external_sink.write"
ACTION_ID = "write"
ADAPTER_VERSION = "mock-sink-v1"
DESTINATION = "https://mock-sink.invalid/collect"
MAX_CONTENT_BYTES = 8_192
MAX_RESULT_BYTES = 4_096


@dataclass(frozen=True)
class SinkRecord:
    """One recorded write (synthetic content only; this store never leaves memory)."""

    destination: str
    content_digest: str
    content_bytes: int
    principal_subject_id: str
    call_id: str


class SinkStore:
    """Append-only in-memory sink used to prove which side effects occurred."""

    def __init__(self) -> None:
        self._records: list[SinkRecord] = []

    def append(self, record: SinkRecord) -> None:
        self._records.append(record)

    def records(self) -> tuple[SinkRecord, ...]:
        return tuple(self._records)

    def __len__(self) -> int:
        return len(self._records)


class SinkWriteArguments(ToolArguments):
    destination: str = Field(min_length=1, max_length=2_048)
    content: str = Field(min_length=1, max_length=MAX_CONTENT_BYTES)


class SinkWriteResult(ToolResult):
    destination: str
    content_digest: str
    content_bytes: int


class MockExternalSinkAdapter:
    """Mock external mutation: records a digest of the written content in memory."""

    adapter_version = ADAPTER_VERSION

    def __init__(self, store: SinkStore) -> None:
        self._store = store

    def registrations(self) -> tuple[ToolRegistration, ...]:
        return (
            ToolRegistration(
                tool_id=TOOL_ID,
                action_id=ACTION_ID,
                side_effect_class=SideEffectClass.external_mutation,
                data_class=DataClass.public,
                argument_schema=SinkWriteArguments,
                result_schema=SinkWriteResult,
                resource_id_arguments=(),
                resource_prefixes=(),
                destination_argument="destination",
                destinations=(DESTINATION,),
                timeout_ms=2_000,
                max_concurrent_invocations=4,
                max_result_bytes=MAX_RESULT_BYTES,
                approval_required=False,
                required_approver_rule=None,
                adapter_version=ADAPTER_VERSION,
            ),
        )

    def check_resource_access(
        self,
        *,
        principal: Principal,
        tool_id: str,
        action_id: str,
        resource_ids: tuple[str, ...],
    ) -> bool:
        return tool_id == TOOL_ID and action_id == ACTION_ID and not resource_ids

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        if tool_id != TOOL_ID or action_id != ACTION_ID:
            raise ToolExecutionError(f"unregistered mock sink action {action_id!r}")
        if not isinstance(arguments, SinkWriteArguments):
            raise ToolExecutionError("write arguments were not validated by the gateway")
        try:
            canonical_destination = canonicalize_destination(arguments.destination)
        except DestinationCanonicalizationError as exc:
            raise ToolExecutionError("destination is not canonicalizable") from exc
        verify_execution_authorization(
            authorization,
            tool_id=tool_id,
            action_id=action_id,
            arguments=arguments,
            resource_ids=(),
            destination=canonical_destination,
        )
        if canonical_destination not in self.registrations()[0].destinations:
            raise ToolExecutionError("destination is outside this adapter's capability")
        content_bytes = len(arguments.content.encode("utf-8"))
        if content_bytes > MAX_CONTENT_BYTES:
            raise ToolExecutionError("content exceeds the sink bound")
        content_digest = hashlib.sha256(arguments.content.encode("utf-8")).hexdigest()
        self._store.append(
            SinkRecord(
                destination=canonical_destination,
                content_digest=content_digest,
                content_bytes=content_bytes,
                principal_subject_id=authorization.principal_subject_id,
                call_id=authorization.call_id,
            )
        )
        return SinkWriteResult(
            destination=canonical_destination,
            content_digest=content_digest,
            content_bytes=content_bytes,
        )

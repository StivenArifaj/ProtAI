"""Synthetic mock files adapter (blueprint sections 14.1, 14.3).

A fixed synthetic workspace addressed only by resource IDs — the adapter never accepts a
host path, so there is no host-filesystem surface. Ownership is assigned to synthetic
test users and re-checked at execution time.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import Field

from ai_security.data_security.classification import DataClass
from ai_security.identity.models import Principal

from .base import (
    STABLE_ID_PATTERN,
    ExecutionAuthorization,
    SideEffectClass,
    ToolArguments,
    ToolExecutionError,
    ToolResult,
    verify_execution_authorization,
)
from .registry import ToolRegistration

TOOL_SEARCH = "mock_files.search"
TOOL_READ = "mock_files.read"
ADAPTER_VERSION = "mock-files-v1"
MAX_RESULT_BYTES = 16_384


@dataclass(frozen=True)
class FileFixture:
    """One synthetic workspace file owned by a synthetic user."""

    file_id: str
    owner_subject_id: str
    name: str
    content: str


DEFAULT_FILES: tuple[FileFixture, ...] = (
    FileFixture(
        file_id="file-1",
        owner_subject_id="dev-user",
        name="project-notes.txt",
        content="Mock project notes: gateway design, registry rules, and test plan.",
    ),
    FileFixture(
        file_id="file-2",
        owner_subject_id="dev-user",
        name="meeting-agenda.txt",
        content="Agenda: policy review, no-execution proofs, and documentation.",
    ),
    FileFixture(
        file_id="file-3",
        owner_subject_id="other-user",
        name="other-user-notes.txt",
        content="Synthetic file owned by a different test user.",
    ),
)


class FileSearchArguments(ToolArguments):
    query: str = Field(min_length=1, max_length=256)
    limit: int = Field(default=10, ge=1, le=50, strict=True)


class FileReadArguments(ToolArguments):
    file_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)


class FileSummary(ToolResult):
    file_id: str
    name: str
    size_bytes: int


class FileSearchResult(ToolResult):
    files: tuple[FileSummary, ...]


class FileReadResult(ToolResult):
    file_id: str
    name: str
    content: str


class MockFilesAdapter:
    """Read-only mock workspace search/read addressed by resource ID."""

    adapter_version = ADAPTER_VERSION

    def __init__(self, files: tuple[FileFixture, ...] = DEFAULT_FILES) -> None:
        self._files = {item.file_id: item for item in files}

    def registrations(self) -> tuple[ToolRegistration, ...]:
        return (
            ToolRegistration(
                tool_id=TOOL_SEARCH,
                action_id="search",
                side_effect_class=SideEffectClass.read_only,
                data_class=DataClass.internal,
                argument_schema=FileSearchArguments,
                result_schema=FileSearchResult,
                resource_id_arguments=(),
                resource_prefixes=(),
                destination_argument=None,
                destinations=(),
                timeout_ms=1_000,
                max_concurrent_invocations=8,
                max_result_bytes=MAX_RESULT_BYTES,
                approval_required=False,
                required_approver_rule=None,
                adapter_version=ADAPTER_VERSION,
            ),
            ToolRegistration(
                tool_id=TOOL_READ,
                action_id="read",
                side_effect_class=SideEffectClass.read_only,
                data_class=DataClass.internal,
                argument_schema=FileReadArguments,
                result_schema=FileReadResult,
                resource_id_arguments=("file_id",),
                resource_prefixes=("file-",),
                destination_argument=None,
                destinations=(),
                timeout_ms=1_000,
                max_concurrent_invocations=8,
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
        if tool_id != TOOL_READ or action_id != "read" or not resource_ids:
            return False
        return all(
            (item := self._files.get(resource_id)) is not None
            and item.owner_subject_id == principal.subject_id
            for resource_id in resource_ids
        )

    async def execute(
        self,
        *,
        tool_id: str,
        action_id: str,
        arguments: ToolArguments,
        authorization: ExecutionAuthorization,
    ) -> ToolResult:
        if tool_id == TOOL_SEARCH and action_id == "search":
            if not isinstance(arguments, FileSearchArguments):
                raise ToolExecutionError("search arguments were not validated by the gateway")
            verify_execution_authorization(
                authorization,
                tool_id=tool_id,
                action_id=action_id,
                arguments=arguments,
                resource_ids=(),
                destination=None,
            )
            return self._search(arguments, principal_subject_id=authorization.principal_subject_id)
        if tool_id == TOOL_READ and action_id == "read":
            if not isinstance(arguments, FileReadArguments):
                raise ToolExecutionError("read arguments were not validated by the gateway")
            verify_execution_authorization(
                authorization,
                tool_id=tool_id,
                action_id=action_id,
                arguments=arguments,
                resource_ids=(arguments.file_id,),
                destination=None,
            )
            item = self._files.get(arguments.file_id)
            if item is None or item.owner_subject_id != authorization.principal_subject_id:
                raise ToolExecutionError("resource is not accessible to this principal")
            return FileReadResult(
                file_id=item.file_id,
                name=item.name,
                content=item.content,
            )
        raise ToolExecutionError(f"unregistered mock files action {action_id!r}")

    def _search(
        self, arguments: FileSearchArguments, *, principal_subject_id: str
    ) -> FileSearchResult:
        query = arguments.query.casefold()
        matches = [
            FileSummary(
                file_id=item.file_id,
                name=item.name,
                size_bytes=len(item.content.encode("utf-8")),
            )
            for item in sorted(self._files.values(), key=lambda entry: entry.file_id)
            if item.owner_subject_id == principal_subject_id
            and (query in item.name.casefold() or query in item.content.casefold())
        ]
        return FileSearchResult(files=tuple(matches[: arguments.limit]))

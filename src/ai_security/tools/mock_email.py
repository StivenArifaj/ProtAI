"""Synthetic mock email adapter (blueprint section 14.1).

No live inbox, no real addresses, no network. The fixture dataset is assigned to
synthetic test users; search only returns the verified principal's own messages, and
read re-checks ownership in addition to the gateway's pre-decision scope check
(least-privilege connector behavior, §12.3).
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

TOOL_SEARCH = "mock_email.search"
TOOL_READ = "mock_email.read"
ADAPTER_VERSION = "mock-email-v1"
MAX_RESULT_BYTES = 16_384


@dataclass(frozen=True)
class EmailFixture:
    """One synthetic message assigned to a synthetic user mailbox."""

    email_id: str
    owner_subject_id: str
    sender: str
    subject: str
    folder: str
    body: str


DEFAULT_EMAILS: tuple[EmailFixture, ...] = (
    EmailFixture(
        email_id="email-1",
        owner_subject_id="dev-user",
        sender="finance@internal.example",
        subject="Q3 budget review draft",
        folder="inbox",
        body="Please review the Q3 budget draft before the planning meeting.",
    ),
    EmailFixture(
        email_id="email-2",
        owner_subject_id="dev-user",
        sender="ops@internal.example",
        subject="Deployment checklist",
        folder="inbox",
        body="The deployment checklist is ready for the mock environment.",
    ),
    EmailFixture(
        email_id="email-3",
        owner_subject_id="other-user",
        sender="someone@elsewhere.example",
        subject="Private planning notes",
        folder="inbox",
        body="Synthetic content owned by a different test user.",
    ),
)


class EmailSearchArguments(ToolArguments):
    query: str = Field(min_length=1, max_length=256)
    limit: int = Field(default=10, ge=1, le=50, strict=True)


class EmailReadArguments(ToolArguments):
    email_id: str = Field(min_length=1, max_length=128, pattern=STABLE_ID_PATTERN)


class EmailSummary(ToolResult):
    email_id: str
    sender: str
    subject: str
    folder: str


class EmailSearchResult(ToolResult):
    emails: tuple[EmailSummary, ...]


class EmailReadResult(ToolResult):
    email_id: str
    sender: str
    subject: str
    folder: str
    body: str


class MockEmailAdapter:
    """Read-only mock email search/read over a fixed synthetic dataset."""

    adapter_version = ADAPTER_VERSION

    def __init__(self, emails: tuple[EmailFixture, ...] = DEFAULT_EMAILS) -> None:
        self._emails = {email.email_id: email for email in emails}

    def registrations(self) -> tuple[ToolRegistration, ...]:
        return (
            ToolRegistration(
                tool_id=TOOL_SEARCH,
                action_id="search",
                side_effect_class=SideEffectClass.read_only,
                data_class=DataClass.internal,
                argument_schema=EmailSearchArguments,
                result_schema=EmailSearchResult,
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
                argument_schema=EmailReadArguments,
                result_schema=EmailReadResult,
                resource_id_arguments=("email_id",),
                resource_prefixes=("email-",),
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
        if tool_id != TOOL_READ or action_id != "read":
            return False
        if not resource_ids:
            return False
        return all(
            (email := self._emails.get(resource_id)) is not None
            and email.owner_subject_id == principal.subject_id
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
            if not isinstance(arguments, EmailSearchArguments):
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
            if not isinstance(arguments, EmailReadArguments):
                raise ToolExecutionError("read arguments were not validated by the gateway")
            verify_execution_authorization(
                authorization,
                tool_id=tool_id,
                action_id=action_id,
                arguments=arguments,
                resource_ids=(arguments.email_id,),
                destination=None,
            )
            email = self._emails.get(arguments.email_id)
            if email is None or email.owner_subject_id != authorization.principal_subject_id:
                raise ToolExecutionError("resource is not accessible to this principal")
            return EmailReadResult(
                email_id=email.email_id,
                sender=email.sender,
                subject=email.subject,
                folder=email.folder,
                body=email.body,
            )
        raise ToolExecutionError(f"unregistered mock email action {action_id!r}")

    def _search(
        self, arguments: EmailSearchArguments, *, principal_subject_id: str
    ) -> EmailSearchResult:
        query = arguments.query.casefold()
        matches = [
            EmailSummary(
                email_id=email.email_id,
                sender=email.sender,
                subject=email.subject,
                folder=email.folder,
            )
            for email in sorted(self._emails.values(), key=lambda item: item.email_id)
            if email.owner_subject_id == principal_subject_id
            and query in f"{email.subject}\n{email.body}".casefold()
        ]
        return EmailSearchResult(emails=tuple(matches[: arguments.limit]))

"""Mock adapter tests: scoping, authorization guard, and no-side-effect denials (§14.1)."""

from __future__ import annotations

import asyncio
import hashlib

import pytest
from _tool_auth import issue_authorization

from ai_security.identity.models import Principal
from ai_security.tools.base import (
    ExecutionAuthorization,
    ExecutionAuthorizationError,
    ToolExecutionError,
    UngatedExecutionError,
)
from ai_security.tools.mock_email import (
    EmailReadArguments,
    EmailSearchArguments,
    MockEmailAdapter,
)
from ai_security.tools.mock_external_sink import (
    DESTINATION,
    MockExternalSinkAdapter,
    SinkStore,
    SinkWriteArguments,
)
from ai_security.tools.mock_files import (
    FileReadArguments,
    FileSearchArguments,
    MockFilesAdapter,
)
from ai_security.tools.mock_text import MockTextAdapter, SummarizeArguments


def principal(subject_id: str = "dev-user") -> Principal:
    return Principal(
        subject_id=subject_id,
        auth_method="test",
        issuer="test",
        permissions_context_ref="test-ref",
    )


def test_execution_authorization_cannot_be_constructed_directly() -> None:
    with pytest.raises(UngatedExecutionError):
        ExecutionAuthorization(
            call_id="call-1",
            request_id="req-1",
            principal_subject_id="dev-user",
            tool_id="text.summarize",
            action_id="summarize",
            resource_ids=(),
            destination=None,
            policy_hash="a" * 64,
            action_digest="b" * 64,
        )


# -- mock email -----------------------------------------------------------------------


def test_email_search_only_returns_the_authorized_principals_mail() -> None:
    adapter = MockEmailAdapter()
    arguments = EmailSearchArguments(query="budget")
    authorization = issue_authorization(
        tool_id="mock_email.search", action_id="search", arguments=arguments
    )
    result = asyncio.run(
        adapter.execute(
            tool_id="mock_email.search",
            action_id="search",
            arguments=arguments,
            authorization=authorization,
        )
    )
    assert [email.email_id for email in result.emails] == ["email-1"]


def test_email_search_does_not_leak_another_users_messages() -> None:
    adapter = MockEmailAdapter()
    arguments = EmailSearchArguments(query="synthetic")
    authorization = issue_authorization(
        tool_id="mock_email.search", action_id="search", arguments=arguments
    )
    result = asyncio.run(
        adapter.execute(
            tool_id="mock_email.search",
            action_id="search",
            arguments=arguments,
            authorization=authorization,
        )
    )
    assert result.emails == ()


def test_email_read_returns_owned_message() -> None:
    adapter = MockEmailAdapter()
    arguments = EmailReadArguments(email_id="email-1")
    authorization = issue_authorization(
        tool_id="mock_email.read",
        action_id="read",
        arguments=arguments,
        resource_ids=("email-1",),
    )
    result = asyncio.run(
        adapter.execute(
            tool_id="mock_email.read",
            action_id="read",
            arguments=arguments,
            authorization=authorization,
        )
    )
    assert result.email_id == "email-1"
    assert "Q3 budget" in result.body


def test_email_read_scope_check_denies_cross_user_and_unknown_resources() -> None:
    adapter = MockEmailAdapter()
    assert adapter.check_resource_access(
        principal=principal(),
        tool_id="mock_email.read",
        action_id="read",
        resource_ids=("email-1",),
    )
    assert not adapter.check_resource_access(
        principal=principal("other-user"),
        tool_id="mock_email.read",
        action_id="read",
        resource_ids=("email-1",),
    )
    assert not adapter.check_resource_access(
        principal=principal(),
        tool_id="mock_email.read",
        action_id="read",
        resource_ids=("email-404",),
    )
    assert not adapter.check_resource_access(
        principal=principal(),
        tool_id="mock_email.read",
        action_id="read",
        resource_ids=(),
    )


def test_email_read_execution_rechecks_ownership() -> None:
    adapter = MockEmailAdapter()
    arguments = EmailReadArguments(email_id="email-1")
    authorization = issue_authorization(
        tool_id="mock_email.read",
        action_id="read",
        arguments=arguments,
        resource_ids=("email-1",),
        principal_subject_id="other-user",
    )
    with pytest.raises(ToolExecutionError, match="not accessible"):
        asyncio.run(
            adapter.execute(
                tool_id="mock_email.read",
                action_id="read",
                arguments=arguments,
                authorization=authorization,
            )
        )


def test_changed_arguments_fail_the_action_digest_before_execution() -> None:
    adapter = MockEmailAdapter()
    authorized = EmailReadArguments(email_id="email-1")
    authorization = issue_authorization(
        tool_id="mock_email.read",
        action_id="read",
        arguments=authorized,
        resource_ids=("email-1",),
    )
    tampered = EmailReadArguments(email_id="email-2")
    with pytest.raises(ExecutionAuthorizationError):
        asyncio.run(
            adapter.execute(
                tool_id="mock_email.read",
                action_id="read",
                arguments=tampered,
                authorization=authorization,
            )
        )


def test_authorization_for_a_different_tool_is_rejected() -> None:
    adapter = MockEmailAdapter()
    arguments = EmailSearchArguments(query="budget")
    authorization = issue_authorization(
        tool_id="text.summarize", action_id="summarize", arguments=SummarizeArguments(text="x")
    )
    with pytest.raises(ExecutionAuthorizationError):
        asyncio.run(
            adapter.execute(
                tool_id="mock_email.search",
                action_id="search",
                arguments=arguments,
                authorization=authorization,
            )
        )


# -- mock files -----------------------------------------------------------------------


def test_file_search_scopes_results_to_the_principal() -> None:
    adapter = MockFilesAdapter()
    arguments = FileSearchArguments(query="notes")
    authorization = issue_authorization(
        tool_id="mock_files.search", action_id="search", arguments=arguments
    )
    result = asyncio.run(
        adapter.execute(
            tool_id="mock_files.search",
            action_id="search",
            arguments=arguments,
            authorization=authorization,
        )
    )
    assert [item.file_id for item in result.files] == ["file-1"]


def test_file_read_owner_and_cross_user_scope() -> None:
    adapter = MockFilesAdapter()
    arguments = FileReadArguments(file_id="file-1")
    authorization = issue_authorization(
        tool_id="mock_files.read",
        action_id="read",
        arguments=arguments,
        resource_ids=("file-1",),
    )
    result = asyncio.run(
        adapter.execute(
            tool_id="mock_files.read",
            action_id="read",
            arguments=arguments,
            authorization=authorization,
        )
    )
    assert result.file_id == "file-1"
    assert not adapter.check_resource_access(
        principal=principal("other-user"),
        tool_id="mock_files.read",
        action_id="read",
        resource_ids=("file-1",),
    )


# -- external sink --------------------------------------------------------------------


def test_sink_authorized_write_records_exactly_one_digest() -> None:
    store = SinkStore()
    adapter = MockExternalSinkAdapter(store)
    arguments = SinkWriteArguments(destination=DESTINATION, content="hello world")
    authorization = issue_authorization(
        tool_id="mock_external_sink.write",
        action_id="write",
        arguments=arguments,
        destination=DESTINATION,
    )
    result = asyncio.run(
        adapter.execute(
            tool_id="mock_external_sink.write",
            action_id="write",
            arguments=arguments,
            authorization=authorization,
        )
    )
    assert result.content_digest == hashlib.sha256(b"hello world").hexdigest()
    records = store.records()
    assert len(records) == 1
    assert records[0].principal_subject_id == "dev-user"
    assert records[0].content_digest == result.content_digest
    assert records[0].destination == DESTINATION


def test_sink_tampered_content_leaves_the_store_unchanged() -> None:
    store = SinkStore()
    adapter = MockExternalSinkAdapter(store)
    authorized = SinkWriteArguments(destination=DESTINATION, content="hello")
    authorization = issue_authorization(
        tool_id="mock_external_sink.write",
        action_id="write",
        arguments=authorized,
        destination=DESTINATION,
    )
    tampered = SinkWriteArguments(destination=DESTINATION, content="evil")
    with pytest.raises(ExecutionAuthorizationError):
        asyncio.run(
            adapter.execute(
                tool_id="mock_external_sink.write",
                action_id="write",
                arguments=tampered,
                authorization=authorization,
            )
        )
    assert store.records() == ()


def test_sink_destination_outside_capability_leaves_the_store_unchanged() -> None:
    store = SinkStore()
    adapter = MockExternalSinkAdapter(store)
    evil_destination = "https://evil.example/collect"
    arguments = SinkWriteArguments(destination=evil_destination, content="hello")
    authorization = issue_authorization(
        tool_id="mock_external_sink.write",
        action_id="write",
        arguments=arguments,
        destination=evil_destination,
    )
    with pytest.raises(ToolExecutionError, match="capability"):
        asyncio.run(
            adapter.execute(
                tool_id="mock_external_sink.write",
                action_id="write",
                arguments=arguments,
                authorization=authorization,
            )
        )
    assert store.records() == ()


# -- text summarize -------------------------------------------------------------------


def test_summarize_is_deterministic_and_normalizes_whitespace() -> None:
    adapter = MockTextAdapter()
    text = "  hello   world  "
    arguments = SummarizeArguments(text=text, max_chars=100)
    authorization = issue_authorization(
        tool_id="text.summarize", action_id="summarize", arguments=arguments
    )
    first = asyncio.run(
        adapter.execute(
            tool_id="text.summarize",
            action_id="summarize",
            arguments=arguments,
            authorization=authorization,
        )
    )
    second = asyncio.run(
        adapter.execute(
            tool_id="text.summarize",
            action_id="summarize",
            arguments=arguments,
            authorization=authorization,
        )
    )
    assert first == second
    assert first.summary == "hello world"
    assert first.original_chars == len(text)
    assert first.truncated is False


def test_summarize_truncates_to_the_requested_bound() -> None:
    adapter = MockTextAdapter()
    arguments = SummarizeArguments(text="abcdefghij" * 10, max_chars=20)
    authorization = issue_authorization(
        tool_id="text.summarize", action_id="summarize", arguments=arguments
    )
    result = asyncio.run(
        adapter.execute(
            tool_id="text.summarize",
            action_id="summarize",
            arguments=arguments,
            authorization=authorization,
        )
    )
    assert len(result.summary) == 20
    assert result.truncated is True

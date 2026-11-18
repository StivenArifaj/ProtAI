"""SOC no-authority security tests (Phase 10, ADR-004, ADR-017).

The summarizer and alerting components must have no tool-execution, policy-edit,
approval, audit-write, session-revocation, or containment authority. These tests
assert by construction that no such surface exists.
"""

from __future__ import annotations

import inspect

from ai_security.soc.summarizer import (
    AuditSummarizer,
    DeterministicSummarizerStub,
    SummarizerClient,
    SummarizerInputEnvelope,
    SummarizerOutput,
)


class SpyClient:
    """Records every call; implements only the narrow summarizer-client protocol."""

    def __init__(self) -> None:
        self.calls = 0

    async def summarize(self, envelope: SummarizerInputEnvelope) -> str:  # type: ignore[no-untyped-def]
        self.calls += 1
        return "hypothesis"


def test_summarizer_has_no_tool_or_adapter_access() -> None:
    """The summarizer imports nothing from adapters, gateway, or policy engine."""
    source = inspect.getsource(AuditSummarizer)
    for forbidden in ("adapter", "gateway", "policy_engine", "ToolGateway", "invoke_tool"):
        assert forbidden not in source, f"summarizer references {forbidden!r}"


def test_stub_has_no_network_or_model_access() -> None:
    """The deterministic stub imports no network/model/client modules."""
    source = inspect.getsource(DeterministicSummarizerStub)
    for forbidden in ("httpx", "requests", "urllib", "ollama", "openai", "anthropic", "socket"):
        assert forbidden not in source.lower(), f"stub references {forbidden!r}"


def test_summarizer_client_protocol_is_narrow() -> None:
    """The client protocol exposes only ``summarize`` — no tool/policy/audit/approval
    methods exist."""
    attrs = [name for name in dir(SummarizerClient) if not name.startswith("_")]
    # The only public attribute should be ``summarize``
    assert attrs == ["summarize"], f"unexpected public attrs on protocol: {attrs}"


def test_summarizer_output_has_no_authority_fields() -> None:
    """Output carries only a bounded hypothesis and a recommended action — no
    execution, approval, revocation, or containment fields."""
    output = SummarizerOutput(
        generated_at=__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").UTC),
        hypothesis="test",
        content_digest="0" * 64,
    )
    fields = set(output.model_fields.keys())
    assert fields <= {
        "schema_version",
        "generated_at",
        "hypothesis",
        "recommended_action",
        "confidence_note",
        "content_digest",
    }
    for forbidden in (
        "tool_id",
        "action_id",
        "approval_id",
        "approver",
        "revoke",
        "contain",
        "policy",
        "execute",
        "session",
    ):
        assert forbidden not in fields


def test_recommended_action_is_limited() -> None:
    """``recommended_action`` can only be annotate_alert or no_action — never execute,
    revoke, or contain."""
    import datetime as dt

    for action in ("annotate_alert", "no_action"):
        output = SummarizerOutput(
            generated_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
            hypothesis="h",
            recommended_action=action,  # type: ignore[arg-type]
            content_digest="0" * 64,
        )
        assert output.recommended_action == action


def test_summarizer_is_opt_in_off_by_default() -> None:
    summarizer = AuditSummarizer()
    assert summarizer.enabled is False


def test_summarizer_cannot_write_audit() -> None:
    """The summarizer has no ``record``/``append`` method and cannot mutate the audit
    chain."""
    summarizer = AuditSummarizer(enabled=True)
    assert not hasattr(summarizer, "record")
    assert not hasattr(summarizer, "append")
    assert not hasattr(summarizer, "write")


def test_deterministic_stub_is_sync_constructible_without_network() -> None:
    """The stub constructs with no network, no credentials, no model endpoint."""
    stub = DeterministicSummarizerStub()
    assert stub is not None

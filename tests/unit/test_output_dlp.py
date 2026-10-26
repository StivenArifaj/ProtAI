"""Deterministic output-DLP and destination-aware egress policy (blueprint section 15).

These tests cover the strict configuration contract, detector behavior, destination trust
bounds, redaction/digest preservation, and fail-closed inspection limits. Gateway
integration is covered separately; here the service is exercised directly.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_security.data_security.classification import DataClass
from ai_security.data_security.dlp import (
    DestinationTrust,
    DestinationTrustLabel,
    DlpCategory,
    DlpLimits,
    DlpOutcome,
    DlpPhase,
    DlpRelease,
    EgressReason,
    EgressScope,
    LoadedOutputDlpConfig,
    OutputDefenseService,
    OutputDlpConfig,
    OutputDlpConfigError,
    SensitivePattern,
    load_output_dlp_config,
)
from ai_security.security.canonical_json import canonical_json_bytes

CONFIG = "config/output_dlp.yaml"
SINK = "https://mock-sink.invalid/collect"
CANARY = "CANARY_SECRET_UNIT_TEST_1234"
EMAIL = "finance@internal.example"


def service() -> OutputDefenseService:
    return OutputDefenseService(load_output_dlp_config(CONFIG))


def write_config(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


BASE_CONFIG = f"""
schema_version: 1
version: "test-1"
limits:
  max_scan_bytes: 65536
  max_findings: 8
  max_matches_per_pattern: 4
patterns:
  - code: canary
    category: SYNTHETIC_CANARY
    pattern: "\\\\bCANARY_SECRET_[A-Z0-9_]+\\\\b"
    data_class: RESTRICTED
    egress: BLOCK
    release: BLOCK
  - code: email
    category: PII_EMAIL
    pattern: "\\\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Za-z]{{2,}}\\\\b"
    data_class: CONFIDENTIAL
    egress: CLASSIFY
    release: REDACT
destinations:
  - name: sink
    destination: "{SINK}"
    trust: PUBLIC
    max_data_class: PUBLIC
"""


def test_repository_configuration_loads_and_covers_the_registered_sink() -> None:
    loaded = load_output_dlp_config(CONFIG)
    defense = OutputDefenseService(loaded)
    assert loaded.config.version == "1.0.1"
    assert loaded.sha256 == hashlib.sha256(Path(CONFIG).read_bytes()).hexdigest()
    assert {pattern.code for pattern in loaded.config.patterns} == {
        "synthetic_canary",
        "private_key",
        "api_key",
        "credential_assignment",
        "email_address",
    }
    defense.validate_registered_destinations({SINK})


def test_trust_map_must_exactly_match_registered_external_destinations() -> None:
    defense = service()
    with pytest.raises(OutputDlpConfigError, match="no output-DLP trust entry"):
        defense.validate_registered_destinations({"https://other.invalid/collect"})
    with pytest.raises(OutputDlpConfigError, match="no registered external destination"):
        defense.validate_registered_destinations(set())


def test_loader_refuses_duplicate_keys_unknown_fields_and_bad_versions(tmp_path: Path) -> None:
    duplicate = write_config(
        tmp_path / "duplicate.yaml",
        BASE_CONFIG.replace('version: "test-1"', 'version: "test-1"\nversion: "test-2"'),
    )
    with pytest.raises(OutputDlpConfigError, match="duplicate"):
        load_output_dlp_config(duplicate)

    unknown = write_config(tmp_path / "unknown.yaml", BASE_CONFIG + "\nunexpected: true\n")
    with pytest.raises(OutputDlpConfigError, match="strict validation"):
        load_output_dlp_config(unknown)

    bad_version = write_config(
        tmp_path / "version.yaml", BASE_CONFIG.replace('version: "test-1"', "version: bad/version")
    )
    with pytest.raises(OutputDlpConfigError, match="strict validation"):
        load_output_dlp_config(bad_version)


def test_loader_refuses_non_utf8_and_missing_files(tmp_path: Path) -> None:
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(OutputDlpConfigError, match="UTF-8"):
        load_output_dlp_config(binary)
    with pytest.raises(OutputDlpConfigError, match="cannot be read"):
        load_output_dlp_config(tmp_path / "missing.yaml")


def test_pattern_rejects_empty_matches_markers_and_control_characters() -> None:
    def make(pattern: str) -> SensitivePattern:
        return SensitivePattern(
            code="test",
            category=DlpCategory.synthetic_canary,
            pattern=pattern,
            data_class=DataClass.restricted,
            egress=EgressScope.block,
            release=DlpRelease.block,
        )

    with pytest.raises(ValidationError, match="empty string"):
        make(".*")
    with pytest.raises(ValidationError, match="redaction marker"):
        make(r"\[REDACTED:[A-Z_]+\]")
    with pytest.raises(ValidationError, match="control"):
        make("a\x00b")


def test_destination_must_already_be_canonical() -> None:
    with pytest.raises(ValidationError, match="must already be canonical"):
        DestinationTrust(
            name="sink",
            destination="https://MOCK-SINK.invalid/collect",
            trust=DestinationTrustLabel.public,
            max_data_class=DataClass.public,
        )
    with pytest.raises(ValidationError):
        DestinationTrust(
            name="sink",
            destination="http://insecure.invalid/collect",
            trust=DestinationTrustLabel.public,
            max_data_class=DataClass.public,
        )


def test_canary_egress_is_blocked_and_report_contains_no_match_text() -> None:
    report = service().inspect_egress(
        data={"destination": SINK, "content": f"prefix {CANARY} suffix"},
        declared_data_class=DataClass.public,
        destination=SINK,
        require_destination=True,
    )
    assert report.phase is DlpPhase.egress
    assert report.outcome is DlpOutcome.block
    assert report.egress_reason is EgressReason.category_blocked
    assert report.max_data_class is DataClass.restricted
    assert report.finding_codes == ("synthetic_canary",)
    assert (
        report.content_digest
        == hashlib.sha256(
            canonical_json_bytes({"destination": SINK, "content": f"prefix {CANARY} suffix"})
        ).hexdigest()
    )
    serialized = json.dumps(
        {
            "findings": [
                {"code": finding.code, "category": finding.category, "count": finding.count}
                for finding in report.findings
            ],
            "digest": report.content_digest,
        }
    )
    assert CANARY not in serialized
    assert CANARY not in repr(report)


def test_destination_aware_class_blocks_classified_content() -> None:
    report = service().inspect_egress(
        data={"destination": SINK, "content": f"contact {EMAIL}"},
        declared_data_class=DataClass.public,
        destination=SINK,
        require_destination=True,
    )
    assert report.outcome is DlpOutcome.block
    assert report.egress_reason is EgressReason.class_above_destination
    assert report.max_data_class is DataClass.confidential
    assert report.destination_trust is not None
    assert report.destination_trust.max_data_class is DataClass.public


def test_registry_data_class_is_a_floor_not_a_ceiling() -> None:
    report = service().inspect_egress(
        data={"destination": SINK, "content": "benign"},
        declared_data_class=DataClass.confidential,
        destination=SINK,
        require_destination=True,
    )
    assert report.outcome is DlpOutcome.block
    assert report.egress_reason is EgressReason.class_above_destination
    assert report.egress_allowed is False


def test_benign_similar_strings_do_not_match() -> None:
    benign = {
        "content": (
            "CANARY_SECRET is a label, sk-short is not a key, "
            "-----BEGIN PUBLIC KEY----- is public, password is configured elsewhere, "
            "reach the team at localhost without a dot"
        )
    }
    egress = service().inspect_egress(
        data={"destination": SINK, **benign},
        declared_data_class=DataClass.public,
        destination=SINK,
        require_destination=True,
    )
    output = service().inspect_output(data=benign, declared_data_class=DataClass.public)
    assert egress.outcome is DlpOutcome.pass_
    assert egress.egress_reason is EgressReason.passed
    assert egress.findings == ()
    assert output.outcome is DlpOutcome.pass_
    assert output.findings == ()


def test_egress_without_a_destination_fails_closed() -> None:
    report = service().inspect_egress(
        data={"content": "benign"},
        declared_data_class=DataClass.public,
        destination=None,
        require_destination=True,
    )
    assert report.outcome is DlpOutcome.block
    assert report.egress_reason is EgressReason.destination_missing


def test_non_egress_action_may_not_carry_a_destination() -> None:
    report = service().inspect_egress(
        data={"content": "benign"},
        declared_data_class=DataClass.public,
        destination=SINK,
        require_destination=False,
    )
    assert report.outcome is DlpOutcome.block
    assert report.inspection_error is True


def test_response_redaction_is_span_safe_idempotent_and_digest_preserving() -> None:
    defense = service()
    payload = {"sender": EMAIL, "body": "password: synthetic-value", "safe": "keep me"}
    report = defense.inspect_output(data=payload, declared_data_class=DataClass.internal)
    assert report.outcome is DlpOutcome.redact
    assert report.finding_codes == ("credential_assignment", "email_address")
    assert report.content_digest == hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    redacted, changed = defense.redact_payload(payload, report=report)
    assert changed is True
    assert redacted == {
        "sender": "[REDACTED:PII_EMAIL]",
        "body": "[REDACTED:CREDENTIAL]",
        "safe": "keep me",
    }
    again = defense.inspect_output(data=redacted, declared_data_class=DataClass.internal)
    assert again.outcome is DlpOutcome.pass_
    second, changed_again = defense.redact_payload(redacted, report=again)
    assert changed_again is False
    assert second == redacted


def test_response_block_and_review_are_distinct_outcomes() -> None:
    defense = service()
    block = defense.inspect_output(
        data={"body": f"leaked {CANARY}"}, declared_data_class=DataClass.public
    )
    assert block.outcome is DlpOutcome.block
    assert block.max_data_class is DataClass.restricted
    assert block.response_releasable is False

    review_config = OutputDlpConfig(
        schema_version=1,
        version="review-test",
        limits={"max_scan_bytes": 1024, "max_findings": 4, "max_matches_per_pattern": 2},
        patterns=(
            SensitivePattern(
                code="review_marker",
                category=DlpCategory.credential,
                pattern=r"REVIEWME",
                data_class=DataClass.confidential,
                egress=EgressScope.classify,
                release=DlpRelease.review,
            ),
        ),
        destinations=(),
    )
    review_defense = OutputDefenseService(
        LoadedOutputDlpConfig(config=review_config, sha256="a" * 64)
    )
    review = review_defense.inspect_output(
        data={"body": "REVIEWME"}, declared_data_class=DataClass.public
    )
    assert review.outcome is DlpOutcome.review
    assert review.response_releasable is False


def test_oversized_content_fails_closed_for_both_phases() -> None:
    defense = service()
    oversized = "x" * (defense.config.limits.max_scan_bytes + 1)
    output = defense.inspect_output(data={"body": oversized}, declared_data_class=DataClass.public)
    assert output.outcome is DlpOutcome.block
    assert output.inspection_error is True
    assert output.max_data_class is DataClass.restricted
    assert output.response_releasable is False

    egress = defense.inspect_egress(
        data={"destination": SINK, "content": oversized},
        declared_data_class=DataClass.public,
        destination=SINK,
        require_destination=True,
    )
    assert egress.outcome is DlpOutcome.block
    assert egress.inspection_error is True
    assert egress.egress_allowed is False
    assert egress.egress_reason is EgressReason.category_blocked


def test_release_failure_and_released_digest_helpers_are_guarded() -> None:
    defense = service()
    report = defense.inspect_output(data={"sender": EMAIL}, declared_data_class=DataClass.internal)
    failed = defense.release_failure(report)
    assert failed.outcome is DlpOutcome.block
    assert failed.inspection_error is True
    passing = defense.inspect_output(data={"note": "benign"}, declared_data_class=DataClass.public)
    assert passing.outcome is DlpOutcome.pass_
    with pytest.raises(ValueError):
        defense.released(passing, released_digest="a" * 64)
    with pytest.raises(ValueError):
        defense.release_failure(
            defense.inspect_egress(
                data={"content": "benign"},
                declared_data_class=DataClass.public,
                destination=None,
                require_destination=True,
            )
        )


def test_overlapping_matches_are_merged_without_releasing_a_tail() -> None:
    config = OutputDlpConfig(
        schema_version=1,
        version="overlap-test",
        limits=DlpLimits(max_scan_bytes=1024, max_findings=4, max_matches_per_pattern=4),
        patterns=(
            SensitivePattern(
                code="left",
                category=DlpCategory.credential,
                pattern=r"ALPHA_[A-Z]+",
                data_class=DataClass.confidential,
                egress=EgressScope.classify,
                release=DlpRelease.redact,
            ),
            SensitivePattern(
                code="right",
                category=DlpCategory.api_key,
                pattern=r"[A-Z]+_OMEGA_END",
                data_class=DataClass.restricted,
                egress=EgressScope.classify,
                release=DlpRelease.redact,
            ),
        ),
        destinations=(),
    )
    defense = OutputDefenseService(LoadedOutputDlpConfig(config=config, sha256="c" * 64))
    payload = {"body": "prefix ALPHA_BETA_OMEGA_END suffix"}
    report = defense.inspect_output(data=payload, declared_data_class=DataClass.public)
    assert report.outcome is DlpOutcome.redact
    assert report.max_data_class is DataClass.restricted
    redacted, changed = defense.redact_payload(payload, report=report)
    assert changed is True
    # The union of both overlapping matches is replaced; no tail of the longer match
    # survives. The higher-severity category labels the merged span.
    assert redacted == {"body": "prefix [REDACTED:API_KEY] suffix"}
    assert (
        defense.inspect_output(data=redacted, declared_data_class=DataClass.public).outcome
        is DlpOutcome.pass_
    )


def test_finding_cap_never_skips_an_unscanned_blocking_pattern() -> None:
    """A saturated finding report must fail closed, not return a partial verdict.

    The first pattern matches immediately and exhausts ``max_findings``. The second
    pattern is never evaluated under a naive loop, so a later BLOCK category could be
    missed. Both phases must report a failed inspection instead.
    """
    config = OutputDlpConfig(
        schema_version=1,
        version="finding-cap-test",
        limits=DlpLimits(max_scan_bytes=1024, max_findings=1, max_matches_per_pattern=4),
        patterns=(
            SensitivePattern(
                code="first",
                category=DlpCategory.pii_email,
                pattern=r"first@example\.com",
                data_class=DataClass.internal,
                egress=EgressScope.classify,
                release=DlpRelease.redact,
            ),
            SensitivePattern(
                code="second",
                category=DlpCategory.synthetic_canary,
                pattern=r"CANARY_SECRET_[A-Z0-9_]{4,}",
                data_class=DataClass.restricted,
                egress=EgressScope.block,
                release=DlpRelease.block,
            ),
        ),
        destinations=(),
    )
    defense = OutputDefenseService(LoadedOutputDlpConfig(config=config, sha256="e" * 64))
    payload = {"body": "first@example.com CANARY_SECRET_REGRESSION"}

    output = defense.inspect_output(data=payload, declared_data_class=DataClass.public)
    assert output.outcome is DlpOutcome.block
    assert output.inspection_error is True
    assert output.findings == ()
    assert output.max_data_class is DataClass.restricted

    egress = defense.inspect_egress(
        data=payload,
        declared_data_class=DataClass.public,
        destination=None,
        require_destination=False,
    )
    assert egress.outcome is DlpOutcome.block
    assert egress.inspection_error is True
    assert egress.findings == ()


def test_credential_redaction_covers_a_multi_word_value() -> None:
    """A passphrase must not leave its tail after the first whitespace token."""
    defense = service()
    payload = {
        "body": "password: correct horse battery staple",
        "safe": "keep me",
    }
    report = defense.inspect_output(data=payload, declared_data_class=DataClass.public)
    assert report.outcome is DlpOutcome.redact
    assert report.finding_codes == ("credential_assignment",)

    redacted, changed = defense.redact_payload(payload, report=report)
    assert changed is True
    assert redacted == {"body": "[REDACTED:CREDENTIAL]", "safe": "keep me"}
    again = defense.inspect_output(data=redacted, declared_data_class=DataClass.public)
    assert again.outcome is DlpOutcome.pass_

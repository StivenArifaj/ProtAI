"""Safe YAML loading for policy documents (blueprint sections 10.4, 10.6; ADR-007).

The only sanctioned YAML entry point is ``yaml.safe_load``: standard tags only, no
Python object construction. Additional fail-closed rules beyond the loader itself:

- duplicate mapping keys are rejected by first inspecting the composed node tree
  (``yaml.compose`` constructs no Python objects); ``yaml.safe_load`` alone would
  silently keep the last duplicate — a policy-weakening footgun;
- the document is decoded as strict UTF-8 and validated into its strict Pydantic model;
- a missing, unreadable, malformed, or invalid file raises ``PolicyConfigError`` —
  never a silent pass or a partially applied policy;
- the SHA-256 of the exact file bytes is returned alongside the document, so the loaded
  policy version/hash can be exposed in health metadata and audit events (§10.6).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, ValidationError

from ai_security.security.safe_yaml import SafeYamlError, parse_unique_yaml

from .models import PoliciesDocument, PolicyBundle, RiskThresholdsDocument


class PolicyConfigError(RuntimeError):
    """A policy document is missing, malformed, or invalid (fail closed)."""


def _load_yaml_text(text: str, path: Path) -> object:
    """Parse YAML text with duplicate-key rejection, then ``yaml.safe_load``."""
    try:
        return parse_unique_yaml(text)
    except SafeYamlError as exc:
        raise PolicyConfigError(f"policy file {path}: {exc}") from exc


def _load_yaml_document[ModelT: BaseModel](path: Path, model: type[ModelT]) -> tuple[ModelT, str]:
    """Load, strictly validate, and hash one YAML policy document."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PolicyConfigError(f"policy file {path} cannot be read: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyConfigError(f"policy file {path} is not valid UTF-8") from exc
    data = _load_yaml_text(text, path)
    try:
        document = model.model_validate(data)
    except ValidationError as exc:
        raise PolicyConfigError(
            f"policy file {path} failed strict validation: {exc.error_count()} error(s)"
        ) from exc
    return document, hashlib.sha256(raw).hexdigest()


def load_policies(path: str | Path) -> tuple[PoliciesDocument, str]:
    """Load ``config/policies.yaml``; returns (document, sha256 of file bytes)."""
    return _load_yaml_document(Path(path), PoliciesDocument)


def load_risk_thresholds(path: str | Path) -> tuple[RiskThresholdsDocument, str]:
    """Load ``config/risk_thresholds.yaml``; returns (document, sha256 of file bytes)."""
    return _load_yaml_document(Path(path), RiskThresholdsDocument)


def load_policy_bundle(policies_path: str | Path, thresholds_path: str | Path) -> PolicyBundle:
    """Load and validate both policy documents into one bundle."""
    policies, policies_sha256 = load_policies(policies_path)
    risk_thresholds, thresholds_sha256 = load_risk_thresholds(thresholds_path)
    return PolicyBundle(
        policies=policies,
        risk_thresholds=risk_thresholds,
        policies_sha256=policies_sha256,
        thresholds_sha256=thresholds_sha256,
    )

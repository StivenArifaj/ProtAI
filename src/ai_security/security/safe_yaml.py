"""Shared, strict YAML loading for security configuration files.

The only sanctioned entry point is ``yaml.safe_load`` (standard tags only, no Python
object construction). Duplicate mapping keys are rejected by first inspecting the
composed node tree (``yaml.compose``); ``yaml.safe_load`` alone silently keeps the last
duplicate, which is a configuration-weakening footgun. Callers wrap ``SafeYamlError`` in
their domain-specific configuration error.
"""

from __future__ import annotations

import yaml


class SafeYamlError(ValueError):
    """The document is not valid YAML or contains duplicate mapping keys."""


def _find_duplicate_key(node: yaml.Node, seen_nodes: set[int]) -> str | None:
    """Return the first duplicated mapping key below ``node``, if any (cycle-safe)."""
    if id(node) in seen_nodes:
        return None
    seen_nodes.add(id(node))
    if isinstance(node, yaml.MappingNode):
        seen_keys: set[str] = set()
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode):
                key_value = str(key_node.value)
                if key_value in seen_keys:
                    return key_value
                seen_keys.add(key_value)
            duplicate = _find_duplicate_key(value_node, seen_nodes)
            if duplicate is not None:
                return duplicate
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            duplicate = _find_duplicate_key(item, seen_nodes)
            if duplicate is not None:
                return duplicate
    return None


def parse_unique_yaml(text: str) -> object:
    """Parse YAML text, rejecting duplicate mapping keys (fail closed)."""
    try:
        node = yaml.compose(text)
    except yaml.YAMLError as exc:
        raise SafeYamlError("document is not valid YAML") from exc
    if node is not None:
        duplicate = _find_duplicate_key(node, set())
        if duplicate is not None:
            raise SafeYamlError(
                f"document contains duplicate key {duplicate!r} in a mapping "
                "(configuration documents must not repeat keys)"
            )
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SafeYamlError("document is not valid YAML") from exc

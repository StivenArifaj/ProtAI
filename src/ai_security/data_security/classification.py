"""Canonical data-classification types (blueprint section 6.1).

The ``DataClass`` enum is the single canonical definition (blueprint section 6.1).
Classification is never taken from an LLM self-assessment, a user-supplied label, or
text found inside untrusted content (section 6.1); those rules belong to the Phase 6
classification layer. This module only fixes the vocabulary.
"""

from __future__ import annotations

from enum import StrEnum


class DataClass(StrEnum):
    """Canonical data classes (blueprint section 6.1)."""

    public = "PUBLIC"
    internal = "INTERNAL"
    confidential = "CONFIDENTIAL"
    restricted = "RESTRICTED"

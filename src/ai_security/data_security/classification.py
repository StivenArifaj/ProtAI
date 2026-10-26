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


#: Sensitivity order, least to most sensitive. The tuple is the single ordering
#: authority; never compare ``DataClass`` strings or enum declaration order.
DATA_CLASS_ORDER: tuple[DataClass, ...] = (
    DataClass.public,
    DataClass.internal,
    DataClass.confidential,
    DataClass.restricted,
)


def data_class_rank(value: DataClass) -> int:
    """Return the sensitivity rank of a canonical data class (0 = least sensitive)."""
    if not isinstance(value, DataClass):
        raise TypeError("data class must be a canonical DataClass")
    return DATA_CLASS_ORDER.index(value)


def max_data_class(*values: DataClass) -> DataClass:
    """Return the most sensitive of one or more canonical data classes.

    Classification layers may only *raise* sensitivity: the registry declaration is a
    floor and a detector can never lower it (blueprint sections 6.1, 15.3).
    """
    if not values:
        raise ValueError("at least one data class is required")
    return max(values, key=data_class_rank)


__all__ = [
    "DATA_CLASS_ORDER",
    "DataClass",
    "data_class_rank",
    "max_data_class",
]

"""Canonical tool-registry domain types (blueprint section 6.1).

The ``SideEffectClass`` enum is the single canonical definition (blueprint section 6.1);
every other module imports it from here. Unknown, missing, or invalid values fail closed
everywhere they are consumed: registration fails at startup and policy evaluation
returns ``BLOCK``. There are no string aliases and no coercions.
"""

from __future__ import annotations

from enum import StrEnum


class SideEffectClass(StrEnum):
    """Canonical side-effect classes (blueprint section 6.1)."""

    read_only = "READ_ONLY"
    local_mutation = "LOCAL_MUTATION"
    external_mutation = "EXTERNAL_MUTATION"
    destructive = "DESTRUCTIVE"

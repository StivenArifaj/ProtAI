#!/usr/bin/env python3
"""Convenience entry point for the ProtAI evaluation harness.

Equivalent to ``python -m ai_security.evaluation`` with the repository defaults.
Run from the repository root (or pass ``--dataset``/``--output-dir`` explicitly).
"""

from __future__ import annotations

import sys

from ai_security.evaluation.cli import main

if __name__ == "__main__":
    sys.exit(main())

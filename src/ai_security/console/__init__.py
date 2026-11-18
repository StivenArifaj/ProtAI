"""Web console API (post-v1 dashboard).

Additive, opt-in, and authority-free. The browser authenticates here, never to the
host HMAC `/v1` surface. No endpoint can execute a tool or produce an ALLOW.
"""

from __future__ import annotations

from ai_security.console.service import ConsoleService
from ai_security.console.wiring import mount_console

__all__ = ["ConsoleService", "mount_console"]

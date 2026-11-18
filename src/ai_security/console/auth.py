"""Console authentication and RBAC (post-v1 dashboard).

The browser never sees the host HMAC key. It authenticates to ``/admin/*`` with a
console session, and every endpoint checks a permission. ``AuthProvider`` is an
interface so an OIDC/SSO adapter can replace the local provider without changing
routes or the frontend.

Security rules:
- Passwords are salted PBKDF2-HMAC-SHA256 hashes; comparisons use the project's
  project's dedicated constant-time helper (the only module allowed to use the
  low-level primitive).
- Session tokens are 256-bit CSPRNG values, stored server-side only, never in a URL.
- Write requests require a CSRF header equal to the session token.
- No token, password, or secret is ever returned by an API response.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Protocol, cast

from fastapi import Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from ai_security.security.constant_time import constant_time_bytes_equal

SESSION_COOKIE = "protai_console_session"
CSRF_HEADER = "X-Console-CSRF"
PBKDF2_ITERATIONS = 210_000
SESSION_TTL_SECONDS = 8 * 3600


class ConsoleRole(StrEnum):
    """Maps to the six actor categories in the interaction model."""

    admin = "admin"
    analyst = "analyst"
    approver = "approver"
    operator = "operator"
    developer = "developer"
    viewer = "viewer"


class Permission(StrEnum):
    audit_read = "audit:read"
    alert_read = "alert:read"
    alert_triage = "alert:triage"
    approval_read = "approval:read"
    approval_decide = "approval:decide"
    approval_revoke = "approval:revoke"
    tool_read = "tool:read"
    tool_write = "tool:write"
    policy_read = "policy:read"
    policy_write = "policy:write"
    settings_read = "settings:read"
    settings_write = "settings:write"
    eval_read = "eval:read"
    checkpoint_write = "checkpoint:write"


ROLE_PERMISSIONS: dict[ConsoleRole, frozenset[Permission]] = {
    ConsoleRole.admin: frozenset(Permission),
    ConsoleRole.analyst: frozenset(
        {
            Permission.audit_read,
            Permission.alert_read,
            Permission.alert_triage,
            Permission.approval_read,
            Permission.tool_read,
            Permission.policy_read,
            Permission.eval_read,
        }
    ),
    ConsoleRole.approver: frozenset(
        {
            Permission.audit_read,
            Permission.alert_read,
            Permission.approval_read,
            Permission.approval_decide,
        }
    ),
    ConsoleRole.operator: frozenset(
        {
            Permission.audit_read,
            Permission.alert_read,
            Permission.tool_read,
            Permission.tool_write,
            Permission.settings_read,
            Permission.checkpoint_write,
            Permission.eval_read,
        }
    ),
    ConsoleRole.developer: frozenset(
        {
            Permission.audit_read,
            Permission.alert_read,
            Permission.tool_read,
            Permission.policy_read,
            Permission.eval_read,
        }
    ),
    ConsoleRole.viewer: frozenset(
        {Permission.audit_read, Permission.alert_read, Permission.eval_read}
    ),
}


def hash_password(password: str) -> str:
    """Return a salted PBKDF2 hash string (never logs or stores plaintext)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return (
        f"{PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
    )


def verify_password(password: str, stored: str) -> bool:
    """Verify a password in constant time. Malformed stored values return False."""
    try:
        iterations_text, salt_b64, digest_b64 = stored.split("$", 2)
        iterations = int(iterations_text)
        if iterations < 1 or iterations > 1_000_000:
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(digest_b64, validate=True)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return constant_time_bytes_equal(expected, candidate)


@dataclass(frozen=True)
class ConsoleUser:
    """Authenticated console identity."""

    username: str
    role: ConsoleRole
    tenant_id: str | None = None

    @property
    def permissions(self) -> frozenset[Permission]:
        return ROLE_PERMISSIONS[self.role]


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


class SessionInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    # Returned in the JSON body so JS can echo it in the CSRF header; the session
    # cookie itself stays HttpOnly and is never readable from JavaScript.
    csrf_token: str
    username: str
    role: ConsoleRole
    tenant_id: str | None = None
    permissions: tuple[Permission, ...]
    expires_at: datetime


@dataclass(frozen=True)
class Session:
    token: str
    user: ConsoleUser
    expires_at: datetime


class AuthProvider(Protocol):
    """Pluggable authentication interface (local now, OIDC later)."""

    async def authenticate(self, username: str, password: str) -> ConsoleUser | None: ...
    def name(self) -> str: ...


class LocalAuthProvider:
    """Local user store. Passwords are hashes only; no plaintext is retained."""

    def __init__(self, users: dict[str, tuple[str, ConsoleRole, str | None]]) -> None:
        # username -> (pbkdf2 hash, role, tenant)
        self._users = users

    async def authenticate(self, username: str, password: str) -> ConsoleUser | None:
        record = self._users.get(username)
        if record is None:
            return None
        stored, role, tenant = record
        if not verify_password(password, stored):
            return None
        return ConsoleUser(username=username, role=role, tenant_id=tenant)

    def name(self) -> str:
        return "local"


class SessionStore:
    """In-memory server-side sessions (documented: not shared across workers)."""

    def __init__(
        self,
        *,
        ttl_seconds: int = SESSION_TTL_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._sessions: dict[str, Session] = {}

    def create(self, user: ConsoleUser) -> Session:
        token = secrets.token_urlsafe(32)
        now = self._clock()
        if now.utcoffset() is None:
            now = now.replace(tzinfo=UTC)
        session = Session(token=token, user=user, expires_at=now + timedelta(seconds=self._ttl))
        self._sessions[token] = session
        return session

    def get(self, token: str) -> Session | None:
        session = self._sessions.get(token)
        if session is None:
            return None
        now = self._clock()
        if now.utcoffset() is None:
            now = now.replace(tzinfo=UTC)
        if now >= session.expires_at:
            self._sessions.pop(token, None)
            return None
        return session

    def revoke(self, token: str) -> None:
        self._sessions.pop(token, None)

    def active_count(self) -> int:
        return len(self._sessions)


def get_session_store(request: Request) -> SessionStore:
    store = getattr(request.app.state, "console_sessions", None)
    if store is None:
        raise HTTPException(status_code=503, detail="console_unavailable")
    return cast(SessionStore, store)


def optional_user(request: Request) -> ConsoleUser | None:
    store = getattr(request.app.state, "console_sessions", None)
    if store is None:
        return None
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    session = store.get(token)
    return None if session is None else session.user


def current_user(request: Request) -> ConsoleUser:
    user = optional_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="console_auth_required")
    return user


CurrentUser = Annotated[ConsoleUser, Depends(current_user)]


def require(permission: Permission) -> Callable[[ConsoleUser], ConsoleUser]:
    """Dependency factory: require one permission."""

    def dependency(user: CurrentUser) -> ConsoleUser:
        if permission not in user.permissions:
            raise HTTPException(status_code=403, detail="console_permission_denied")
        return user

    return dependency


def verify_csrf(
    request: Request,
    csrf: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
) -> None:
    """Write requests must echo the session token in a header."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    token = request.cookies.get(SESSION_COOKIE)
    if not token or not csrf or not constant_time_bytes_equal(token.encode(), csrf.encode()):
        raise HTTPException(status_code=403, detail="console_csrf_failed")


__all__ = [
    "AuthProvider",
    "ConsoleRole",
    "ConsoleUser",
    "CSRF_HEADER",
    "LocalAuthProvider",
    "LoginBody",
    "Permission",
    "ROLE_PERMISSIONS",
    "SESSION_COOKIE",
    "Session",
    "SessionInfo",
    "SessionStore",
    "current_user",
    "get_session_store",
    "hash_password",
    "optional_user",
    "require",
    "verify_csrf",
    "verify_password",
]

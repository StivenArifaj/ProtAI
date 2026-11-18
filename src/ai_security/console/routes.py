"""Console API routes. Every endpoint is RBAC-checked and returns redacted schemas.

No route here can execute a tool, produce an ALLOW, or trigger containment.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ai_security.console.auth import (
    ConsoleRole,
    ConsoleUser,
    LoginBody,
    Permission,
    SessionInfo,
    current_user,
    get_session_store,
    hash_password,
    require,
    verify_csrf,
)
from ai_security.console.schemas import (
    DecideBody,
    EnableBody,
    RevokeBody,
    SummarizeBody,
    TriageBody,
    UserView,
    WriteResult,
)
from ai_security.console.service import ConsoleService

# Annotated dependency aliases keep ruff B008 quiet while preserving FastAPI DI.
CurrentUser = Annotated[ConsoleUser, Depends(current_user)]
ReadSettings = Annotated[ConsoleUser, Depends(require(Permission.settings_read))]
WriteSettings = Annotated[ConsoleUser, Depends(require(Permission.settings_write))]
ReadAudit = Annotated[ConsoleUser, Depends(require(Permission.audit_read))]
ReadAlerts = Annotated[ConsoleUser, Depends(require(Permission.alert_read))]
TriageAlerts = Annotated[ConsoleUser, Depends(require(Permission.alert_triage))]
ReadApprovals = Annotated[ConsoleUser, Depends(require(Permission.approval_read))]
DecideApprovals = Annotated[ConsoleUser, Depends(require(Permission.approval_decide))]
RevokeApprovals = Annotated[ConsoleUser, Depends(require(Permission.approval_revoke))]
ReadTools = Annotated[ConsoleUser, Depends(require(Permission.tool_read))]
WriteTools = Annotated[ConsoleUser, Depends(require(Permission.tool_write))]
ReadPolicy = Annotated[ConsoleUser, Depends(require(Permission.policy_read))]
ReadEvaluation = Annotated[ConsoleUser, Depends(require(Permission.eval_read))]
WriteCheckpoint = Annotated[ConsoleUser, Depends(require(Permission.checkpoint_write))]


def get_service(request: Request) -> ConsoleService:
    service = getattr(request.app.state, "console_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="console_unavailable")
    return cast(ConsoleService, service)


def get_connector_registry(request: Request) -> Any | None:
    return getattr(request.app.state, "connector_registry", None)


router = APIRouter(prefix="/admin")

# -- auth --------------------------------------------------------------------------


@router.post("/auth/login", response_model=SessionInfo)
async def login(body: LoginBody, request: Request) -> Any:
    store = get_session_store(request)
    provider = getattr(request.app.state, "console_auth_provider", None)
    if provider is None:
        raise HTTPException(status_code=503, detail="console_unavailable")
    user = await provider.authenticate(body.username, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    session = store.create(user)
    response = JSONResponse(
        content=SessionInfo(
            csrf_token=session.token,
            username=user.username,
            role=user.role,
            tenant_id=user.tenant_id,
            permissions=tuple(sorted(user.permissions, key=lambda p: p.value)),
            expires_at=session.expires_at,
        ).model_dump(mode="json")
    )
    settings = getattr(request.app.state, "settings", None)
    secure = bool(settings and settings.app_env.value == "production")
    response.set_cookie(
        "protai_console_session",
        session.token,
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=8 * 3600,
        path="/",
    )
    return response


@router.post("/auth/logout", response_model=WriteResult)
async def logout(request: Request, user: CurrentUser) -> WriteResult:
    store = get_session_store(request)
    token = request.cookies.get("protai_console_session")
    if token:
        store.revoke(token)
    response = JSONResponse(
        content=WriteResult(ok=True, message="Signed out.").model_dump(mode="json")
    )
    response.delete_cookie("protai_console_session", path="/")
    return response  # type: ignore[return-value]


@router.get("/meta/session", response_model=SessionInfo)
async def session_info(request: Request, user: CurrentUser) -> SessionInfo:
    store = get_session_store(request)
    token = request.cookies.get("protai_console_session") or ""
    session = store.get(token)
    expires = session.expires_at if session else datetime.now(UTC)
    return SessionInfo(
        csrf_token=token,
        username=user.username,
        role=user.role,
        tenant_id=user.tenant_id,
        permissions=tuple(sorted(user.permissions, key=lambda p: p.value)),
        expires_at=expires,
    )


@router.get("/auth/users", response_model=tuple[UserView, ...])
async def list_users(
    request: Request,
    user: ReadSettings,
) -> tuple[UserView, ...]:
    provider = getattr(request.app.state, "console_user_records", {})
    return tuple(
        UserView(username=name, role=meta[1], tenant_id=meta[2])
        for name, meta in sorted(provider.items())
    )


@router.post("/auth/users", response_model=WriteResult, dependencies=[Depends(verify_csrf)])
async def create_user(
    body: dict[str, Any],
    request: Request,
    user: WriteSettings,
) -> WriteResult:
    records = getattr(request.app.state, "console_user_records", None)
    if records is None:
        return WriteResult(ok=False, message="Local user store unavailable.")
    username = str(body.get("username", ""))[:128]
    password = str(body.get("password", ""))
    if not username or len(password) < 12:
        return WriteResult(ok=False, message="Username required; password must be 12+ characters.")
    try:
        role = ConsoleRole(str(body.get("role", "viewer")))
    except ValueError:
        return WriteResult(ok=False, message="Unknown role.")
    provider = getattr(request.app.state, "console_auth_provider", None)
    records[username] = (hash_password(password), role, None)
    if provider is not None and hasattr(provider, "add_user"):
        provider.add_user(username, password, role)
    return WriteResult(ok=True, message="User created.", id=username)


# -- overview / stream --------------------------------------------------------------


@router.get("/overview")
async def overview(
    request: Request,
    user: CurrentUser,
) -> Any:
    service = get_service(request)
    return (await service.overview()).model_dump(mode="json")


@router.get("/events/stream")
async def event_stream(
    request: Request,
    user: CurrentUser,
) -> StreamingResponse:
    """SSE heartbeat + alert-count changes. Pause/Resume is client-side."""

    async def generator() -> AsyncIterator[str]:
        service = get_service(request)
        last: int | None = None
        for _ in range(300):  # bounded 10-minute stream; client reconnects
            if await request.is_disconnected():
                break
            current = await service._count_event(
                session_factory=service._sessions,
                event_type="SECURITY_ALERT_RAISED",
            )
            if last is None:
                last = current
                yield "event: snapshot\ndata: " + json.dumps({"alerts": current}) + "\n\n"
            elif current != last:
                yield "event: alerts\ndata: " + json.dumps({"alerts": current}) + "\n\n"
                last = current
            else:
                yield ": heartbeat\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# -- audit --------------------------------------------------------------------------


@router.get("/audit/events")
async def audit_events(
    request: Request,
    user: ReadAudit,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    event_type: str | None = None,
    request_id: str | None = None,
    principal: str | None = None,
    decision: str | None = None,
) -> Any:
    service = get_service(request)
    page = await service.audit_events(
        limit=limit,
        offset=offset,
        event_type=event_type,
        request_id=request_id,
        principal=principal,
        decision=decision,
    )
    return page.model_dump(mode="json")


@router.get("/audit/correlate")
async def correlate(
    request_id: Annotated[str, Query(min_length=1, max_length=128)],
    request: Request,
    user: ReadAudit,
) -> Any:
    return (await get_service(request).correlate(request_id)).model_dump(mode="json")


@router.get("/audit/verify")
async def verify(
    request: Request,
    user: ReadAudit,
) -> Any:
    return (await get_service(request).verify()).model_dump(mode="json")


@router.get("/audit/checkpoints")
async def checkpoints(
    request: Request,
    user: ReadAudit,
) -> Any:
    return [item.model_dump(mode="json") for item in get_service(request).checkpoints()]


@router.post("/audit/checkpoints", response_model=WriteResult, dependencies=[Depends(verify_csrf)])
async def write_checkpoint(
    request: Request,
    user: WriteCheckpoint,
) -> WriteResult:
    return get_service(request).write_checkpoint(user)


# -- alerts -------------------------------------------------------------------------


@router.get("/alerts")
async def alerts(
    request: Request,
    user: ReadAlerts,
) -> Any:
    return [item.model_dump(mode="json") for item in await get_service(request).alerts()]


@router.get("/alerts/rules")
async def alert_rules(
    request: Request,
    user: ReadAlerts,
) -> Any:
    return get_service(request).alert_rules().model_dump(mode="json")


@router.post(
    "/alerts/triage/{sequence}", response_model=WriteResult, dependencies=[Depends(verify_csrf)]
)
async def triage(
    sequence: int,
    body: TriageBody,
    request: Request,
    user: TriageAlerts,
) -> WriteResult:
    return get_service(request).triage(sequence, body.status, body.note, body.assignee, user)


@router.post("/alerts/summarize", response_model=WriteResult, dependencies=[Depends(verify_csrf)])
async def summarize(
    body: SummarizeBody,
    request: Request,
    user: TriageAlerts,
) -> WriteResult:
    return get_service(request).summarize(body.alert_sequence)


# -- approvals ----------------------------------------------------------------------


@router.get("/approvals")
async def approvals(
    request: Request,
    user: ReadApprovals,
) -> Any:
    return [item.model_dump(mode="json") for item in await get_service(request).approvals()]


@router.post(
    "/approvals/{approval_id}/decide",
    response_model=WriteResult,
    dependencies=[Depends(verify_csrf)],
)
async def decide(
    approval_id: str,
    body: DecideBody,
    request: Request,
    user: DecideApprovals,
) -> WriteResult:
    return await get_service(request).decide(approval_id, body.approval_token, body.approve, user)


@router.post(
    "/approvals/{approval_id}/revoke",
    response_model=WriteResult,
    dependencies=[Depends(verify_csrf)],
)
async def revoke(
    approval_id: str,
    body: RevokeBody,
    request: Request,
    user: RevokeApprovals,
) -> WriteResult:
    return await get_service(request).revoke(approval_id, body.reason, user)


# -- tools / connectors / policy ----------------------------------------------------


@router.get("/tools")
async def tools(
    request: Request,
    user: ReadTools,
) -> Any:
    return [item.model_dump(mode="json") for item in get_service(request).tools()]


@router.get("/connectors")
async def connectors(
    request: Request,
    user: ReadTools,
) -> Any:
    return [
        item.model_dump(mode="json")
        for item in get_service(request).connectors(get_connector_registry(request))
    ]


@router.post(
    "/connectors/{connector_id}/enable",
    response_model=WriteResult,
    dependencies=[Depends(verify_csrf)],
)
async def enable_connector(
    connector_id: str,
    body: EnableBody,
    request: Request,
    user: WriteTools,
) -> WriteResult:
    registry = get_connector_registry(request)
    if registry is None:
        return WriteResult(ok=False, message="Connector registry unavailable.")
    return get_service(request).enable_connector(registry, connector_id, user)


@router.post(
    "/connectors/{connector_id}/disable",
    response_model=WriteResult,
    dependencies=[Depends(verify_csrf)],
)
async def disable_connector(
    connector_id: str,
    request: Request,
    user: WriteTools,
) -> WriteResult:
    registry = get_connector_registry(request)
    if registry is None:
        return WriteResult(ok=False, message="Connector registry unavailable.")
    return get_service(request).disable_connector(registry, connector_id)


@router.get("/policies")
async def policies(
    request: Request,
    user: ReadPolicy,
) -> Any:
    return get_service(request).policy().model_dump(mode="json")


@router.get("/configs")
async def configs(
    request: Request,
    user: ReadPolicy,
) -> Any:
    return [item.model_dump(mode="json") for item in get_service(request).configs()]


@router.get("/limiter")
async def limiter(
    request: Request,
    user: ReadSettings,
) -> Any:
    return get_service(request).limiter().model_dump(mode="json")


@router.get("/settings")
async def settings(
    request: Request,
    user: ReadSettings,
) -> Any:
    return [item.model_dump(mode="json") for item in get_service(request).settings()]


@router.get("/evaluation/reports")
async def evaluation_reports(
    request: Request,
    user: ReadEvaluation,
) -> Any:
    return [item.model_dump(mode="json") for item in get_service(request).evaluations()]


__all__ = ["router", "get_service"]

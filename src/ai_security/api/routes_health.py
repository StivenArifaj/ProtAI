"""Liveness and readiness endpoints (blueprint section 18.1).

Responses contain only status booleans; they must never reveal credentials, DSNs, or
internal stack details. Health endpoints may be unauthenticated.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ai_security.api.dependencies import database_ready, policy_self_checks_ok

router = APIRouter(tags=["health"])


class LivenessResponse(BaseModel):
    status: str


class ReadinessChecks(BaseModel):
    config: bool
    database: bool
    policy_self_checks: bool


class ReadinessResponse(BaseModel):
    status: str
    checks: ReadinessChecks


@router.get("/health/live", response_model=LivenessResponse)
async def health_live() -> LivenessResponse:
    """The process is alive. No dependency checks, no internal details."""
    return LivenessResponse(status="alive")


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    responses={503: {"model": ReadinessResponse}},
)
async def health_ready(
    database_ok: Annotated[bool, Depends(database_ready)],
    policy_ok: Annotated[bool, Depends(policy_self_checks_ok)],
) -> ReadinessResponse | JSONResponse:
    """Critical config, dependencies, and policy self-checks are ready (blueprint 18.1)."""
    checks = ReadinessChecks(config=True, database=database_ok, policy_self_checks=policy_ok)
    if database_ok and policy_ok:
        return ReadinessResponse(status="ready", checks=checks)
    return JSONResponse(
        status_code=503,
        content=ReadinessResponse(status="not_ready", checks=checks).model_dump(),
    )

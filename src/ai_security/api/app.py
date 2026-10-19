"""FastAPI application factory.

The factory reads validated settings and fails startup on any configuration error so a
misconfigured process never serves traffic. Documentation endpoints (/docs, /redoc,
/openapi.json) are disabled unless ``APP_ENV`` is exactly ``development`` or ``test``
(blueprint section 18.2).

A module-level ``app`` is provided for the documented uvicorn command
(``uvicorn ai_security.api.app:app``); in-process tests import ``create_app`` and pass
explicit settings instead.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from ai_security.api.routes_health import router as health_router
from ai_security.settings import Settings

APP_VERSION = "0.1.0"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application from validated settings."""
    resolved = settings if settings is not None else Settings()  # type: ignore[call-arg]

    logging.basicConfig(level=resolved.log_level.value)

    docs_enabled = resolved.app_env.documentation_enabled
    app = FastAPI(
        title="AI Agent Security & Safety Platform",
        version=APP_VERSION,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.settings = resolved
    app.include_router(health_router)
    return app


app = create_app()

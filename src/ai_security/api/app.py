"""FastAPI application factory.

The factory reads validated settings and fails startup on any configuration error so a
misconfigured process never serves traffic. Documentation endpoints (/docs, /redoc,
/openapi.json) are disabled unless ``APP_ENV`` is exactly ``development`` or ``test``
(blueprint section 18.2).

It also builds the process-wide persistence layer (``Database``) from settings; engine
construction is lazy, so the factory performs no network I/O. The engine is disposed on
application shutdown.

A module-level ``app`` is provided for the documented uvicorn command
(``uvicorn ai_security.api.app:app``); in-process tests import ``create_app`` and pass
explicit settings instead.

Since Phase 1 the factory also loads and validates the policy documents
(``config/policies.yaml``, ``config/risk_thresholds.yaml``) and runs the ADR-007
self-checks against the real engine before serving traffic. Since Phase 2 it also
builds the mock tool registry (proving it is consistent with the loaded policy) and the
enforced ``ToolGateway`` bound to the audit chain; both are exposed on ``app.state``
for the (later) API routes and for in-process callers. Since Phase 3 it also loads the
strict input-defense configuration, exposes the detection service, and constructs the
session security-state repository. Since Phase 4 it issues request/principal/policy-
bound intent manifests and the wired gateway requires a valid manifest plus its
concrete constraints (and per-constraint use limits) before policy/execution. No
``/v1`` routes exist yet.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ai_security.api.middleware import HostAuthMiddleware
from ai_security.api.routes_health import router as health_router
from ai_security.audit.writer import ChainAuditRecorder
from ai_security.firewall.gateway import ToolGateway
from ai_security.firewall.policy_engine import PolicyEngine
from ai_security.input_defense.config import load_input_defense_config
from ai_security.input_defense.service import InputDefenseService
from ai_security.intent.extractors import MockIntentExtractor
from ai_security.intent.service import IntentManifestService
from ai_security.intent.validator import IntentUsageTracker
from ai_security.persistence.audit_repository import V1_CHAIN_ID, AuditChainRepository
from ai_security.persistence.database import Database
from ai_security.persistence.nonce_repository import SqlAlchemyNonceRepository
from ai_security.persistence.session_repository import SessionSecurityRepository
from ai_security.policy.loader import load_policy_bundle
from ai_security.policy.self_checks import (
    PolicySelfCheckError,
    load_policy_self_checks,
    run_policy_self_checks,
)
from ai_security.settings import Settings
from ai_security.tools.mock_email import MockEmailAdapter
from ai_security.tools.mock_external_sink import MockExternalSinkAdapter, SinkStore
from ai_security.tools.mock_files import MockFilesAdapter
from ai_security.tools.mock_text import MockTextAdapter
from ai_security.tools.registry import build_registry

APP_VERSION = "0.1.0"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application from validated settings."""
    resolved = settings if settings is not None else Settings()  # type: ignore[call-arg]

    logging.basicConfig(level=resolved.log_level.value)

    # Startup policy loading + self-checks (ADR-007/ADR-008): invalid policy documents
    # (PolicyConfigError), an invalid/missing fixture file, or any matrix mismatch
    # refuses startup. Readiness re-evaluates everything live.
    policy_bundle = load_policy_bundle(resolved.policy_path, resolved.risk_thresholds_path)
    self_check_failures = run_policy_self_checks(
        load_policy_self_checks(resolved.policy_self_checks_path), policy_bundle
    )
    if self_check_failures:
        names = ", ".join(failure.fixture for failure in self_check_failures)
        raise PolicySelfCheckError(f"policy self-checks failed at startup: {names}")

    database = Database.from_settings(resolved)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        await database.dispose()

    docs_enabled = resolved.app_env.documentation_enabled
    app = FastAPI(
        title="AI Agent Security & Safety Platform",
        version=APP_VERSION,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.database = database
    # The startup-loaded policy bundle (validated, hashed). Readiness reports its
    # version/hash and re-validates the on-disk configuration live (ADR-007); policy
    # hot-reload is future work, so the running process keeps this bundle.
    app.state.policy_bundle = policy_bundle
    # Host-auth enforcement for every /v1/* request (path-based, fail closed), with the
    # replay store and audit chain bound per application instance. Tests may replace
    # app.state.nonce_registrar to simulate store behavior.
    app.state.nonce_registrar = SqlAlchemyNonceRepository(database.session_factory)
    app.state.audit_chain = AuditChainRepository(database.session_factory, chain_id=V1_CHAIN_ID)
    # Phase 2: capability/policy consistency is proven at startup (fail closed) and the
    # single execution path is wired to the audit chain. The in-memory mock sink is
    # process-local by design (no network, no real side effect).
    registry = build_registry(
        policy_bundle,
        (
            MockEmailAdapter(),
            MockFilesAdapter(),
            MockExternalSinkAdapter(SinkStore()),
            MockTextAdapter(),
        ),
    )
    app.state.tool_registry = registry
    # Phase 4: manifests are issued only by this service (mock extractor in Phase 4;
    # the local-model adapter interface is ready for Phase 8 provider wiring). The
    # gateway is constructed with the tracker so production execution requires a
    # verified, unexpired manifest and reserves each constraint's bounded uses.
    app.state.intent_usage_tracker = IntentUsageTracker()
    app.state.intent_manifest_service = IntentManifestService(
        extractor=MockIntentExtractor(),
        registry=registry,
        bundle=policy_bundle,
        manifest_ttl_seconds=resolved.intent_manifest_ttl_seconds,
    )
    app.state.tool_gateway = ToolGateway(
        registry=registry,
        engine=PolicyEngine(policy_bundle),
        recorder=ChainAuditRecorder(app.state.audit_chain),
        intent_tracker=app.state.intent_usage_tracker,
    )
    # Phase 3: the input-defense configuration is validated at startup (invalid or
    # incomplete dispositions refuse startup) and the detection service plus the
    # tenant/subject-bound session signal store are exposed on app.state for the
    # (later) API routes and for in-process callers. Detection never authorizes tools.
    app.state.input_defense_config = load_input_defense_config(resolved.input_defense_path)
    app.state.input_defense_service = InputDefenseService(app.state.input_defense_config)
    app.state.session_security = SessionSecurityRepository(
        database.session_factory,
        ttl_seconds=resolved.session_signal_ttl_seconds,
        max_age_seconds=resolved.session_max_age_seconds,
    )
    app.add_middleware(HostAuthMiddleware, settings=resolved)
    app.include_router(health_router)
    return app


app = create_app()

# AI Agent Security & Safety Platform

Repository foundation for the AI Agent Security & Safety Platform. The authoritative
specification is `AI_Agent_Security_Platform_Master_Blueprint_v1.2.md` in the repository
root; the archived v1.0 is under `archive/` and is superseded.

**Current state: Phases 0a-9 complete and verified** (repository foundation; security
foundation; typed contracts + deterministic policy engine; tool registry + enforced
gateway; advisory input defense + context provenance; intent extraction + manifest
validation; risk v2 + durable one-time human approvals; output DLP + destination-aware
egress policy; full audit taxonomy + correlation + exact-bytes verification; signed
HTTP ingress, bounded request runtime, and optional local-model intent extraction; and a
reproducible six-task evaluation harness over a versioned synthetic dataset).
Implemented today: enforced
configuration validation; host HMAC authentication + replay rejection on the `/v1/*`
path prefix; deterministic policy engine with 21 startup/readiness self-check fixtures;
typed tool registry + mock-only adapters; the `invoke_tool` gateway as the only execution
path (digest-bound execution authorization, deadlines, timeouts/concurrency/result
bounds, audit-first through the hash chain); `risk-v2` scoring (all `risk-v1` weights plus
one bounded resource-breadth factor); strict versioned
input-defense config with bounded intake, copy-only normalization, versioned injection
heuristics, typed non-PASS failure semantics, trust-labelled context assembly, and a
tenant/subject-bound session signal store; server-issued sealed intent manifests with
exact action/resource/destination/parameter/use constraints and trusted-timezone relative
dates; durable, action-bound approval requests with strict approver rules, digest-only
tokens, and row-locked one-time consumption, enforced by the gateway for engine
`ASK_USER`; mandatory output DLP that inspects validated tool-bound arguments before
execution and the complete buffered result before release, with deterministic pattern
detection, exact-canonical destination trust, span-preserving redaction, and full-response
suppression; and the complete structured audit lifecycle (request, proposal,
inspection, decision, approval consumption, execution, output inspection, response) with
first-class redacted DLP events, indexed correlation metadata, and a read-only verifier
over the exact stored hash-chain bytes with typed tamper findings. Phase 8 adds
host-signed principal assertions, the three documented `/v1` routes (execute, preview,
approval decision), a bounded read-then-summarize demo runtime, per-process rate limits,
and an optional strict Ollama-compatible local model provider. Phase 9 adds a
measurement-only evaluation harness (`ai_security.evaluation`) with a 106-case synthetic
dataset (42 dev / 34 validation / 30 holdout), a 15-case dev quick subset, six separate
task matrices, exact risk-conformance and unauthorized-side-effect counts, and
JSON/Markdown reports with provenance metadata. The measured baseline contains 3
hard-negative input false positives, 0 unauthorized side effects, and 0 DLP leaks; it is
not a risk-calibration result. Detection is advisory and intent/approval/DLP can only
narrow, gate, or raise sensitivity: none can produce an `ALLOW` or bypass policy. **No
general agent planner, real connectors, cloud model adapter, classifier/entropy-based
DLP, approval UI/delivery, process sandbox, external audit anchor, automated retention,
or audit query API/UI exists yet** — do not present the system as providing them. See
`docs/API_INTEGRATION.md`, `docs/EVALUATION.md`, `docs/IMPLEMENTATION_STATE.md`,
`docs/SECURITY_INVARIANTS.md`, `docs/OUTPUT_DLP_FALSE_POSITIVES.md`,
`docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`, and `docs/KNOWN_LIMITATIONS.md`.

## Prerequisites

- Python project tooling: [uv](https://docs.astral.sh/uv/) (`uv --version`)
- Docker Desktop (for the Compose database and API container)
- macOS or Linux shell

## Setup and baseline checks (no Docker required)

```bash
uv sync --frozen          # install from the committed lockfile
uv run pytest             # full suite (1013 unit/integration/security/evaluation tests)
bash scripts/check.sh     # full local gate: lockfile, ruff, mypy, pytest, invariant greps
```

`scripts/check.sh` exits non-zero on any failure.

## Evaluation

The Phase 9 harness is measurement-only and runs offline against repository-owned
synthetic fixtures. It does not add routes or bypass any control.

```bash
# Full 106-case dataset, all splits
uv run --frozen python -m ai_security.evaluation \
  --dataset evaluation/dataset_manifest.yaml --output-dir evaluation/reports

# 15-case dev quick regression; exit 2 on any failed expectation
uv run --frozen python -m ai_security.evaluation \
  --dataset evaluation/dataset_manifest.yaml --output-dir evaluation/reports \
  --split dev --quick --report-name quick_report --fail-on-failures
```

Reports are written as authoritative JSON plus derived Markdown in
`evaluation/reports/`. See `docs/EVALUATION.md` and `evaluation/README.md` for the
positive-class conventions, split rules, metric semantics, and measured limitations.
Do not present the measured matrices as production accuracy or benchmark comparability.

## Local run without Docker

The readiness probe needs a reachable PostgreSQL instance; liveness does not.

```bash
cp .env.example .env      # local development values only; replace `db` with 127.0.0.1
uv run uvicorn ai_security.api.app:app --host 127.0.0.1 --port 8080
curl -s http://127.0.0.1:8080/health/live
curl -s http://127.0.0.1:8080/health/ready
```

## Docker Compose (API + PostgreSQL)

```bash
docker compose up -d db       # start PostgreSQL and wait until healthy
docker compose up api         # start the API (foreground)
curl -s http://127.0.0.1:8080/health/live
```

Expected results:

- `GET /health/live` returns `200 {"status":"alive"}`.
- `GET /health/ready` returns `200` with `checks.config`, `checks.database`, and
  `checks.policy_self_checks` all `true` (plus `policy_version`/`policy_hash`) when the
  stack is healthy, and `503 {"status":"not_ready",...}` when the database is unreachable
  or policy self-checks drift. Neither response contains credentials or stack details.
- `/docs`, `/redoc`, and `/openapi.json` exist only when `APP_ENV` is exactly
  `development` or `test`; they are absent otherwise.

Stop the stack with `docker compose down` (add `-v` to drop the database volume).

## Configuration

All configuration is environment-based; see `.env.example` (blueprint section 5.4). Key
rules enforced at startup:

- `APP_ENV` is required and must be one of `development`, `test`, `staging`, `production`;
  unknown values fail startup.
- `DATABASE_URL` must use the `postgresql+asyncpg://` scheme (ADR-005).
- The sample database password (`firewall_dev_only`) is refused outside
  `development`/`test`.
- `OUTPUT_DLP_PATH` defaults to `config/output_dlp.yaml`; the strict versioned file is
  required at startup, and its exact-canonical destination trust map must cover every
  registered external-mutation destination. Invalid, missing, or non-covering
  configuration refuses startup.
- `MODEL_PROVIDER` defaults to `mock` (offline). `local` requires an exact
  `LOCAL_MODEL_NAME`, an origin-only `LOCAL_MODEL_BASE_URL` (HTTPS outside development
  unless loopback), and a bounded `LOCAL_MODEL_TIMEOUT_SECONDS` (1-60);
  `ALLOW_EXTERNAL_MODEL_CALLS=true` is refused because no cloud adapter exists.
- `REQUEST_TIMEOUT_SECONDS` (1-120, default 30) bounds each request's tool deadline;
  `RATE_LIMIT_*_PER_MINUTE` bounds the four per-process, per-principal buckets.

Configuration errors fail startup with a clear message; the process never starts in a
partially configured state.

## Documentation map

- `docs/ARCHITECTURE.md` — component map and request lifecycle
- `docs/EVALUATION.md` — six-task measurement contract, dataset/splits, measured baseline, limits
- `docs/API_INTEGRATION.md` — signed `/v1` routes, host auth, status/error mapping, local model setup
- `docs/THREAT_MODEL.md` — threat table and trust boundaries with implementation status
- `docs/SECURITY_INVARIANTS.md` — the 25 mandatory invariants and their status
- `docs/POLICY_DECISION_MATRIX.md` — the mandated v1 decision matrix and its enforcement status
- `docs/DECISIONS.md` + `docs/adr/` — architecture decision records
- `docs/IMPLEMENTATION_STATE.md` — what exists, what is verified, what is deferred
- `docs/KNOWN_LIMITATIONS.md` — known gaps of the current phase
- `docs/OUTPUT_DLP_FALSE_POSITIVES.md` — tested DLP hard negatives, false positives, false negatives
- `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md` — stored/excluded audit fields, retention, export/backup/deletion, integrity limits

# Phase 0a application image.
# Python 3.12 pinned by digest per blueprint section 5.1; dependencies install
# exclusively from the committed uv.lock (no resolution drift). Non-root runtime user.
FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

COPY --from=ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 /uv /bin/uv

WORKDIR /app

# Dependencies first so source changes do not invalidate the dependency layer.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev

# src plus the runtime assets the app reads at startup and migrations it is expected to
# run (policy self-check fixtures are required at startup; alembic.ini/migrations make
# `alembic upgrade head` runnable inside the container, e.g. `make migrate` in compose).
COPY src ./src
COPY config ./config
COPY migrations ./migrations
COPY alembic.ini ./
RUN uv sync --frozen --no-dev

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home app \
    && chown -R app:app /app

USER app

EXPOSE 8000

# Module-level app (ai_security.api.app:app). Settings validation fails startup on any
# configuration error; listeners only accept traffic after a successful start.
CMD ["uvicorn", "ai_security.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

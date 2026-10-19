.PHONY: check test migrate up down logs

check:
	bash scripts/check.sh

test:
	uv run pytest

migrate:
	uv run --frozen alembic upgrade head

up:
	docker compose up -d db
	docker compose up api

down:
	docker compose down

logs:
	docker compose logs -f api

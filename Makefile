.PHONY: up down logs fmt lint test ci

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

fmt:
	cd backend && .venv/bin/ruff format .

lint:
	cd backend && .venv/bin/ruff format --check .
	cd backend && .venv/bin/ruff check .

test:
	cd backend && .venv/bin/pytest -q

ci: lint test

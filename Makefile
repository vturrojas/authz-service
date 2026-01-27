.PHONY: up down logs test

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

test:
	cd backend && . .venv/bin/activate && pytest -q

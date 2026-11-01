.PHONY: install check test demo serve docker

install:
	python -m venv .venv && .venv/bin/pip install -e ".[dev]"

check:
	ruff check . && ruff format --check . && mypy && pytest --cov=guardrails_gateway

test:
	pytest

demo:
	aggw demo

serve:
	aggw serve --port 8080

docker:
	docker build -t agent-guardrails-gateway .

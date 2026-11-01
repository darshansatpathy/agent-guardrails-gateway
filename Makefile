.PHONY: install check test eval demo serve docker audit

install:
	python -m venv .venv && .venv/bin/pip install -e ".[dev,llm]"

check:
	ruff check . && ruff format --check . && mypy && pytest --cov=guardrails_gateway --cov-fail-under=85

test:
	pytest

eval:
	aggw eval

audit:
	pip-audit --skip-editable

demo:
	aggw demo

serve:
	aggw serve --port 8080

docker:
	docker build -t agent-guardrails-gateway .

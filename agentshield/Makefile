.PHONY: install dev test test-security lint format clean build demo

# ── Setup ───────────────────────────────────────────
install:
	pip install -e .

dev:
	pip install -e ".[dev,all]"

# ── Quality ─────────────────────────────────────────
test:
	pytest tests/ -v --cov=agentshield --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v

test-security:
	pytest tests/security/ -v

lint:
	ruff check agentshield/ tests/

format:
	ruff format agentshield/ tests/
	ruff check --fix agentshield/ tests/

# ── Build ───────────────────────────────────────────
build: clean
	python -m build

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ── Demo ────────────────────────────────────────────
demo:
	python examples/quickstart.py

validate-policy:
	agentshield validate policies/default.yaml
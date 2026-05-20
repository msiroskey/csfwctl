# csfwctl — developer Makefile
#
# Production install targets (install/uninstall) are stubs for Phase 0.
# The real layout lands when the install tooling is built out in a later
# phase: venv in /opt/csfwctl, wrapper in /usr/local/bin, config in
# /etc/csfwctl. See csfwctl-project-plan.md section 6.

PYTHON ?= python3
VENV ?= .venv
VENV_BIN := $(VENV)/bin
PIP := $(VENV_BIN)/pip
PY := $(VENV_BIN)/python

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "csfwctl development targets:"
	@echo "  make dev        Create .venv and editable-install with dev extras."
	@echo "  make test       Run pytest with coverage."
	@echo "  make lint       Run ruff and mypy."
	@echo "  make wheel      Build a distributable wheel into dist/."
	@echo "  make clean      Remove build artifacts and caches."
	@echo "  make install    (stub) Production install to /opt/csfwctl."
	@echo "  make uninstall  (stub) Remove production install."

$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: dev
dev: $(VENV)/bin/activate
	$(PIP) install -e ".[dev]"

.PHONY: test
test:
	$(PY) -m pytest --cov=csfwctl --cov-report=term-missing

.PHONY: lint
lint:
	$(VENV_BIN)/ruff check csfwctl tests
	$(VENV_BIN)/ruff format --check csfwctl tests
	$(VENV_BIN)/mypy

.PHONY: format
format:
	$(VENV_BIN)/ruff format csfwctl tests
	$(VENV_BIN)/ruff check --fix csfwctl tests

.PHONY: wheel
wheel:
	$(PY) -m pip install --upgrade build
	$(PY) -m build --wheel

.PHONY: clean
clean:
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

.PHONY: install
install:
	@echo "make install is a stub in Phase 0."
	@echo "Production install layout will be implemented in a later phase."
	@echo "See csfwctl-project-plan.md section 6."
	@exit 1

.PHONY: uninstall
uninstall:
	@echo "make uninstall is a stub in Phase 0."
	@exit 1

# csfwctl — developer Makefile
#
# Production install targets (install/uninstall) are stubs for Phase 0.
# The real layout lands when the install tooling is built out in a later
# phase: venv in /opt/csfwctl, wrapper in /usr/local/bin, config in
# /etc/csfwctl. See csfwctl-project-plan.md section 6.

# Python interpreter selection.
#
# csfwctl requires Python >= 3.11 (see pyproject.toml). On macOS the
# default `python3` often points at the system 3.10, which is too old.
# Auto-detect the newest available interpreter; override explicitly with
# e.g. `make dev PYTHON=python3.14`. If a `.venv` already exists, its
# interpreter wins and `make dev` will warn about a mismatch — run
# `make clean-venv` to rebuild against a different Python.
PYTHON ?= $(shell \
	for p in python3.14 python3.13 python3.12 python3.11 python3; do \
		if command -v $$p >/dev/null 2>&1 && \
		   $$p -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then \
			echo $$p; exit 0; \
		fi; \
	done; \
	echo python3)
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
	@echo "  make clean-venv Remove the .venv (rebuilt on next 'make dev')."
	@echo "  make install    (stub) Production install to /opt/csfwctl."
	@echo "  make uninstall  (stub) Remove production install."
	@echo ""
	@echo "Override the Python interpreter:"
	@echo "  make dev PYTHON=python3.14"
	@echo "Auto-detected interpreter: $(PYTHON)"

.PHONY: check-python
check-python:
	@command -v $(PYTHON) >/dev/null 2>&1 || { \
		echo "error: PYTHON=$(PYTHON) not found on PATH" >&2; \
		echo "hint: install Python >= 3.11 or override, e.g. make dev PYTHON=python3.14" >&2; \
		exit 1; \
	}
	@$(PYTHON) -c 'import sys; v = sys.version_info; \
sys.exit(0) if v >= (3, 11) else sys.exit(f"error: csfwctl requires Python >= 3.11, got {v.major}.{v.minor} ({sys.executable})\nhint: override with, e.g., make dev PYTHON=python3.14")'

$(VENV)/bin/activate: | check-python
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

.PHONY: dev
dev: $(VENV)/bin/activate
	@venv_py=$$($(PY) -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'); \
	want_py=$$($(PYTHON) -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "?"); \
	if [ "$$venv_py" != "$$want_py" ] && [ "$$want_py" != "?" ]; then \
		echo "warning: existing $(VENV) uses Python $$venv_py, but PYTHON=$(PYTHON) is $$want_py" >&2; \
		echo "         run 'make clean-venv' to rebuild against $(PYTHON)" >&2; \
	fi
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

.PHONY: clean-venv
clean-venv:
	rm -rf $(VENV)

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

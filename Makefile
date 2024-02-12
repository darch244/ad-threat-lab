PYTHON ?= python3
VENV    = .venv
PIP     = $(VENV)/bin/pip
PYTEST  = $(VENV)/bin/pytest
RUFF    = $(VENV)/bin/ruff
MYPY    = $(VENV)/bin/mypy
PYTHON_BIN = $(VENV)/bin/python

.PHONY: setup test lint format scan-syntax mypy all clean

all: lint test

## Create venv and install pinned requirements
setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

## Statically type-check the custom tooling
mypy:
	$(MYPY) tools

## Lint the tools and tests with ruff (zero errors required)
lint:
	$(RUFF) check tools tests

## Auto-format the tools and tests with ruff
format:
	$(RUFF) format tools tests

## Syntax-scan: compile every Python tool + (when pwsh exists) PowerShell scripts
scan-syntax:
	$(PYTHON_BIN) -m compileall -q tools tests
	$(PYTHON_BIN) -m py_compile tools/__init__.py tools/spn_collector.py tools/acl_scanner.py tools/py_kerberoast.py
	@if command -v pwsh >/dev/null 2>&1; then \
		pwsh -NoProfile -Command "Get-ChildItem automation -Filter *.ps1 | ForEach-Object { \$$null = [System.Management.Automation.Language.Parser]::ParseFile(\$$_.FullName, [ref]\$$null, [ref]\$$errs); if (\$$errs.Count -gt 0) { Write-Error 'PS syntax errors in \$$(\$$_.Name)'; exit 1 }; Write-Host 'PS OK: \$$(\$$_.Name)' }"; \
	else echo "pwsh not on PATH - skipped PowerShell syntax scan"; \
	fi

## Run the unit test suite (no live domain required)
test:
	$(PYTEST) -q

## Full gate: syntax + lint + typecheck + tests
ci: scan-syntax lint mypy test
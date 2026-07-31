SHELL := /bin/bash
PYTHON ?= python

.DEFAULT_GOAL := help

.PHONY: help bootstrap test-python test-contracts check-toolchain dev package-linux

help: ## Show Complete development commands.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Initialize the pinned Complete component submodules.
	@bash scripts/bootstrap-complete.sh

test-python: ## Run the TrafficTracer Python test suite.
	@$(PYTHON) -m pytest -q

test-contracts: ## Run cross-component contract tests (available after TT-009).
	@echo "test-contracts is not available until TT-009 is complete" >&2
	@exit 2

check-toolchain: ## Check the Complete development toolchain (available after TT-005).
	@echo "check-toolchain is not available until TT-005 is complete" >&2
	@exit 2

dev: ## Build and start TrafficTracer Complete (available after TT-034).
	@echo "dev is not available until TT-034 is complete" >&2
	@exit 2

package-linux: ## Build the Linux package (available after TT-035).
	@echo "package-linux is not available until TT-035 is complete" >&2
	@exit 2

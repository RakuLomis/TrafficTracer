SHELL := /bin/bash
PYTHON ?= python

.DEFAULT_GOAL := help

.PHONY: help bootstrap test-python test-contracts check-toolchain build-core build-worker prepare-dev dev package-linux

help: ## Show Complete development commands.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Initialize the pinned Complete component submodules.
	@bash scripts/bootstrap-complete.sh

test-python: ## Run the TrafficTracer Python test suite.
	@$(PYTHON) -m pytest -q

test-contracts: ## Run the Complete schema and validation contract tests.
	@$(PYTHON) -m pytest -q test/test_job_contract.py test/test_worker_api_contract.py test/test_session_flow_contract.py test/test_contracts.py

check-toolchain: ## Check the Complete development toolchain.
	@bash scripts/check-toolchain.sh

build-core: ## Rebuild the pinned mihomo-traffictracer sidecar.
	@bash scripts/build-core.sh

build-worker: ## Rebuild and smoke-test the TrafficTracer Worker sidecar.
	@bash scripts/build-worker.sh

prepare-dev: ## Rebuild and inject all Complete development sidecars.
	@bash scripts/build-ui.sh --prepare-only

dev: ## Rebuild sidecars and start TrafficTracer Complete in development mode.
	@bash scripts/build-ui.sh

package-linux: ## Build the Linux package (available after TT-035).
	@echo "package-linux is not available until TT-035 is complete" >&2
	@exit 2

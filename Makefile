SHELL := /bin/bash
PYTHON ?= python

.DEFAULT_GOAL := help

.PHONY: help bootstrap test-python test-contracts test-e2e-direct check-toolchain build-core build-worker check-component-lock prepare-dev dev package-linux

help: ## Show Complete development commands.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: ## Initialize the pinned Complete component submodules.
	@bash scripts/bootstrap-complete.sh

test-python: ## Run the TrafficTracer Python test suite.
	@$(PYTHON) -m pytest -q

test-contracts: ## Run the Complete schema and validation contract tests.
	@PYTHON=$(PYTHON) bash scripts/test-contracts.sh

test-e2e-direct: check-component-lock ## Run the unprivileged DIRECT-mode integration test.
	@PYTHON=$(PYTHON) bash scripts/test-e2e-direct.sh

check-toolchain: ## Check the Complete development toolchain.
	@bash scripts/check-toolchain.sh

build-core: ## Rebuild the pinned mihomo-traffictracer sidecar.
	@bash scripts/build-core.sh

build-worker: ## Rebuild and smoke-test the TrafficTracer Worker sidecar.
	@bash scripts/build-worker.sh

check-component-lock: build-core build-worker ## Verify source pins and binary protocol handshakes.
	@scripts/check-component-lock.py

prepare-dev: ## Rebuild and inject all Complete development sidecars.
	@bash scripts/build-ui.sh --prepare-only

dev: ## Rebuild sidecars and start TrafficTracer Complete in development mode.
	@bash scripts/build-ui.sh

package-linux: ## Build, verify, and collect the Complete Linux packages.
	@bash scripts/package-linux.sh

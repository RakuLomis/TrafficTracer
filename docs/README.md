# TrafficTracer Documentation

This directory contains the detailed documentation for TrafficTracer Complete. The root README is intentionally limited to the product overview and first-run QuickStart.

## User guides

- [Complete UI guide](complete/quickstart.md): installation, first capture, YAML batches, Session browsing, and flow lookup.
- [Target configuration](configuration.md): supported YAML fields, normalization rules, examples, and validation limits.
- [Operations and troubleshooting](operations.md): TUN and service behavior, capture permissions, output directories, recovery, and common failures.

## Technical reference

- [Profile and proxy pipelines](profile-proxy-pipelines.md): queue semantics, ownership, barriers, resume behavior, and provenance.

- [Architecture](architecture.md): component ownership, process boundaries, lifecycle, and protocol pins.
- [Sessions and correlation data](data-model.md): directory layout, canonical indexes, correlation semantics, coverage, and packet evidence.
- [Deferred multi-tab design](future-multi-tab-capture.md): non-normative notes for a possible post-1.0 browser-group mode; current releases remain single-tab.
- [Capture startup and Session-store efficiency plan](complete/execution-efficiency-atomic-plan.md): measured bottlenecks, invariants, atomic implementation tasks, and performance gates.
- [Development and releases](development.md): source setup, tests, packaging, provenance, and release gates.
- [Standalone tools](standalone-tools.md): compatibility CLI entry points and the legacy NetLog parser.
- [JSON Schemas](../contracts/): machine-readable Worker, Job, Session, Flow, target, batch, and PCAP contracts.

## Release information

- [1.0.14 release notes](releases/v1.0.14.md)
- [1.0.7 release notes](releases/v1.0.7.md)
- [1.0.4 release notes](releases/v1.0.4.md)
- [1.0.1 release notes](releases/v1.0.1.md)
- [1.0.0 release notes](releases/v1.0.0.md)
- [Release checklist](release-checklist.md)
- [Changelog](../CHANGELOG.md)

## Documentation policy

The documentation follows these rules:

1. English is the only maintained documentation language.
2. `README.md` is a stable entry point, not a full technical reference.
3. `complete/components.lock.yaml` is the source of truth for product, component, and protocol versions.
4. Files in `contracts/` are authoritative for serialized payload fields and enum values.
5. Runtime behavior takes precedence over historical design notes. Obsolete implementation plans are not kept in the active documentation tree.
6. Examples must not contain real proxy credentials, subscription URLs, controller secrets, captures, or user-specific paths.

Unless a page states otherwise, this documentation describes TrafficTracer Complete 1.0.14 on Linux x86-64. Legacy Session schemas remain readable, but new captures use the current contracts pinned by `complete/components.lock.yaml`.

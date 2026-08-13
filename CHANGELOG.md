# Changelog

All notable TrafficTracer Complete changes are recorded here.

## [1.0.0] - 2026-08-13

First Linux x86-64 release of the integrated TrafficTracer workflow.

### Added

- One UI for profile import, node selection, system proxy/TUN control, serial capture, analysis, Session browsing, and five-tuple lookup.
- Versioned contracts joining Chrome CDP/NetLog, dual-interface PCAP, Mihomo tracing events, request attribution, and pre-proxy to post-proxy flow results.
- YAML-driven serial capture with cancellation, recovery, integrity reporting, and explicit direct/proxy/reject/local egress semantics.
- Deb and AppImage packaging with pinned component revisions, checksums, CycloneDX SBOM, notices, secret/permission audit, and package smoke tests.

### Release scope

- Supported release target: Linux x86-64 (`x86_64-unknown-linux-gnu`).
- Build and release validation environment: the current Ubuntu 24.04 LTS host.
- The public packages may be unsigned when no Tauri updater signing key is configured; checksums and release audit metadata remain mandatory.

### Compatibility

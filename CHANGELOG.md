# Changelog

All notable TrafficTracer Complete changes are recorded here.

## Unreleased

## [1.0.12] - 2026-08-26

### Fixed

- Aligned the Rust and JavaScript Mihomo API plugins on one compatible revision.
- Accepted valid TUIC server configuration responses that omit an empty `ech-key`.
- Adapted log-level and traffic models to the updated plugin bindings.
- Added dependency-lock and TUIC deserialization regression coverage.

## [1.0.11] - 2026-08-26

### Fixed

- Recovered Home core data after sidecar-to-service controller transitions.
- Refreshed all Mihomo-backed queries after a real controller readiness probe.
- Added bounded error-only retries for core configuration, proxies, rules,
  providers, and version data.
- Replaced the empty Clash Info failure state with visible feedback and retry.

## [1.0.10] - 2026-08-26

### Added

- Added monotonic Job, stage, and operation timings for Worker recovery,
  capture preparation, tshark, Chrome, page observation, analysis, and packet
  splitting.
- Added an output-root-bound persistent Session catalog with incremental
  reconciliation, indexed recovery candidates, and catalog-first pagination.
- Added an application-owned Chrome profile scratch root with strict ownership
  markers and bounded crash-safe cold-profile cleanup.
- Persisted active TrafficTracer progress and Worker startup timing in the UI.

### Changed

- Deferred whole-history five-tuple lookup until the user submits the query and
  cancelled stale history/detail requests when the workspace changes.
- Updated DIRECT, TUN, and recovery integration fixtures to the normalized
  `raw/` input, atomic `analysis/` output, and canonical v2 connection-index
  contracts.

### Fixed

- Removed output-root-wide Session scans from capture and normal recovery hot
  paths.
- Preserved reusable warm Chrome profiles during Worker crash recovery while
  retaining fail-closed handling for unknown marked layouts.

### Validation

- Passed 575 Python tests, 36 frontend tests, 72 TrafficTracer Rust bridge
  tests, Python/Go/Rust contract gates, Mihomo tracer tests, DIRECT E2E, and
  Chrome/tshark/analysis cancellation plus Worker crash-recovery E2E.
- On the 1,000-Session five-run fixture, warm catalog lookup stayed below
  30 ms and indexed recovery discovery stayed below 28 ms.

## [1.0.9] - 2026-08-24

### Added

- Added explicit carrier protocol and carrier path evidence-source fields so
  inferred fallback metadata remains distinguishable from lifecycle evidence.
- Added an optional proxy selection group for strict single-protocol preflight.
- Persisted the TrafficTracer environment, YAML target selection, current or
  recent Job and Capture Group, selected capture folder, page, and Session.

### Fixed

- Accepted capture-tail attribution counters in the canonical PCAP index
  contract instead of failing analysis after a successful capture.
- Allowed failed analysis Sessions to be retried in place without recapturing
  or replacing their raw evidence.
- Reconciled a successful standalone reanalysis with its owning Capture Group,
  preserving the correct Resume position for any remaining targets.
- Scoped proxy-protocol preflight to an explicitly selected chain and retained
  runtime trace evidence as the authoritative protocol observation.
- Kept capture startup and runtime failures visible after navigation instead of
  relying on a transient notification.

### Validation

- Passed all 552 TrafficTracer Python tests, 72 TrafficTracer Rust bridge tests,
  33 focused frontend tests and TypeScript checks, strict frontend lint, and the
  Mihomo tracer package tests.

## [1.0.8] - 2026-08-23

### Added

- Added protocol-neutral physical carrier identities, generations, lifecycle
  events, logical-flow bindings, and multi-path observations.
- Added strict single-protocol batch capture and observational mode, with the
  frozen expected protocol retained across Resume.
- Added carrier, proxy-protocol, and TUN inbound consistency summaries to the
  canonical artifacts and desktop UI.

### Fixed

- Correlated reused Hysteria2 logical streams and UDP associations with their
  long-lived QUIC/UDP carrier instead of reporting the reused socket as missing.
- Preserved Hysteria2 port-hopping paths under one carrier identity and allocated
  a new generation only after a successful carrier replacement.
- Stored each shared physical carrier PCAP once and referenced it from every
  bound logical connection instead of duplicating encrypted packets per flow.

### Validation

- Passed all 543 TrafficTracer Python tests, the Mihomo full and race suites,
  cross-repository golden contracts, and Clash Verge TypeScript, lint, frontend,
  Rust command, and Worker integration tests.

## [1.0.5] - 2026-08-19

### Fixed

- Kept the TrafficTracer batch UI polling through stale terminal snapshots while a Resume transition is being accepted by the Worker.
- Reconciled resumed batch status with the newest manifest revision so an old failed child cannot mask continued capture progress.
- Preserved normalized pre-proxy tuples and bounded causally related post-barrier Mihomo events during correlation.
- Classified explicit no-socket, local endpoint, and failure-before-socket outcomes without reporting false missing post-proxy flows.

### Validation

- Completed a 64-target capture with all Sessions passing request attribution, transport correlation, and consistency checks.
- Confirmed YouTube primary media playback and URL-to-pre/post-proxy flow association.

## [1.0.4] - 2026-08-18

### Fixed

- Preserved every CDP redirect occurrence as a distinct, stable request while
  retaining the redirect-chain relationship and URL attribution.
- Backfilled occurrence metadata when reanalyzing legacy captures and replaced
  false duplicate-request consistency failures with occurrence-aware checks.
- Made resumed site batches skip completed targets, retry failed targets, and
  continue to later targets instead of stopping at the first network failure.
- Defaulted UI-created and resumed serial batches to non-fail-fast execution so
  one inaccessible site no longer aborts a broad capture campaign.

### Added

- Expanded and normalized the default site catalog for broader static, portal,
  SPA, media, real-time, and infrastructure capture coverage.

### Validation

- Passed all 522 TrafficTracer Python tests and the targeted Clash Verge UI
  tests and type checks.
- Reanalyzed the captured Stack Overflow redirect case successfully, retaining
  both 307-to-403 and 302-to-200 request occurrences.

## [1.0.3] - 2026-08-15

### Fixed

- Updated Home Current Node delay checks reactively without requiring route
  navigation to reveal completed results.
- Waited for per-node and group delay checks to settle before the final refresh.
- Supported multiple delay subscribers with owner-scoped cleanup so Home,
  Proxies, and chain-mode consumers do not replace one another.

### Validation

- Added DelayManager multi-subscriber regression coverage and validated the
  complete frontend, Node packaging tests, type checks, lint, and production
  Web build.

## [1.0.2] - 2026-08-15

### Fixed

- Replaced page-script Play and Skip activation with scoped, coordinate-based
  CDP mouse events while retaining a fixed capture window.
- Confirmed primary YouTube playback only from consecutive media-time advances,
  preventing a stalled player state from being reported as useful video.
- Distinguished no-ad, unskippable-ad, attempted-Skip, confirmed-Skip, and
  missing-primary outcomes in analysis artifacts and the desktop UI.

### Added

- Added an isolated temporary-profile YouTube interaction harness for repeatable
  headed-browser diagnostics without touching existing browser processes.

## [1.0.1] - 2026-08-14

### Added

- Added optional bounded YouTube playback observation for YAML targets, with a
  fixed capture window, visible Skip-control interaction, preserved ad traffic,
  primary-content duration goals, YouTube Player API and active-video
  detection, bounded interaction diagnostics, and explicit scenario outcomes.
- Added a TrafficTracer UI heartbeat and a tray action that reloads only the
  WebView while leaving Mihomo and active capture work running.

### Fixed

- Stopped terminal batches and missing packet-split Jobs from retaining
  high-frequency polling state across application restarts.
- Prevented packet-split previews from running while a capture batch is active.
- Separated playback scenario success from analysis integrity and network
  outcome so a failed playback goal cannot be hidden by valid flow correlation.

### Documentation

- Reduced the root README to the product overview and first-run QuickStart.
- Reorganized maintained documentation into focused English user, architecture, data, operations, development, and compatibility-tool guides.

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

- The bundle retains Clash Verge's package identity for in-place upgrades and configuration reuse while using a TrafficTracer-specific bundle version and release asset names.

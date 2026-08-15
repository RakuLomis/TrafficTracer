# Changelog

All notable TrafficTracer Complete changes are recorded here.

## Unreleased

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

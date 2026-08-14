# TrafficTracer Complete UI Guide

TrafficTracer Complete 1.0.0 packages the pinned UI, Worker, Mihomo core, and privileged service integration as one Linux x86-64 application. This guide covers the normal desktop workflow. It does not require sibling repositories or standalone capture commands.

## 1. Verify the release

The release directory contains one Deb, one AppImage, checksums, component provenance, license notices, an SBOM, and an audit report:

```text
traffictracer-complete-v1.0.0-linux-x86_64/
├── TrafficTracer-Complete_1.0.0_linux_x86_64.deb
├── TrafficTracer-Complete_1.0.0_linux_x86_64.AppImage
├── SHA256SUMS
├── VERSION
├── COMPONENTS
├── SBOM.cdx.json
├── RELEASE-AUDIT.json
├── METADATA.sha256
├── LICENSE
├── NOTICE
└── THIRD_PARTY_NOTICES.md
```

Verify the package checksums:

```bash
cd /path/to/traffictracer-complete-v1.0.0-linux-x86_64
sha256sum -c SHA256SUMS
```

`VERSION` identifies TrafficTracer Complete 1.0.0. `COMPONENTS` records the exact TrafficTracer, Mihomo, UI, and service revisions used by the package.

## 2. Install prerequisites

TrafficTracer needs Chrome or Chromium and the Wireshark command-line capture tools. On Ubuntu:

```bash
sudo apt update
sudo apt install tshark
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
dumpcap -D
```

Some distributions grant capture access through the `wireshark` group instead of file capabilities. Follow the package prompt and sign in again after changing group membership.

## 3. Install or run the application

Install the Deb:

```bash
sudo apt install ./TrafficTracer-Complete_1.0.0_linux_x86_64.deb
```

The package name remains `clash-verge` and its bundle version is `2.5.2+traffictracer.1.0.0`. This allows an in-place upgrade of an existing Clash Verge installation and preserves user configuration. The already-running process does not change until it exits. Use a maintenance window, exit it normally, install the package, and start the new version.

To avoid installing system files, use the AppImage:

```bash
chmod +x TrafficTracer-Complete_1.0.0_linux_x86_64.AppImage
./TrafficTracer-Complete_1.0.0_linux_x86_64.AppImage
```

Do not install from `/tmp` if the path may disappear after a reboot. For `apt`, include `./` or an absolute path; otherwise the filename is interpreted as a package name.

## 4. Configure Mihomo

1. Open **Profiles** and import a valid Mihomo YAML profile.
2. Activate that profile.
3. Open **Settings → Clash Core** and select `verge-mihomo-tt`.
4. Open **Proxies**, run the latency test, and choose a node or policy group.
5. Enable system proxy if applications should use the proxy explicitly.
6. Enable TUN if the experiment must intercept system traffic transparently.

TrafficTracer owns tracing only while a capture job is active. There is no independent tracing toggle in Settings.

## 5. Install and verify the TUN service

TUN changes require the bundled Clash Verge service. Install it from the application when prompted. On Linux, the UI and service communicate through:

```text
/run/clash-verge-service/service.sock
```

Authentication is expected during service installation. An `IPC path not ready` message means the installer finished but the application did not observe a ready socket within the allowed handshake. See [Operations and troubleshooting](../operations.md#service-and-ipc) before retrying.

The runtime TUN device is normally `Meta`. The Traffic Tracer form may be left empty to use the runtime/default device. A value displayed elsewhere in the profile is configuration input, not proof that the interface currently exists. Environment Check resolves the effective interface before capture.

## 6. Prepare a capture

Open **Traffic Tracer** and configure:

- **Session output directory**: an absolute, writable directory owned by the desktop user;
- **TUN interface**: empty for runtime/default discovery, or the exact active device;
- **Physical interface**: the egress interface carrying proxy traffic;
- **Chrome executable**: an absolute path when automatic discovery is insufficient;
- **Analysis storage**: `Standard` for raw PCAP plus indexes, or `Full` to also export per-connection PCAP files immediately;
- **Cache mode**: `Cold` for isolated repeatable captures, or `Warm` only when cache reuse is part of the experiment.

Find the physical interface with:

```bash
ip route show default
```

Run **Environment Check**. Capture cannot start while a blocking diagnostic exists. The check covers the selected core, controller, tracing capability, service, TUN state, both interfaces, Chrome, packet-capture permissions, and output-directory access.

## 7. Select targets

### Manual target

Enter one absolute HTTP or HTTPS URL and its domain. The manual values are one target only.

### YAML target list

Select an absolute `.yaml` or `.yml` file. TrafficTracer reads only safe target fields from its `sites` list, displays a normalized preview, and lets you select a subset. The URL and domain inputs remain available for manual mode; they do not override entries selected from the YAML preview.

```yaml
sites:
  - domain: example.com
    url: https://example.com/
    page_type: main-page
    wait: 10
    wait_load_timeout: 30
    traffic_type: all

  - domain: example.com
    url: https://example.com/video/1
    page_type: video-play1
    wait: 20
    wait_load_timeout: 45
    traffic_type: all
```

Targets execute serially in YAML order. TrafficTracer waits for the previous managed Chrome process to exit before starting the next target. A capture group can be cancelled, and interrupted or failed groups retain enough state to resume from the exact target.

See [Target configuration](../configuration.md) for normalization and limits.

## 8. Run the capture

Start capture only after Environment Check passes. During a job, controls that could invalidate evidence are locked, including core, profile, tracing, service, TUN, and system-proxy changes.

Each target follows this lifecycle:

1. create a versioned Session;
2. snapshot the effective runtime context;
3. enable Mihomo tracing for the Session;
4. capture the TUN and physical interfaces;
5. launch managed Chrome with CDP and NetLog collection;
6. navigate and observe for the configured duration;
7. stop managed processes in a bounded order;
8. finalize raw evidence;
9. run correlation and consistency analysis;
10. publish canonical indexes and update the Session manifest.

A completed job can still have `degraded` page quality. Job state reports whether orchestration completed; quality reports whether the captured evidence represents a usable network observation.

## 9. Browse Sessions

While capture is active, the UI automatically selects the current timestamped capture-group directory. When no capture is active, historical Sessions are not mixed into one root-level list. Select a specific timestamp directory to inspect it.

The default layout is:

```text
<session-root>/
└── <capture-timestamp>/
    └── <domain>/
        └── <page-type>__<readable-url>/
            ├── session.json
            ├── raw/
            └── analysis/
```

Open a Session to inspect its state, target, warnings, artifacts, request attribution, canonical connections, egress outcomes, packet evidence, and coverage metrics. Old schema-v1 Sessions remain readable.

### Split a complete Standard capture group

Select the timestamp folder in **Sessions**. The header reports how many page Sessions are complete, still unsplit, or need repair.

- **Split missing** processes only completed Standard Sessions whose two managed raw PCAP files are available and whose current analysis generation has no per-connection split.
- **Repair incomplete** processes only `partial` or `stale` splits. It does not rewrite a valid completed split.
- The Worker processes page Sessions strictly one at a time. Closing the UI does not stop the Worker Job; reopen Sessions to restore its progress display. Use **Cancel** for an orderly stop.

Progress is persisted atomically as `<capture-timestamp>/packet-split-manifest.json`. Before every child analysis, the Worker rechecks the published Session manifest and PCAP index, so resuming or starting the operation again does not duplicate completed output. A failed page is recorded and the remaining eligible pages continue.

The split keeps the existing timestamp/domain/page layout. Flow PCAPs remain inside each page Session and retain connection IDs, request IDs, URLs, pre/post roles, and generation provenance; the operation never merges unrelated page captures.

## 10. Query a flow

Enter a pre-proxy five-tuple consisting of protocol, source IP, source port, destination IP, and destination port. The query returns every matching logical flow in the selected Session scope.

Interpret the result as follows:

- `post_flow` contains the observed physical-side five-tuple when an outbound socket was established;
- `post_flow=null` is valid for reject, failure-before-socket, and local/not-applicable outcomes;
- `post_flow.shared=true` means multiple logical flows reuse one outer transport and the relation is not one-to-one;
- `attribution_scope` separates page-attributed, browser-background, capture-unattributed, and local-internal traffic;
- URLs are attached through the request index and may be many-to-one with a connection.

See [Sessions and correlation data](../data-model.md) for the full semantics.

## 11. Protocol versions

`complete/components.lock.yaml` is authoritative. TrafficTracer Complete 1.0.0 uses:

| Contract | Version |
| --- | ---: |
| Worker JSONL API | 2 |
| Job schema | 2 |
| Session manifest | 2 |
| Flow result | 1 |
| Connection index | 2 |
| Request index | 2 |
| PCAP index | 1 |
| Batch manifest | 1 |
| Mihomo tracing API | 1 |
| Mihomo event schema | 1 |

Do not replace only the Worker, UI, or Mihomo sidecar. The component lock and startup handshake require a compatible set.

## 12. Next references

- [Architecture](../architecture.md)
- [Target configuration](../configuration.md)
- [Sessions and correlation data](../data-model.md)
- [Operations and troubleshooting](../operations.md)
- [Development and releases](../development.md)

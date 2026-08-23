# Architecture

TrafficTracer Complete integrates a desktop controller, a job Worker, an instrumented proxy core, Chrome observability, and two packet-capture surfaces. The integration is pinned by `complete/components.lock.yaml` and packaged from the `Complete` branch.

## Component boundaries

| Component | Primary responsibility | Does not own |
| --- | --- | --- |
| Clash Verge UI | Profiles, proxy selection, system proxy, TUN controls, capture forms, progress, Session browsing, and result presentation | Flow inference or packet parsing |
| Tauri TrafficTracer backend | Worker lifecycle, request/response transport, UI events, control locking, path selection, and startup recovery | Browser or packet evidence interpretation |
| TrafficTracer Worker | Diagnostics, one active job, serial batches, managed processes, Session state, capture orchestration, analysis, cancellation, and recovery | Proxy routing policy |
| Mihomo TrafficTracer core | Proxy routing plus versioned pre-proxy, dial, post-proxy, terminal, and byte-count events | URL attribution |
| Chrome CDP and NetLog | Request URL, timing, resource type, cache/service-worker state, socket and transport evidence | Physical proxy egress |
| dumpcap/tshark | Raw packets on the TUN and physical interfaces and optional per-flow extraction | Application request identity |

The privileged Clash Verge service changes system-level networking state. The desktop UI and Worker run as the desktop user. Packet capture should be granted through narrowly scoped `dumpcap` capabilities or distribution group policy; the entire application should not run as root.

## Repository composition

```text
TrafficTracer (Complete branch)
├── traffictracer/                  Python Worker and analysis library
├── contracts/                      Cross-language JSON Schemas
├── components/mihomo/              Pinned TrafficTracer core submodule
├── components/clash-verge-rev/     Pinned UI submodule
├── complete/components.lock.yaml   Product, source, service, and protocol pins
└── scripts/                        Build, verification, package, and release gates
```

The two submodules are build inputs, not arbitrary sibling checkouts. A Complete build rejects source commits or binary handshakes that do not match the lock.

## Runtime topology

```text
User
  |
  v
Clash Verge UI
  | Tauri commands and events
  v
TrafficTracer backend
  | Worker API v2 over JSON Lines
  v
TrafficTracer Worker
  |-- controller API ----------> Mihomo TrafficTracer
  |-- CDP / managed process ---> Chrome
  |-- dumpcap / tshark --------> TUN and physical interfaces
  `-- atomic files ------------> selected Session root

Mihomo TrafficTracer
  `-- tracing JSONL -----------> Session raw evidence
```

Only one Worker job is active at a time. A YAML batch is a persistent parent job whose child captures execute serially. This avoids overlapping Chrome profiles, tracing ownership, interfaces, or output paths.

## Capture lifecycle

For each target, the Worker:

1. validates the immutable Job specification;
2. creates a Session and writes an atomic manifest;
3. snapshots effective interfaces, TUN, controller, profile, selected node, and capture options;
4. enables tracing with the Session identity;
5. starts packet capture on the pre-proxy TUN and post-proxy physical interfaces;
6. starts a Worker-owned Chrome profile and CDP/NetLog collection;
7. navigates to the target and waits for the configured observation period;
8. closes only Worker-owned Chrome processes and waits for quiescence;
9. stops packet capture and tracing in a bounded cleanup sequence;
10. validates raw artifacts and runs analysis;
11. atomically publishes indexes, summaries, and the terminal Session state.

Controls that would change evidence semantics are locked during this lifecycle. The UI cannot switch the core, profile, TUN, tracing, service, or system-proxy state in the middle of a job.

## Analysis topology

The canonical analysis is evidence-based and layered:

```text
CDP request and timing records
           +
NetLog request-to-socket and transport records
           |
           v
request resolution and pre-proxy transport identity
           +
Mihomo versioned logical-flow and dial events
           |
           v
canonical request and connection indexes
           +
TUN/physical PCAP reconciliation
           |
           v
coverage, integrity, egress, and packet-evidence summaries
```

URL attribution and transport correlation are separate stages. One connection can serve multiple requests and URLs; one proxy transport can carry multiple logical flows. The data model retains both relationships instead of forcing a connection ID to equal a URL.

## Logical flows and physical carriers

Mihomo emits logical proxy-flow evidence separately from physical carrier
lifecycles. Exclusive protocols commonly create one socket per logical flow.
Hysteria2 instead multiplexes logical TCP streams and UDP associations over a
long-lived QUIC/UDP carrier. TrafficTracer records this as a many-to-one binding
with a stable carrier ID, generation, protocol, relation, and complete observed
path set.

A Hysteria2 port hop updates the carrier path set without inventing a new logical
flow. A successfully replaced carrier receives a new generation. Carrier evidence
is embedded in every logical bind, so a carrier opened before the current trace
file remains attributable. Shared encrypted carrier packets are stored once and
referenced by each logical connection; they are not falsely divided into unique
per-stream packet captures.

## Failure and uncertainty model

TrafficTracer distinguishes orchestration state from evidence quality:

- a `completed` job finished its lifecycle and wrote valid outputs;
- a completed Session may be `degraded` when the target was cache-only, browser-internal, unreachable, or insufficiently observed;
- a rejected or failed-before-socket flow can be correct with no post-proxy tuple;
- a shared post-proxy transport is correct but non-one-to-one;
- an unexpected missing post-flow is a quality failure, not silently treated as direct traffic;
- unmatched evidence is retained with reason codes.

Interruption is cooperative, resumable, and stage-aware. The process registry terminates only managed children. Recovery journals let the Worker mark abandoned active work as interrupted and resume eligible batches without fabricating completion.

## TUN and tracing ownership

Clash Verge owns the desired proxy and TUN configuration. The effective runtime interface is resolved from the controller and operating system during diagnostics and capture. The default TrafficTracer expectation is `Meta`, but an explicitly configured active device can override it.

TrafficTracer owns the tracing lifecycle for capture jobs. It enables tracing at capture start with a Session-specific output and disables/finalizes it during cleanup. A separate Settings toggle would create conflicting owners and is intentionally absent.

## Version and protocol authority

The component lock pins:

- TrafficTracer product version;
- Mihomo and Clash Verge source commits;
- the service release, archive checksum, and IPC protocol compatibility;
- Worker, Job, Session, Flow, request, connection, PCAP, batch, and Mihomo tracing schema versions.

Machine-readable payloads are validated against `contracts/`. A package also records exact commits in `COMPONENTS`, product and bundle identity in `VERSION`, and dependencies in `SBOM.cdx.json`.

## Security and privacy boundaries

Capture output can contain complete URLs, addresses, timing data, DNS data, and payload-independent packet metadata. Store it in a user-controlled directory with appropriate permissions. Do not commit Sessions, browser profiles, real proxy profiles, controller secrets, subscription URLs, signing keys, or capture data.

The release audit extracts both package formats and checks expected executables, filesystem permissions, escaping symlinks, sensitive filenames, common secret patterns, component revisions, checksums, notices, and SBOM consistency.

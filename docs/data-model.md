# Sessions and Correlation Data

TrafficTracer stores each page visit as a versioned Session. A timestamped capture group contains one or more page Sessions and is the unit selected by the UI for browsing and batch recovery.

## Directory layout

```text
<session-root>/
└── 20260813-093042-765/
    ├── batch-manifest.json                # present for a YAML batch
    └── example.com/
        ├── main-page__https_example.com/
        │   ├── session.json
        │   ├── recovery.json              # only while recovery state is needed
        │   ├── raw/
        │   │   ├── tun.pcap
        │   │   ├── phys.pcap
        │   │   ├── mihomo-trace.jsonl
        │   │   ├── proxy-info.json
        │   │   ├── cdp.json
        │   │   ├── netlog.json
        │   │   └── capture-context.json
        │   └── analysis/
        │       ├── connection-index-v2.json
        │       ├── request-index-v2.json
        │       ├── flow-index.json
        │       ├── pcap-index-v1.json
        │       ├── summary.json
        │       ├── correlation.json
        │       └── connections/            # immediate in Full, on demand in Standard
        └── video-play1__https_example.com_video_1/
            └── ...
```

Exact raw filenames are registered in `session.json`; consumers should use the artifact list instead of assuming every optional file exists. Analysis generations are immutable. Re-analysis publishes a new generation and updates the manifest rather than overwriting a prior result in place.

The currently published generation appears at `analysis/`. Re-analysis builds in a generation-specific staging directory and atomically replaces the published view only after validation succeeds; artifacts record their generation UUID.

The layout intentionally avoids directories keyed only by opaque connection IDs. Domain, page type, and readable URL identify page Sessions; stable connection IDs live inside canonical indexes.

## Session manifest

`session.json` is the authoritative Session record. Schema v2 includes:

- Session and Job UUIDs;
- lifecycle state and timestamps;
- absolute Session directory;
- target URL, domain, and manual or YAML provenance;
- TrafficTracer, Mihomo, UI, and Worker protocol versions;
- registered artifacts with phase, role, relative path, size, optional hash, and analysis generation;
- warnings and structured terminal errors.

Valid lifecycle states are:

```text
created -> preparing -> capturing -> analyzing -> completed
                                          |        |
                                          v        v
                                       failed   cancelled

active state abandoned by a prior Worker -> interrupted
```

State transitions and manifests are written atomically. A corrupt Session means the selected Session manifest or required artifact is invalid; unrelated directories under the output root are not treated as Sessions.

## Evidence layers

TrafficTracer does not infer the full pipeline from one source.

| Layer | Evidence |
| --- | --- |
| Request | CDP request ID, URL, resource type, initiator, timing, response, cache and Service Worker flags |
| Browser transport | NetLog socket and transport events, endpoints, timing, DNS and reuse relationships |
| Pre-proxy flow | Mihomo inbound logical-flow tuple and/or browser/TUN transport evidence |
| Routing outcome | Mihomo selected chain, proxy type, terminal state, reject/failure classification, bytes and duration |
| Post-proxy flow | Mihomo dialer socket tuple, reconciled with physical-side packet evidence |
| Packet evidence | Raw TUN and physical PCAP plus derived filters or per-connection PCAP artifacts |

Every canonical record keeps evidence and match metadata so downstream users can distinguish observed facts from correlation decisions.

## Request index

`request-index-v2.json` is URL-centric. It maps browser requests to a canonical connection when evidence is sufficient and records ambiguity or non-network behavior when it is not.

Important fields include:

- request and Session identity;
- complete URL and target relationship;
- resource and document role;
- `network_observation`;
- connection resolution and unmatched reason;
- attribution evidence and timing.

For playback-enabled targets, `raw/capture-context.json` and
`analysis/summary.json` also preserve the fixed observation window, phase
durations, visible-skip attempts, primary-content duration, and quality result.

`network_observation` can be:

- `network`;
- `disk_cache`;
- `service_worker`;
- `prefetch_cache`;
- `browser_internal`;
- `local_endpoint`;
- `failed_before_socket`;
- `not_dispatched`;
- `unknown`.

Cache hints do not override stronger socket evidence. If NetLog proves that a real transport existed, the request remains a network observation.

## Connection index

`connection-index-v2.json` is transport-centric. A canonical connection contains:

- stable `connection_id`;
- protocol;
- `pre_flow`;
- `post_flow` or `null`;
- selected proxy node, type, chain, and route semantics when available;
- terminal status and normalized error class;
- request IDs, a primary URL, and all associated URLs;
- sharing and multiplexing flags;
- attribution scope and evidence;
- match method, score, ambiguity, and unmatched reason;
- packet-evidence status.

Request and connection identity are deliberately separate. HTTP/2, HTTP/3, keep-alive, browser pooling, and proxy multiplexing can create many-to-one relationships.

## Five-tuples

A flow tuple is:

```text
protocol, source IP, source port, destination IP, destination port
```

`pre_flow` describes the logical connection entering the proxy boundary. `post_flow` describes the outbound socket visible on the physical side after routing and proxy encapsulation.

For direct traffic, the post-proxy destination normally remains the original destination while the source reflects the physical socket. For proxied traffic, the post-proxy destination is typically the selected proxy server. For rejected, failed-before-socket, or local/not-applicable traffic, no outbound socket exists and `post_flow` is correctly `null`.

The query API accepts a pre-proxy tuple and returns all matching logical flows. It does not promise one result because reused or ambiguous observations can produce multiple candidates.

## Post-flow disposition

`post_flow_disposition` prevents all missing post-flows from being treated as the same error:

| Value | Meaning |
| --- | --- |
| `with_post_flow` | An outbound socket tuple was observed. |
| `explicit_no_socket` | Routing intentionally produced no socket, such as reject. |
| `failed_before_socket` | An attempted route failed before a usable outbound socket existed. |
| `local_not_applicable` | The target was a local endpoint; external egress is not applicable. |
| `unexpected_missing` | Egress should have existed, but required post-flow evidence is missing. |

Only `unexpected_missing` is counted as an unexplained egress gap.

## Attribution scope

`attribution_scope` answers whether a logical connection belongs to the requested page:

| Scope | Meaning |
| --- | --- |
| `page_attributed` | Connected to a selected page request through browser evidence. |
| `browser_background` | Browser traffic observed in the same managed capture but not attributed to the page. |
| `capture_unattributed` | Seen in capture or Mihomo evidence without enough browser identity. |
| `local_internal` | Local control, loopback, or internal traffic. |

Coverage for the page should be evaluated on `page_attributed` traffic. Background and capture-unattributed records remain available for auditing but must not inflate page coverage.

## Shared transports

`post_flow.shared=true` means the outer physical transport is reused by more than one logical flow. The same warning can also be expressed through the connection sharing object, including request multiplexing and outer-connection reuse.

Shared transport is not a correlation failure. TrafficTracer preserves the logical pre-proxy flow, shared outer tuple, associated URLs, and non-one-to-one warning. Packet bytes on that outer transport cannot always be uniquely assigned to one inner request.

## Match and ambiguity semantics

Correlation combines exact IDs, endpoints, protocol, timing windows, NetLog dependency relationships, Mihomo event sequence, and reuse evidence. Match metadata records the selected method and confidence.

Unmatched reasons include:

- `missing_pre_flow`;
- `missing_post_flow`;
- `no_candidate`;
- `multiple_candidates`;
- `insufficient_time`;
- `unsupported_protocol`.

TrafficTracer retains ambiguous requests and candidates rather than selecting a URL without sufficient evidence.

## PCAP index and storage modes

`pcap-index-v1.json` records whether packet extraction was requested, applicable, successful, shared, or unavailable for each canonical connection.

`Standard` mode keeps both raw PCAP files and all canonical indexes but does not immediately duplicate packets into one pre/post file pair per connection. The UI can request packet verification later, creating a new analysis generation.

A timestamp-group split is still a sequence of per-Session analyses, not one merged capture. Completion is authoritative only when the Session and published evidence agree: the Session is completed schema v2; the PCAP index validates and names the same Session; its split mode is `unique_connections`; its generation matches the manifest artifact; and every successful side is a regular in-Session file registered in that generation. No requested side may remain `not_requested`.

The UI exposes `unsplit`, `complete`, `complete_empty`, `partial`, `stale`, `raw_missing`, and `ineligible`. `complete_empty` is a successful terminal result with no eligible logical connections. `partial` means at least one side reported an extraction failure. `stale` means published metadata, generation, or files disagree. Merely finding an `analysis/pcap/` directory never proves completion.

`packet-split-manifest.json` is an operational checkpoint for group progress and cancellation. The per-Session manifest plus PCAP index remain the source of truth for idempotency, so recovery always rescans actual published evidence.

`Full` mode performs per-connection extraction during analysis. It is useful when downstream tools require ready-to-open filters, but it consumes more storage and does not make shared transports one-to-one.

## Coverage and integrity

The summary separates metrics that answer different questions:

- raw artifact integrity;
- browser request observation;
- request-to-connection attribution;
- transport correlation;
- page-attributed logical flows;
- egress establishment;
- expected versus unexpected missing post-flows;
- packet evidence applicability and availability;
- direct, proxy, reject, failure, and local outcome counts;
- temporal evidence coverage.

A single overall percentage would hide important distinctions. For example, all observed transports may be correlated while the target document is cache-only, or all page connections may be attributed while several proxy dials fail before a socket.

## Legacy projections

`correlation.json` and older schema-v1 views are compatibility projections. New consumers should use the v2 request and connection indexes plus the PCAP index. Consistency checks verify that legacy projections do not contradict canonical data.

Old schema-v1 Sessions remain readable and can be re-analyzed when their raw artifacts are available. Re-analysis never changes the recorded target provenance or raw capture files.


## Scenario outcome

A configured browser scenario is evaluated separately from flow integrity.
YouTube playback Sessions include scenario_outcome in analysis/summary.json
with passed, degraded, or indeterminate state, the bounded primary-content
duration, the configured goal, and a machine-readable reason. A degraded
scenario does not invalidate otherwise consistent request, connection, flow, or
PCAP indexes.

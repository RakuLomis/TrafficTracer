# Deferred Multi-Tab Capture Design

## Status

This is a non-normative post-1.0 design note, not an implemented feature.
TrafficTracer Complete 1.0 supports isolated single-tab capture only. Every
selected `sites[]` target owns one Chrome process, one Session, one NetLog, one
pair of packet captures, and one Mihomo trace window. Targets execute serially,
and the Worker verifies that the managed Chrome process exits before starting
the next target.

The current lifecycle remains the default because it provides clear evidence
boundaries, isolated cold-cache profiles, bounded cleanup, and target-level
recovery.

## Intended scenario

A future multi-tab mode could keep related pages open in one browser process so
they share cookies, cache, Service Workers, HTTP/2 or HTTP/3 sessions, and
background connections. A typical group could contain a site main page and
several video pages.

Shared transports are part of the result. The implementation must not create
per-page results by copying or independently analyzing the same process-wide
NetLog and PCAP files.

## Possible configuration

Existing YAML remains valid and retains isolated-process behavior. A future
schema could add named browser groups:

```yaml
schema_version: 2

browser_groups:
  bilibili-tabs:
    observe_seconds: 60
    tab_open_delay_seconds: 2

sites:
  - domain: bilibili.com
    url: https://www.bilibili.com/
    page_type: main-page
    browser_group: bilibili-tabs
    tab_order: 1

  - domain: bilibili.com
    url: https://www.bilibili.com/video/example
    page_type: video-play1
    browser_group: bilibili-tabs
    tab_order: 2
```

Proposed rules:

- the UI offers `Isolated process` and `Multi-tab groups` modes;
- isolated mode preserves current behavior and ignores grouping;
- multi-tab mode runs selected targets with the same `browser_group` in one
  Chrome process;
- ungrouped targets remain singleton groups;
- tabs open serially in YAML or `tab_order` order and remain open until the
  group observation window ends;
- `wait_load_timeout` remains tab-specific;
- `observe_seconds` is group-specific, avoiding an ambiguous reinterpretation
  of the current per-target `wait` field;
- grouping is never inferred from a shared domain.

The first implementation should not navigate tabs concurrently. Deterministic
opening order makes lifecycle failures reproducible while retaining ongoing
traffic from previously opened tabs.

## Capture lifecycle

One group owns one instance of every process-wide resource:

1. checkpoint the group job;
2. enable Mihomo tracing with a group capture identity;
3. start TUN and physical-interface packet capture;
4. launch one owned Chrome process and one CDP collector;
5. create and navigate tabs in deterministic order;
6. observe all open tabs for the group window;
7. serialize CDP data before closing Chrome;
8. close Chrome and finalize NetLog;
9. stop packet capture and persist the Mihomo trace barrier;
10. analyze shared evidence once and publish per-tab projections.

Cancellation and recovery boundaries become browser groups. An interrupted
group should restart from its beginning rather than reattach to an unknown
surviving browser state. Cold cache means one fresh profile per group; warm
cache means an explicitly reusable group profile.

## CDP and analysis requirements

The collector already attaches to page and iframe targets, but a production
multi-tab implementation also needs:

- a stable configured `tab_id` mapped to CDP session and target IDs;
- one navigation record per tab rather than one global `visit_url`;
- response and completion maps keyed by `(CDP session or target ID,
  requestId)`, because `requestId` alone is not a safe cross-target identity;
- immutable target history after target destruction;
- explicit classification of worker, Service Worker, browser-background, and
  otherwise unattributed traffic;
- per-tab and group-level quality summaries.

Canonical analysis must be group-scoped:

```text
group raw evidence
        |
        v
canonical request and connection indexes
        |
        +-- tab ID -> request keys
        +-- request keys -> connection IDs
        +-- connection ID -> tab IDs and URLs
```

A shared TCP, QUIC, proxy, or multiplexed outer connection appears once and
retains every associated tab ID, request key, and URL. Page results are
projections of that canonical index. Mihomo does not need browser tab IDs; it
continues to provide logical pre-proxy flows, route outcomes, and post-routing
sockets, which TrafficTracer joins to browser evidence through CDP and NetLog.

## Storage direction

Process-wide raw artifacts need one owner. A possible layout is:

```text
<capture-timestamp>/
├── _browser-groups/<group-id>/
│   ├── group-manifest.json
│   ├── raw/
│   └── analysis/
└── <domain>/<page-type>__<url-slug>/
    ├── session.json
    └── analysis/
```

The group manifest owns shared CDP, NetLog, trace, and PCAP artifacts. Page
Sessions reference the group without copying raw data. This preserves the
timestamp/domain/page browsing model while keeping ownership and statistics
consistent.

## Acceptance boundary

An eventual implementation requires coordinated Worker, contract, Session,
analysis, Clash Verge UI, recovery, and test changes. The Mihomo tracing
protocol should normally remain unchanged. It is acceptable only when:

- old YAML and single-tab Sessions retain current behavior;
- each tab resolves to its requests after navigation and destruction;
- request identities cannot collide across targets;
- shared connections are counted once and retain all page relationships;
- direct, proxied, rejected, failed, and internal outcomes keep their existing
  evidence-bounded semantics;
- cancellation cleans up only owned processes;
- recovery resumes at a group boundary;
- real HTTP/2, HTTP/3, WebSocket, and background-traffic fixtures pass
  consistency validation.

Until then, TrafficTracer Complete documents and supports isolated single-tab
capture only.

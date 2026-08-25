# Capture Startup and Session-Store Efficiency Atomic Plan

## 1. Goal and measured baseline

Reduce the time between accepting a capture request and navigating the first
page without weakening cold-cache isolation, crash recovery, Session
validation, flow correlation, packet evidence, or owned-process cleanup.

This is a measured scaling problem. In the 2026-08-24 64-target experiment, the
batch was accepted in less than one second, but first navigation began roughly
73 seconds later. The output root contained about 882 Session manifests and
82 GB of data on a rotational SATA disk. On that host:

- `SessionStore.scan()` took about 10 seconds;
- `SessionStore.get(session_id)` took about 8.8 seconds;
- adjacent trace, tshark, and Chrome startup stages had 9-13 second gaps;
- about 1,799 Chrome profile directories occupied 787 MB below the output root.

The primary success criterion is that capture history size no longer makes the
per-Session preparation path progressively slower.

### 1.1 Implementation checkpoint (2026-08-25)

The first implementation batch is complete:

- TT-PERF-001 emits monotonic job, stage, and operation timing in progress
  events. Worker recovery logs include their duration, and successful
  `batch.start` responses include parse, config verification, proxy-protocol
  freeze, and job-accept timing.
- TT-PERF-002 provides `scripts/benchmark-session-store.py`, a deterministic,
  unprivileged fixture with 1,000 Sessions across capture groups, one corrupt
  manifest, a duplicate identity, and an interrupted Session.
- TT-PERF-003 routes capture-owned recovery writes and cleanup through a
  containment-checked, known-Session-directory API without a global lookup.

The 1,000-Session, three-repetition temporary-filesystem baseline measured the
following medians on this host. These values diagnose scaling and are not CI
pass/fail thresholds:

| Operation | Median |
| --- | ---: |
| Store construction | 0.042 ms |
| Full scan | 1,126.901 ms |
| Scoped scan | 115.583 ms |
| ID-based `get()` | 1,127.066 ms |
| Legacy ID-based artifact lookup | 1,128.582 ms |
| Known-Session artifact lookup | 1.200 ms |
| Job-to-scope lookup | 567.474 ms |
| Recovery discovery | 1,174.255 ms |

The direct recovery path is about 940 times faster in this synthetic fixture.
The remaining global scan costs were intentionally left visible for the next
catalog tasks. The correctness suite passed 555 tests after this batch.

### 1.2 In-memory catalog checkpoint (2026-08-25)

TT-PERF-004 adds a Worker-lifetime in-memory catalog indexed by manifest path,
Session ID, job ID, and scope ID. Cache hits validate the selected manifest
fingerprint without enumerating unrelated capture groups. `save()` and
`delete()` update the catalog immediately; missing entries trigger discovery;
explicit full-history scans still rebuild from authoritative manifests; and
scope scans reconcile only the selected timestamp directory.

Using the same 1,000-Session, three-repetition fixture, the before/after
medians were:

| Operation | Before TT-PERF-004 | After TT-PERF-004 |
| --- | ---: | ---: |
| ID-based `get()` | 1,127.066 ms | 0.049 ms |
| Legacy ID-based artifact lookup | 1,128.582 ms | 0.145 ms |
| Job-to-scope lookup | 567.474 ms | 0.225 ms |
| Known-Session artifact lookup | 1.200 ms | 1.175 ms |
| Full scan | 1,126.901 ms | 1,231.197 ms |
| Recovery discovery | 1,174.255 ms | 1,266.650 ms |

The selected-Session hot paths no longer scale with unrelated history. Full
scan and recovery discovery intentionally remain disk-bound until
TT-PERF-005 and TT-PERF-006 add persistent metadata and indexed recovery
candidates. Tests cover catalog hits, immediate saves, moved and removed
Sessions, manifest replacement and corruption, duplicate Session IDs, and
job lookup. The complete correctness suite passed 560 tests.

### 1.3 Persistent catalog and indexed recovery checkpoint (2026-08-25)

TT-PERF-005 persists a versioned lightweight catalog under
`.session-catalog/catalog-v1.json`. It is bound to the canonical output-root
path and filesystem identity. An unchanged root loads Session, job, scope,
state, recovery-marker, path, and manifest-fingerprint metadata without
materializing historical manifests. Root and capture-group discovery
fingerprints trigger reconciliation; selected manifest fingerprints still
fail closed on replacement, removal, movement, corruption, or identity change.
Corrupt manifest records remain visible across warm starts.

TT-PERF-006 indexes non-terminal Sessions and durable atomic-analysis recovery
markers. Analysis staging is registered before work begins and cleared only
after UUID-owned staging and backup directories are gone. Normal Worker
recovery materializes recovery candidates instead of every terminal Session.
Worker recovery logs include catalog operation timing.

TT-PERF-007 performs catalog-first pagination. `session.list` and scoped
history select the requested slice before loading manifests and summaries. A
30-Session regression proves a five-item page materializes exactly five
manifests and reuses them on repeated access.

On the 1,000-Session fixture, warm catalog `get()` measured 27.932 ms including
catalog construction and selected-manifest validation, while indexed recovery
discovery measured 26.934 ms. The complete suite passed 567 tests.

### 1.4 Profile lifecycle and UI checkpoint (2026-08-25)

TT-PERF-008 and TT-PERF-009 move cold Chrome profiles out of the evidence root
into a private, application-owned runtime scratch root. Every removable path is
marker-bound to an exact Session UUID, symlink and broad-directory checks fail
closed, normal cleanup waits for process-group quiescence, and recovery removes
only journaled owned profiles. Cleanup failures are bounded and visible.

CV-PERF-001 consumes Worker timing in Clash Verge. The latest Job stage,
operation, stage duration, operation duration, and total duration survive route
changes without resetting the timer. Worker recovery and catalog reconciliation
timings are persisted separately. CV-PERF-002 keeps normal history on catalog
pages, cancels stale page/detail requests, and defers the intentionally global
five-tuple search until the user submits that query. The modified frontend
passed type checking, lint, and 36 tests.

The first integration pass exposed stale E2E assumptions from the legacy
`logs/` and `captures/` layout. DIRECT, TUN, and recovery fixtures now use
normalized `raw/` inputs, atomic `analysis/` outputs, and the canonical v2
connection index. DIRECT capture/correlation and crash recovery pass. Recovery
also now distinguishes reusable `warm/<domain>/<page>` profiles from removable
`cold/<domain>/<session UUID>` profiles; warm profiles survive a Worker crash
without degrading recovery, while unknown marked layouts still fail closed.

## 2. Confirmed causes

### 2.1 Repeated global Session lookup

`SessionStore.get()` searches every managed manifest. `artifact_path()` calls
`get()` even when the caller already owns a validated Session context. Recovery
persistence calls `artifact_path()` after tracing, TUN tshark,
physical-interface tshark, and Chrome ownership changes. Every safety
checkpoint therefore repeats an output-root-wide lookup.

### 2.2 Full startup recovery scan

Worker recovery parses every Session manifest and inspects analysis workspaces
for terminal historical Sessions. This cost grows with the lifetime of the
output directory and is paid on Worker start or output-root switch.

### 2.3 Cold Chrome profile I/O

Cold mode correctly disables cache, bypasses service workers, and uses a unique
profile for every Session. Profiles currently share the rotational evidence
disk with packet captures and analysis output, increasing profile creation and
Chrome state latency.

### 2.4 Eager history work

Job-to-Session and scope resolution still contain full scans. Complete history
must remain available, but it need not block capture startup or be repeatedly
deserialized.

## 3. Non-negotiable invariants

1. Cold mode keeps a new profile, disabled cache, and service-worker bypass.
2. Recovery is durably updated whenever owned process or tracing state changes.
3. Stale, duplicate, moved, malformed, or externally edited manifests are not
   silently trusted.
4. Legacy Sessions remain readable when no index exists.
5. Index identity is bound to the canonical output root.
6. Cleanup never targets Clash Verge, Mihomo, a user browser, or unrelated
   tshark process.
7. Raw PCAP, NetLog, CDP, trace, correlation, flow IDs, and carrier semantics do
   not change.
8. Performance failures remain visible and never bypass correctness checks.

## 4. Target architecture

Introduce an output-root-scoped `SessionCatalog` owned by the Worker:

- `session_id -> manifest path and lightweight metadata`;
- `job_id -> session_id`;
- `scope_id -> ordered Session identities`;
- state, manifest size, and modification fingerprint;
- known recovery-journal and atomic-analysis-workspace state.

The catalog has an in-memory view and an atomically published on-disk cache in a
reserved metadata directory. Manifests remain authoritative. Catalog hits
validate path and fingerprint before load; misses perform bounded discovery and
repair. Duplicate IDs and corrupt manifests keep explicit errors.

Capture code holding a `CaptureSessionContext` writes recovery artifacts through
that already validated directory. Cold profiles move to an application-owned,
configurable scratch root, preferably on NVMe/runtime storage. They are removed
only after owned Chrome processes exit and recovery ownership is cleared.

## 5. Atomic implementation tasks

### TT-PERF-001: Stage timing instrumentation

**Status:** Implemented; host-level UI consumption remains in CV-PERF-001.

**Change**

- Measure Worker recovery, catalog load/rebuild, batch validation, Session
  creation, trace setup, both tshark starts, Chrome launch, CDP readiness,
  navigation, cleanup, analysis, and PCAP splitting with a monotonic clock.
- Emit structured timing through existing progress/log events.
- Use wall-clock timestamps only for audit presentation.

**Primary files**

- `traffictracer/worker/recovery.py`
- `traffictracer/worker/services.py`
- `traffictracer/capture/job.py`
- Worker event contracts and fixtures if fields are added

**Acceptance**

- Completed and failed Sessions expose every reached stage duration.
- Missing stages are explicit, not reported as zero.
- Instrumentation changes no state transition or capture artifact.

### TT-PERF-002: Reproducible scaling benchmark

**Status:** Implemented as an opt-in script with a functional correctness test.

**Change**

- Create an unprivileged fixture with at least 1,000 terminal Sessions, multiple
  groups, corrupt entries, a duplicate identity, and an interrupted Session.
- Benchmark cold construction, warm load, `get`, `artifact_path`, scoped list,
  job lookup, and recovery discovery.
- Record the scan-based implementation as baseline.

**Primary files**

- `test/test_session_store_benchmark.py`
- `scripts/benchmark-session-store.py`

**Acceptance**

- Benchmark results are deterministic and require no capture privileges.
- Correctness CI does not use unreliable host-dependent timing assertions.

### TT-PERF-003: Direct recovery-artifact path

**Status:** Implemented and covered by path-containment, mismatched-context,
and zero-global-lookup tests.

**Change**

- Add a containment-checked API accepting a loaded manifest or
  `CaptureSessionContext`.
- Use it in `_persist_recovery()` and `_clear_recovery()`.
- Keep the ID-based artifact API for external Worker requests.

**Acceptance**

- Trace, two tshark processes, and Chrome start with zero global Session scans.
- Journals retain exact PID, start token, process group, and profile identity.
- Path escape and mismatched-context tests fail closed.

### TT-PERF-004: In-memory Session catalog

**Status:** Implemented; persistent startup reuse is deferred to TT-PERF-005.

**Dependencies:** TT-PERF-002.

**Change**

- Index Session ID, job ID, and scope.
- Update indexes after `create()` and `save()`.
- Route `get()`, `scope_for_job()`, `_session_for_job()`, and scoped lists through
  the catalog.
- Preserve duplicate-ID and corruption behavior.

**Acceptance**

- Repeated `get()` does not enumerate unrelated groups.
- Transitions are immediately visible.
- Tests cover moved, removed, replaced, corrupt, and duplicate manifests.

### TT-PERF-005: Persistent catalog and incremental reconciliation

**Status:** Implemented with root binding, warm reconciliation, corruption
fallback, and disposable-cache rebuild coverage.

**Dependencies:** TT-PERF-004.

**Change**

- Persist versioned lightweight metadata atomically under a reserved directory.
- Bind it to the canonical output-root identity.
- On startup, validate inexpensive fingerprints, discover new groups, and parse
  only changed entries.
- Rebuild when absent, corrupt, incompatible, or root-mismatched, with visible
  progress.

**Acceptance**

- A legacy root performs one full migration scan.
- An unchanged subsequent start does not deserialize all manifests.
- Removing the catalog affects performance only and triggers safe rebuild.

### TT-PERF-006: Indexed recovery candidates

**Status:** Implemented with durable analysis-workspace ownership markers.

**Dependencies:** TT-PERF-005.

**Change**

- Normal startup examines non-terminal Sessions, known recovery journals, and
  registered incomplete analysis publications.
- Register durable analysis staging/backup state and clear it only after atomic
  publication.
- Retain a manual full audit and automatic legacy migration scan.

**Acceptance**

- Unchanged terminal history requires no per-Session workspace inspection.
- Existing crash-injection stages remain recoverable.
- A stale marker causes conservative inspection, never silent cleanup.

### TT-PERF-007: Paginated and lazy history services

**Status:** Implemented in Worker Session list services; dependent UI request
cancellation remains in CV-PERF-002.

**Dependencies:** TT-PERF-004.

**Change**

- Serve stable capture-group and Session pages from catalog metadata.
- Load full manifest and summary only for a selected Session.
- Invalidate only the affected scope after a transition.

**Acceptance**

- Opening TrafficTracer does not deserialize all historical summaries.
- Active capture events remain independent of history refresh latency.

### TT-PERF-008: Configurable owned profile scratch root

**Status:** Implemented with an application-owned runtime default and the
`TRAFFICTRACER_CHROME_PROFILE_ROOT` diagnostic override.

**Dependencies:** TT-PERF-001.

**Change**

- Separate Chrome scratch profiles from the evidence output root.
- Default to an application-owned Linux runtime/cache path with an absolute
  diagnostic override.
- Persist the resolved profile in recovery.
- Keep cold profiles unique; preserve warm reuse semantics.

**Acceptance**

- Cold cache/service-worker tests are unchanged.
- Evidence remains in the selected output root.
- Ownership validation rejects broad, symlinked, or user browser directories.

### TT-PERF-009: Safe profile lifecycle

**Status:** Implemented for Complete cold profiles with quiescence-gated normal
cleanup, bounded visible failures, and journal-driven crash recovery cleanup.

**Dependencies:** TT-PERF-008.

**Change**

- Remove owned cold profiles only after the complete owned process group exits
  and its journal may be cleared.
- Preserve journaled profiles after interruption/crash for recovery.
- Add inspectable bounded cleanup retries.

**Acceptance**

- Normal Sessions do not accumulate cold profiles.
- Fault injection proves unrelated profiles are never touched.

### CV-PERF-001: Persistent startup-stage display

**Status:** Implemented with persisted Job progress and Worker startup timing.

**Dependencies:** TT-PERF-001.

**Change**

- Display preparation stage and elapsed time.
- Persist the last stage and failure across route changes.
- Distinguish catalog migration, recovery, tshark, Chrome, page observation,
  analysis, and split work.

**Acceptance**

- Users can identify the active stage without logs.
- Route changes do not reset or duplicate the timer.

### CV-PERF-002: Lazy capture-history UI

**Status:** Implemented with on-demand global flow search and stale query
cancellation.

**Dependencies:** TT-PERF-007.

**Change**

- Consume paginated history and fetch detail only for the selected group/page.
- Cancel stale requests when output root or selection changes.

**Acceptance**

- A 1,000-Session fixture does not block the UI thread.
- Active progress remains responsive while history loads.

### INT-PERF-001: Correctness regression

**Status:** Implemented for unprivileged and isolated gates; privileged TUN
execution remains an explicit host-network test.

Run capture, recovery, resume, interruption, protocol observation, correlation,
and packet-split suites. Add crash points after each catalog/profile transition.

**Acceptance**

- No request, flow, carrier, PCAP, or legacy Session contract regression.

### INT-PERF-002: Host-level before/after gate

**Status:** Catalog/recovery scaling gate passed. Real Chrome/TUN stage p95
remains to be collected from the next interactive capture experiment.

On the current Ubuntu 24.04 host, run at least five cold starts and five
subsequent starts with the same target and output root.

**Thresholds**

- Warm catalog `get()` p95 below 50 ms with 1,000 Sessions.
- No output-root-wide scan from Session creation to trace enable.
- Unchanged-root Worker recovery p95 below 3 seconds, excluding controller
  unavailability.
- Capture acceptance to trace enable p95 below 5 seconds.
- Trace enable to CDP readiness p95 below 12 seconds with scratch profiles on
  NVMe; page/network load is reported separately.

Misses block release or require an evidence-backed plan revision. They must not
be hidden by increasing timeouts.

The five-repetition 1,000-Session fixture measured warm catalog `get()` at
27.800-29.685 ms and indexed recovery discovery at 27.135-27.867 ms on this
host. Both are below their thresholds. The DIRECT E2E gate passed, but its fake
Chrome intentionally does not claim the real-CDP startup thresholds.

### INT-PERF-003: Documentation and package verification

**Status:** Operations documentation and component/build checks are complete.
Versioned package publication is deferred until these cross-repository changes
are committed so package provenance never labels dirty source as an old commit.

- Update Operations with catalog migration and profile scratch behavior.
- Add rollback notes.
- Build versioned Linux Deb and AppImage packages.
- Run package smoke, recovery, component-lock, and release-audit gates.

## 6. Implementation order

1. TT-PERF-001 and TT-PERF-002.
2. TT-PERF-003 for the smallest immediate hot-path improvement.
3. TT-PERF-004 and TT-PERF-005.
4. TT-PERF-006 and TT-PERF-007.
5. TT-PERF-008 and TT-PERF-009.
6. CV-PERF-001 and CV-PERF-002.
7. INT-PERF-001 through INT-PERF-003.

Each task should be committed independently unless a serialized contract needs
an atomic cross-repository pin update. TrafficTracer work must pass before its
dependent Clash Verge UI task begins.

## 7. Rollback and compatibility

- Catalog data is disposable derived metadata; removal triggers rebuild.
- Manifests and evidence remain authoritative and are not migrated in place.
- Recovery accepts old profile paths until old journals are terminal.
- Reconciliation failure enters visible degraded mode and may fall back to a
  full scan, but capture cannot start with unresolved active ownership.
- Rolling back to 1.0.9 remains possible because canonical Session schemas do
  not change.

## 8. Out of scope

- PCAP compression or retention reduction.
- Reusing cold profiles or weakening cache isolation.
- Parallel URL capture or packet splitting.
- Proxy selection, correlation, or protocol state-machine changes.
- Silently changing the user-selected evidence directory.

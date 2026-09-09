# UI stability validation work plan

This plan follows the two-hour native-component observation documented in
`native-event-bridge-soak.md`. It does not authorize starting the production
application, changing proxy selection, or mutating capture datasets during
isolated testing.

## Atomic tasks

| ID | Status | Deliverable | Acceptance |
| --- | --- | --- | --- |
| STABLE-01 | Implemented | Monotonic deadline and time-based health rules in the isolated Cargo example | Sampling delay neither extends the intended deadline nor changes the ten-second stall threshold; startup grace is real elapsed time |
| STABLE-02 | Implemented and verified | Versioned running/passed/failed/interrupted reports, atomic report replacement, explicit process exit status, negative-test runner | Normal and delayed runs exit zero; stalled and early-close runs exit nonzero; missing reports cannot pass the runner |
| STABLE-03 | Implemented; five-minute native gate passed | Isolated actual TrafficTracer page with synthetic controller/Worker interfaces | Mount the page, switch away/back, select group history, open Session details; reject unexpected IPC instead of touching real services |
| STABLE-04 | Implemented; combined five-minute native gate passed | Lifecycle and delayed-response scenarios | Completion/failure/cancel/Resume remain consistent; late old responses do not overwrite the selected task; repeated polling does not accumulate |
| STABLE-05 | Implemented; short-run counters/resource review passed | Retention counters and resource review | Inspect listeners, timers, in-flight calls, query caches and view records; correlate with process-family trends; fix demonstrated retention only |
| STABLE-06 | Not passed: heartbeat stall at 39 minutes; diagnostic follow-up in progress | Clean long-run gates and installer handoff | Short positive/negative tests, corrected two-hour run, full-page long run, then installer and user-controlled real-data Resume validation |

## Implemented monitor contract

- `seconds` is intended wall-clock duration, not the number of samples.
- All elapsed-time comparisons use `Instant`. The observer ends at its deadline;
  event generation remains active until the final observation is complete.
- Samples include `sample_index`, actual elapsed seconds/milliseconds, and the
  first failure with a reason and elapsed time. Health rules distinguish JS,
  heartbeat, event and render failures. Later symptoms do not replace the first.
- Clone the heartbeat snapshot before scanning `/proc` or writing files, so the
  observer does not hold the heartbeat mutex during slow I/O.
- Reports have schema version 2 and explicit status. A `running` report or a
  missing/unreadable report is never a pass. Early ordinary window closure
  produces `interrupted`; an external SIGKILL may leave `running`, which the
  test runner rejects.
- `run_return` returns control to the example; the example chooses its exit
  code from the validated completion state rather than relying on the default
  platform exit path.
- Report replacement uses a temporary sibling and rename. A write failure
  cannot set the success flag. No old observation report is rewritten.

## Regression commands

Run from the sibling UI repository, not its embedded historical checkout:

```bash
pnpm exec vite build --config tests/ui-soak/vite.config.mts
CARGO_BUILD_JOBS=2 cargo test --manifest-path src-tauri/Cargo.toml \
  --example traffictracer-ui-soak --offline
CARGO_BUILD_JOBS=2 cargo build --manifest-path src-tauri/Cargo.toml \
  --example traffictracer-ui-soak --offline
node scripts/test-native-soak.mjs
```

The runner invokes only the isolated example. It executes four scenarios
serially, bounds each run, checks both JSON outcome and child exit code, and
prints one summary per scenario. It does not run as part of the general Node
unit-test glob, which should not unexpectedly open native windows.

Four deterministic monitor unit tests passed after STABLE-01. Native regression
results are recorded in `native-event-bridge-soak.md`. Completion of these first
two tasks does not mean that the remaining page/lifecycle/long-run gates passed.

## Page and subscription fixes on 2026-09-09

New tests reproduced production frontend defects before their fixes:

1. An in-flight status read could overwrite a successful interruption with the
   previous running state. A stale read failure could similarly reintroduce a
   start-failure alert after a successful Resume.
2. `Promise.all` registration lost the cleanup handles of successful listeners
   when any sibling registration failed. The negative test observed zero of
   four expected cleanup calls.
3. A queued progress callback after unmount could overwrite a completed cached
   job with an analyzing state.

The page now invalidates earlier status requests at both edges of a lifecycle
operation, pauses new polling while the operation is pending, and ignores stale
success/error responses. It also guards duplicate operations synchronously and
disables pipeline history selection during an operation.

Capture Job, Worker and both Session subscription hooks now use per-registration
ownership. Successful and late registrations are cleaned independently of any
sibling failure. Disposal is idempotent, one cleanup exception does not prevent
others from being released, and disposed callbacks do not mutate state/storage
or invalidate queries.

Validation:

- Ten page-orchestration tests cover interruption, cancellation, Resume,
  restoration, delayed polling, stale errors, persistent current errors,
  history-selector locking and repeated mounts. Twenty-five mount/unmount
  cycles return the page timer count to zero after each unmount.
- Three Capture Job lifecycle tests and three subscription-ownership unit tests
  cover partial registration failure, late callbacks, late successful
  registrations, repeated disposal and cleanup exceptions.
- All 61 frontend tests (13 suites), targeted ESLint, TypeScript checking and
  the production frontend build passed. No installer was produced.

Coverage limitation: `page-lifecycle.test.tsx` mounts the real page orchestrator
and its MUI pipeline controls, but deliberately replaces child workspaces and
Worker hooks with test doubles. It is not the native full-page gate. Session
detail/history interaction in the actual WebKit page, query-cache/resource
trends under combined workloads, and the clean long-run gates remain open.
Production Clash Verge PID 4165912 remained unchanged. No capture dataset or
proxy configuration was modified.

## Native full-page gate on 2026-09-09

STABLE-03 now mounts the actual TrafficTracer page, child workspaces and hooks
inside the isolated native window. Profile hooks, file dialogs, paths and
controller commands use explicit synthetic boundaries. Production React Query
defaults are retained. Unknown controller commands fail closed; the native host
registers only reporting and a no-op UI heartbeat, never capture/proxy commands.

The five-minute run exited zero and passed the independent full-page report
validator: 25,973 received notifications, 23 remounts, 23 detail dialogs, 23
pagination actions, 12 Capture Group selections and 11 pipeline selections.
There were zero JS errors, denied commands or error-boundary failures. Report:
`/tmp/traffictracer-native-soak-2339817-1788920719720166/result.json`.

Four report-validator tests, dedicated TypeScript checking and targeted ESLint
are part of the short gate. The validator rejects a native `passed` result if
either history interaction or the required page coverage is absent.

The earlier paragraph about mocked child workspaces applies only to the Vitest
orchestration suite, not this new native mode. At that stage, remaining work was:
STABLE-04 delayed/faulted native lifecycle scenarios, STABLE-05 retention review
under those workloads, and STABLE-06 clean multi-hour gates and installer
handoff. This run uses twelve synthetic Sessions and empty analysis indexes;
it does not validate real capture/analysis throughput or large result payloads.

## Delayed reads, recovery and bounded details

Additional regression tests reproduced three frontend gaps before correction:

- Closing details while three index reads remained pending left all three
  queries in the cache despite `gcTime: 0`. Query functions now consume the
  cancellation signal and reject late results after abandonment. Tests cover
  late completion, twelve abandoned detail views and another observer retaining
  a shared read. This cancels frontend observation, not backend analysis or an
  already submitted IPC operation.
- Interrupt/Cancel errors only reached a transient notice. Both now use the
  persisted workspace failure record, survive navigation and clear after a
  successful retry. Existing action fences continue to reject old status reads.
- Connection details rendered every index row. With 201 requests and 201
  connections the regression observed 404 table rows. Both tables now paginate
  at 50 records, retaining access to every record and computing summary values
  from the complete indexes. Pages clamp after shorter refreshed results and
  reset when the selected Session changes. No stored artifact is truncated.

The `slow_recovery` native fixture adds 2.5-second status reads, injected read
failures and synthetic Resume outcomes. Alternating detail reads finish before
or after the dialog closes. Its expanded workload uses 1,000 requests and 1,000
connections per detail view. Counters check native-listener ownership after
each unmount, in-flight fixture calls, cached analysis queries and rendered
table rows. Timer disposal remains covered by deterministic page tests.

The initial 100-second slow-read run (before adding populated indexes) passed:
`/tmp/traffictracer-native-soak-2435981-1788921752837774/result.json`.
It observed six injected status failures, five synthetic Resume calls and eight
clean subscription baselines. That historical report does not contain the
new populated-index coverage counters required by the current validator.

All 68 frontend tests across fourteen suites passed, as did five report-validator
tests. The production frontend build and both TypeScript checks passed. The
native combined gate then passed for five minutes, independently verified from
`/tmp/traffictracer-native-soak-2489607-1788922325528870/result.json`:
26,281 notifications, 24 remounts, 24 clean subscription baselines, 16 injected
status failures, 16 Resume attempts, eight observed error-clear transitions and
48 populated-index reads. The peak rendered data-row count was 100. JS errors,
error boundaries and unexpected commands remained zero; maximum heartbeat gap
was 2,002 ms. Native exit code was zero.

Post-warmup query counts ranged from 17 to 23, owned subscriptions from 1 to 10,
and native descriptors from 59 to 60. Family RSS sums ranged from 547,372 to
708,056 KiB. These short-run measurements do not establish leak freedom.
STABLE-06 remains open: a clean multi-hour run, installer build and a
user-controlled real-data Resume validation. Existing production PID 4165912
was unchanged and no capture dataset was modified.

## STABLE-06 execution

The latest frontend was rebuilt with `TT_SOAK_PAGE=full` and
`TT_SOAK_SCENARIO=slow_recovery`, then embedded in the isolated Cargo example.
The 7,200-second low-output runner started with report directory
`/tmp/traffictracer-native-soak-2661166-1788924179147445`.
This entry records a running test, not a pass. Review its final report, process
exit and resource trends before building the installer. Production PID 4165912
remains outside the test scope.

The run did **not** pass. The first failing sample was at 2,344,333 ms
(`HEARTBEAT_STALLED`), and the longest observed heartbeat gap was 36,779 ms.
The native observer continued sampling; JS errors and subscription-cleanup
failures stayed zero. The UI later resumed advancing. This is not proof of a
permanent deadlock, memory exhaustion, or any specific WebKit defect.

After reviewing 2,602 samples through second 2,607, only isolated PID 2661166
was stopped with SIGTERM. The runner exited nonzero. The original `result.json`
still says `running` because the prior observer only finalized at its deadline;
it has not been rewritten. `review.json` records the review separately and the
first failing sample remains in `samples.jsonl`. Production PID 4165912 stayed
running. Installer construction is deferred until the gate is resolved.

Regression checks in parallel with this observation passed: 56 targeted Python
tests, 119 Rust TrafficTracer unit/contract tests and seven fake-Worker
integration tests. They do not override the failed UI observation.

Diagnostic follow-up (no production workaround yet):

1. Persist failure and stop observing at the first failed sample, with a bounded
   exit watchdog, instead of waiting for the remaining multi-hour deadline.
2. Add a bounded native-main-loop pulse and an event-triggered JS probe separate
   from the page driver's timer. Record driver stage/age, frame age, document
   visibility/focus and bounded visibility changes.
3. Record test-process CPU ticks and major faults alongside RSS.
4. Inject timer-driver and JS-main-thread stalls independently, verify the
   resulting diagnostics and keep the ten-second failure threshold unchanged.
5. Repeat the positive short gate before another long observation. Real-data
   Resume and installer handoff remain pending; never treat recovery as a pass.

The diagnostic implementation passed both native negative controls: a stopped
driver retained a fresh JS event probe (634 ms), while a blocked JS main thread
left that probe stale (9,807 ms); the native-main-loop pulse remained 1,002 ms
old in both. Both reports persisted `failed` and exited with code 1 at about
31 seconds, ahead of their 50-second deadlines. Two diagnostic-validator unit
tests and four monitor unit tests passed.

The diagnostic-enabled normal 100-second full-page run also passed:
`/tmp/traffictracer-native-soak-2881535-1788927319553093/result.json`.
It received 8,808 events, completed eight clean remounts and recorded no JS
errors. Its maximum heartbeat gap was 1,038 ms, with final native/JS probe gaps
of 770/796 ms. The independent full-page validator passed. None of these short
controls identifies the cause of the earlier 39-minute incident; a new long
run with the added probes is still required.

# Isolated native event-bridge soak

## Scope

The `traffictracer-ui-soak` Cargo example in the sibling UI repository starts
Tauri/WebKit with the production `WorkerProcess` event bridge and an in-memory
fake child. It never calls `app_lib::run`, initializes the proxy/service,
imports profiles, toggles system proxy/TUN, or starts a real capture Worker.

The default mode exercises the native event bridge and React progress component.
The optional full-page mode mounts the actual TrafficTracer page with synthetic
controller responses. Neither mode runs the pipeline supervisor, browser capture
or analysis workload. A pass is not full-application stability validation.

## Isolation

- Separate configuration directory: `src-tauri/soak/tauri.conf.json`.
  Tauri resolves configuration by directory; a differently named JSON file in
  the production configuration directory is not sufficient isolation.
- Identifier: `local.traffictracer.isolated-soak`.
- A single dedicated `soak` window; unexpected window configuration aborts
  before the builder starts.
- Each run creates a new `traffictracer-native-soak-*` temporary report directory
  and configures separate WebView storage.
- Application IPC is limited to `soak_heartbeat`, `soak_probe`, the production
  read-only desktop heartbeat monitor, and progress/notification/recovery receipt
  and snapshot-confirmation handlers. No proxy/service/capture command handlers
  or application plugins are registered. The heartbeat is no longer a no-op.
- The isolated React entry has no remote resources. Its listener uses the production
  event name and the generator uses the production Worker API version constant.
- The harness can use the existing graphical display without starting a second
  production Clash Verge instance. Do not replace this command with the normal
  application executable.

## Run

From `/data/ytluo/projects/clash-verge-rev`:

```bash
pnpm exec vite build --config tests/ui-soak/vite.config.mts
pnpm exec tsc --project tests/ui-soak/tsconfig.json

CARGO_BUILD_JOBS=2 cargo build --manifest-path src-tauri/Cargo.toml \
  --example traffictracer-ui-soak --offline

# Short gate before any long run:
target/debug/examples/traffictracer-ui-soak 60

# Only after reviewing the short gate and available resources:
target/debug/examples/traffictracer-ui-soak 7200
```

The harness prints `SOAK_REPORT_DIR`. Read `result.json` there; do not infer
success merely from a window appearing. `samples.jsonl` records one sample per
second. Retain reports until the test has been reviewed.
Require both a passed persisted report and a zero process exit code. The
historical two-hour run below returned zero despite `passed: false`; schema 2
corrects that exit behavior without changing the original report.

## Workload and observations

- Approximately 100 generated progress notifications per second.
- JS IPC heartbeat every second; actual `TrafficTracerJobProgress` React/MUI
  rendering driven by native notifications.
- Component unmount/remount and event unsubscription/resubscription every five
  seconds. Late listener registration is disposed after unmount.
- A bounded 100-entry event history.
- Failure on JS errors, heartbeat gaps over ten seconds after startup grace,
  prolonged lack of event or React commit progress, or no received events/remounts.
- Native-process and descendant-process RSS, thread count and file descriptor
  count are sampled. The Linux monitor traverses the isolated process's task
  children, including WebKit processes; it does not inspect production processes
  or process arguments. RSS sums double-count shared pages and are a trend
  indicator, not unique physical memory. Resource trends need human review;
  the pass flag alone is not a leak-free verdict.
- Reports use `scope: native_bridge_react_progress` and `full_ui_soak: false`.
  This explicitly excludes the full page, controller queries, pipeline history,
  slow real IPC and real analysis. Earlier reports retain their original scope.

The first 20-second invocation was deliberately rejected by the configuration
guard before creating a window. Another short invocation produced heartbeats
but zero events because the test generator used the old API version; it correctly
reported `passed: false`. The generator now imports `WORKER_API_VERSION`.

## Native regression reproduced on 2026-09-08

With the correct protocol version and the previously implemented background
emit path, a 60-second run stalled after approximately ten seconds. It received
806 events, completed one listener remount, and ended with a 50,328 ms heartbeat
gap. The independent monitor wrote a failed result even though the native
window could no longer process its exit request. Only the verified isolated
test PID was terminated; the production Clash Verge PID remained unchanged.

Report: `/tmp/traffictracer-native-soak-642397-1788857436728341/result.json`.

Local Tauri source inspection shows that emission holds the JS listener registry
while calling into the WebView, while listen/unlisten also needs that registry.
This supports a lock-order risk with off-main emission. Debugger attachment was
denied by system permissions, so no thread-stack proof of the precise lock cycle
or of the user's earlier production hang is claimed.

The production bridge now schedules the entire native emit on the main thread.
Its bounded blocking worker waits for completion, retaining the single global
permit; it does not enqueue unlimited callbacks when the main loop stalls.

The same 60-second workload then passed: 5,295 events, 11 remounts, zero JS errors,
and a maximum 1,000 ms heartbeat gap including startup.

Report: `/tmp/traffictracer-native-soak-678448-1788857818767927/result.json`.

The subsequent 300-second run passed with 26,673 received events, 59 listener
remounts, zero JS errors, and a maximum 1,000 ms heartbeat gap. Across 300
samples, native host RSS was 155,572–156,096 KiB, file descriptors 53–60, and
threads 31–37. These are host-process observations, not WebKit-family totals.

Report: `/tmp/traffictracer-native-soak-687188-1788857909824136/result.json`.
Samples: `/tmp/traffictracer-native-soak-687188-1788857909824136/samples.jsonl`.

After the main-thread emission change, 119 TrafficTracer Rust unit/contract
tests and seven fake-Worker integration tests passed. No installation or
production restart was performed. Five minutes is a regression check, not
completion of the planned multi-hour/full-React-UI gate.

## Remaining full-UI gate

The full-page entrypoint now exists (see below). Before claiming complete
long-run stability, exercise slow IPC, repeated pipeline completion and failure
recovery for hours. Do not run the production
startup path against the user's live proxy configuration to obtain that evidence.

## React component extension on 2026-09-08

The first 60-second React-component run passed: 5,137 notifications, 11 component
remounts, zero JS errors, and a maximum 2,000 ms heartbeat gap including startup.
The final rendered sequence was 5,214 and received sequence was 5,229; the
independent monitor also checks that commits keep advancing, rather than only
checking event reception. Events during intentional remount gaps are not
considered lossless-delivery tests.

Report: `/tmp/traffictracer-native-soak-1080989-1788862053968911/result.json`.
The final process-family RSS sum was 619,548 KiB across the host and two WebKit
children. This is not comparable to the earlier host-only 152 MiB figure.

The subsequent 300-second React run also passed: 26,409 notifications, 59
component remounts, zero JS errors, a final rendered sequence of 26,501 and a
maximum heartbeat gap of 1,040 ms. It exited normally. From second 30 onward,
process-family RSS sums ranged from 576,420 to 667,016 KiB; the final sum was
664,568 KiB. Fluctuations included decreases, but five minutes and RSS alone
cannot exclude long-term retention or a leak.

Report: `/tmp/traffictracer-native-soak-1088173-1788862131787638/result.json`.
Samples: `/tmp/traffictracer-native-soak-1088173-1788862131787638/samples.jsonl`.

Validation after this extension: dedicated TypeScript typecheck and ESLint
passed; two Hook suites (three tests), 119 Rust unit/contract tests and seven
Worker integration tests passed. The running production Clash Verge PID
remained 4165912. No installer was built, production process restarted, or
capture dataset changed. Full-page and multi-hour validation remain pending.

## Two-hour observation on 2026-09-08

Report: `/tmp/traffictracer-native-soak-1563226-1788867151608551/result.json`.
The run recorded 7,200 samples, 643,432 received events, 1,435 component remounts,
zero JS errors and a maximum heartbeat gap of 2,000 ms including startup.
No native-window heartbeat stall was observed. Production PID 4165912 remained
unchanged, and the isolated window exited without forced termination.

**The raw report is failed, not passed.** Its first failure is the final sample.
The generator used a wall-clock deadline, whereas the observer repeated
`sleep(1s)` plus sampling work 7,200 times. Sampling overhead accumulated, so
the generator stopped while the observer still had about eleven samples left.
Sequence 643,747 remained unchanged from sample 7,189 through 7,200; heartbeats
continued every second (final gap 29 ms), and React committed the final sequence.
The eleventh unchanged sample triggered the event-stall threshold. This is a
harness end-of-run timing defect, not evidence that the UI became unresponsive.
The original report must not be rewritten or represented as a clean long-soak
pass.

The harness now stops generation only after monitoring finishes. It records
actual wall-clock elapsed milliseconds separately from sample count, plus
event/render stagnation counters. `TT_SOAK_SAMPLE_DELAY_MS` (0 by default,
maximum 1,000) allows a short sampling-drift regression test:

```bash
# Historical drift-reproduction command; see schema-2 semantics below.
TT_SOAK_SAMPLE_DELAY_MS=800 target/debug/examples/traffictracer-ui-soak 30
```

The corrected drift regression passed: 30 samples over 54,046 ms, 4,711
received events, ten remounts, zero JS errors and a maximum 1,000 ms heartbeat
gap. Report:
`/tmp/traffictracer-native-soak-1758048-1788874494210103/result.json`.
This checks the timing fix under forced overhead; it does not replace a fresh
two-hour run.

Post-warmup process-family RSS sums ranged from 581,404 to 839,592 KiB, ending
at 603,136 KiB. Native-host RSS stayed near 157,700 KiB and descriptors near
59–60. Family mean RSS was 637,609 KiB over samples 301–900 versus 738,343 KiB
over the final 600 samples. Repeated decreases rule out a simple monotonically
growing RSS trace, but the higher later mean is not proof of leak freedom.
WebKit allocation/retention still needs scrutiny in full-page validation.

Remaining gates: a clean long-soak report with the corrected harness, and the
full-page/controller/history/recovery scenarios already listed above. No
production behavior was changed during this monitoring turn.

## STABLE-01 / STABLE-02 completion

The current schema-2 harness uses a single monotonic observer deadline. Duration
arguments now mean actual seconds, rather than sample count. The delay command
above therefore runs about 30 seconds with fewer samples; the historical
54-second result remains unchanged. Event generation stops after the final
observation. Stall and startup-grace checks use actual elapsed milliseconds.
Heartbeat snapshots are copied before `/proc` reads and report writes.

Reports now record `running`, `passed`, `failed` or `interrupted`, along with
first-failure reason/time. The native example uses `run_return` and explicitly
exits nonzero unless successful report completion was confirmed. A new serial
runner checks both report and exit code:

```bash
node scripts/test-native-soak.mjs
```

All four native scenarios passed their expected assertions:

| Scenario | Report status | Exit code | Report directory under `/tmp` |
| --- | --- | --- | --- |
| Normal 20-second run | passed | 0 | `traffictracer-native-soak-1833771-1788882016522875` |
| 800 ms additional sampling delay | passed | 0 | `traffictracer-native-soak-1834037-1788882036852152` |
| Injected event stall | failed (`EVENT_STALLED`) | 1 | `traffictracer-native-soak-1834323-1788882057194322` |
| Injected early window close | interrupted | 1 | `traffictracer-native-soak-1834723-1788882077489692` |

Each directory contains `result.json`. Four deterministic monitor unit tests,
the runner's ESLint check and whitespace checks also passed. These results
complete the test-foundation repair, not the outstanding full-page or clean
two-hour gate. See `ui-stability-validation-plan.md` for remaining atomic tasks.

## Full-page native mode on 2026-09-09

From the sibling UI repository:

```bash
TT_SOAK_PAGE=full pnpm exec vite build --config tests/ui-soak/vite.config.mts
pnpm exec tsc --noEmit -p tests/ui-soak/tsconfig.json
CARGO_BUILD_JOBS=2 cargo build --manifest-path src-tauri/Cargo.toml \
  --example traffictracer-ui-soak --offline
timeout --signal=TERM --kill-after=10s 330s \
  target/debug/examples/traffictracer-ui-soak 300
# Replace REPORT_DIRECTORY with the printed SOAK_REPORT_DIR:
node scripts/verify-full-page-soak.mjs REPORT_DIRECTORY
node --test scripts/verify-full-page-soak.test.mjs
```

Rebuild the frontend without `TT_SOAK_PAGE=full`, then rebuild the example,
before using the component-only four-scenario runner. Native assets are embedded
at build time. Full-page coverage needs enough time for both history selectors;
the component runner's twenty-second normal case is not a full-page gate.

The full mode renders the actual page, Capture Job, Session list/detail,
analysis and history components with production query-cache defaults. It uses
twelve synthetic Sessions, two completed batches and two completed pipelines.
Every cycle opens/closes details, paginates, selects one history and unmounts/
remounts the page. A separate native event listener and rendered progress
observations distinguish received events from UI updates.

Only explicit read-only fixture commands are supported. Unexpected commands
throw and increment a failure counter. A build-time guard checks that command
replacement occurred, and the native host exposes no production controller
handlers. Profile hooks, paths and file dialogs are also isolated. The bootstrap
reports early JS failures before the main React heartbeat exists.

Both the 40-second gate and the five-minute run exited zero. Five-minute report:
`/tmp/traffictracer-native-soak-2339817-1788920719720166/result.json`.
The independent validator also passed, requiring `mode: full`, both history
selection counters, details, pagination, remounts, full elapsed duration and no
errors. Four validator unit tests reject incomplete or falsely passed reports.

- Duration: 300,001 ms; 300 samples; 25,973 notifications received.
- Page remounts: 23; detail dialogs: 23; pagination actions: 23.
- Capture Group selections: 12; pipeline selections: 11.
- JS errors, denied commands and error-boundary failures: zero.
- Maximum heartbeat gap: 5,581 ms, below the ten-second failure threshold.
- After second 30, family RSS sums ranged from 543,620 to 686,300 KiB;
  query-cache entries ranged from 17 to 23; native descriptors from 59 to 60.
  Final family RSS was 637,236 KiB. These are observations, not a leak verdict.

Earlier failed fixture runs are retained, not relabeled as passes. They exposed
missing synthetic timestamps, an omitted preview command and a native DOM
history-selector mismatch; the fixtures and selector were corrected before
the successful gates. This does not establish those as production defects.

This scope is `native_full_page_mocked_backend`, with `full_ui_soak: true`.
It excludes large real analysis indexes, actual capture/analysis work, slow
controller responses and native failure/recovery scenarios. Full-page rendering
coverage completed STABLE-03. At that point, STABLE-04/05 and multi-hour
STABLE-06 gates remained open; see the combined workload below for subsequent
short-gate results. No installer or production restart was performed.

## Combined delayed-recovery and populated-index workload

Build this mode explicitly; the scenario is embedded in the frontend assets:

```bash
TT_SOAK_PAGE=full TT_SOAK_SCENARIO=slow_recovery \
  pnpm exec vite build --config tests/ui-soak/vite.config.mts
CARGO_BUILD_JOBS=2 cargo build --manifest-path src-tauri/Cargo.toml \
  --example traffictracer-ui-soak --offline
node scripts/run-full-page-soak.mjs 300
node scripts/verify-full-page-soak.mjs REPORT_DIRECTORY
# After the short gate and resource review, the same runner accepts 7200.
# Do not run it concurrently with another native soak.
```

The low-output runner prints the report location at startup and one final
summary. It checks the requested duration, process exit, correct embedded
scenario and independent full-page coverage. A deadline guard affects only the
isolated process it created. Per-second evidence remains in `samples.jsonl`;
there is no need to stream it into the terminal or a conversation.

This scenario injects 2.5-second pipeline status reads and periodic status
failures. The page driver clicks the actual Resume button against a synthetic
controller. Index reads alternate between 100 ms and three seconds, so some
complete after the detail window closes. Each populated index contains 1,000
records. The fixture creates those objects in JS, not through real filesystem
reads or production IPC serialization; it tests rendering/retention, not backend
index-loading throughput. No real pipeline action is dispatched.

The native event adapter still delegates listen/unlisten to Tauri. Its counters
measure owned registration handles (not WebKit's internal listener registry).
After unmount, only the independent test listener may remain. The independent
report validator requires successful cleanup checks, observed error/recovery,
populated-index reads and at most 100 rendered data rows across both tables.
Current production tables retain the complete indexes but render 50 records
per page. Query-cache and in-flight counters supplement process-family RSS;
none alone establishes leak freedom.

The populated-index 300-second gate passed and exited zero. Report:
`/tmp/traffictracer-native-soak-2489607-1788922325528870/result.json`.
Independent validation confirmed 26,281 received events, 24 remounts and detail
visits, 24 clean listener baselines, 16 injected status failures, 16 Resume
attempts and eight observed error-clear transitions. There were 48 populated
index reads, with at most 100 data rows rendered at once. Maximum heartbeat gap
was 2,002 ms; JS errors and denied commands were zero.

After warmup, family RSS sums ranged from 547,372 to 708,056 KiB, query entries
from 17 to 23, owned subscriptions from 1 to 10 and native descriptors from 59
to 60. Analysis-query counts ranged from zero to six during key transitions;
the observed count did not grow with detail cycles. In-flight fixture calls
peaked at five over the run. This is a short regression gate, not proof about
multi-hour WebKit retention or real backend analysis performance.

The low-output runner was also exercised end-to-end for 100 seconds and exited
zero: `/tmp/traffictracer-native-soak-2520735-1788922678596145/result.json`.
It validated the embedded slow-recovery scenario, both history selectors,
populated indexes, error/recovery observations and eight clean unmounts. This
checks the automation entrypoint; it does not replace the pending long run.

## Failed long observation and diagnostic follow-up

The 7,200-second run started under
`/tmp/traffictracer-native-soak-2661166-1788924179147445` did not pass.
At 2,344,333 ms, the original health monitor recorded `HEARTBEAT_STALLED`.
The largest gap later reached 36,779 ms. The native observer kept sampling and
the UI eventually resumed; JS errors and listener-cleanup failures remained
zero. Before the incident, post-warmup process-family RSS ranged roughly from
578 to 703 MiB, with query counts between 14 and 20. These observations do not
prove a deadlock, a leak or an environmental cause.

Debugger attachment to the isolated WebKit process was denied by the host.
Only isolated PID 2661166 was stopped with SIGTERM after collecting 2,602
samples through second 2,607. Production PID 4165912 was unchanged. The original
`result.json` remains `running`, not passed: the old observer only finalized at
its planned deadline. Raw samples were retained and a separate `review.json`
records the failed observation and deliberate stop. Do not relabel it a pass.

The current diagnostic harness stops at the first failing sample and writes its
failed report before requesting exit. The runner bounds a failed native exit
to fifteen seconds, so a blocked main loop cannot waste the rest of a long run.
This changes test reporting, not production behavior or the ten-second gate.

New independent evidence:

- A native-main-loop pulse with at most one queued callback.
- A native-event-triggered JS probe, single-flight and at most once per second,
  independent of the existing page-driver timer.
- Driver stage/age, animation-frame age/count, document visibility/focus and at
  most sixteen visibility transitions. A frame age is diagnostic only: hidden
  windows are not assumed to produce frames.
- CPU ticks and major page faults for the isolated process family only.

Two deliberate negative controls verified the distinction:

| Embedded scenario | First failure | Native pulse gap | Event probe gap | Report directory under `/tmp` |
| --- | --- | --- | --- | --- |
| `driver_stall` | Heartbeat stalled at 31,065 ms | 1,002 ms | 634 ms | `traffictracer-native-soak-2878898-1788927094112030` |
| `js_stall` | Heartbeat stalled at 31,066 ms | 1,002 ms | 9,807 ms | `traffictracer-native-soak-2879920-1788927177746457` |

Both exited with code 1 and finalized early. `driver_stall` intentionally stops
only the page driver while events/frames continue; `js_stall` blocks the isolated
JS main thread for twelve seconds. The event probe has a different one-second
phase from the driver, so its diagnostic negative-control comparison allows
that offset; the actual health threshold remains strictly ten seconds.

Build a negative control with `TT_SOAK_PAGE=full TT_SOAK_SCENARIO=driver_stall`
(or `js_stall`), rebuild the Cargo example, then run the isolated example for
50 seconds under an external timeout. Verify the expected failure with:

```bash
node scripts/verify-native-diagnostics.mjs REPORT_DIRECTORY driver_stall
node scripts/verify-native-diagnostics.mjs REPORT_DIRECTORY js_stall
node --test scripts/verify-native-diagnostics.test.mjs
```

Only invoke the verifier matching the embedded scenario. Rebuild with
`slow_recovery` before positive or long testing. No speculative production fix
or installer was produced in response to this insufficiently localized stall.

A stale event probe alone does not prove a JS deadlock: it also depends on event
delivery and the reporting IPC round trip. Interpret it together with native
pulse, driver stage, visibility and CPU observations; obtain thread stacks if
those signals remain ambiguous.

The diagnostic-enabled 100-second `slow_recovery` run passed independently:
`/tmp/traffictracer-native-soak-2881535-1788927319553093/result.json`.
It received 8,808 events, completed eight clean remounts and had a 1,038 ms
maximum heartbeat gap. The four original component controls were rebuilt and
rechecked after fail-fast reporting changed:

| Scenario | Status / exit | Report directory under `/tmp` |
| --- | --- | --- |
| Normal | passed / 0 | `traffictracer-native-soak-2883526-1788927514776676` |
| Sampling delay | passed / 0 | `traffictracer-native-soak-2883890-1788927535101621` |
| Event stall | failed / 1 | `traffictracer-native-soak-2884148-1788927555400046` |
| Early close | interrupted / 1 | `traffictracer-native-soak-2884417-1788927570731385` |

These controls passed their expected assertions. The unexplained long-run
incident remains unresolved and the installer gate remains closed.

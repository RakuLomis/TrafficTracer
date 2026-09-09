# Resume completion and UI responsiveness

## Evidence and scope (2026-09-08)

The September 7 pipeline reached `finished` on September 8 at 12:19:33
Asia/Shanghai: 174 completed, 16 degraded, and two failed runs. The final
analysis Worker exited normally. Logging stopped immediately after another
Worker started. The user confirmed an OS unresponsive-window dialog, not a
spontaneous process exit. The exact native blocking stack was not captured.

Automatic environment diagnosis could restart/switch the Worker after pipeline
completion. This is a verified lifecycle hazard, not proof of the specific
historical deadlock. The two SS retry failures were configuration fingerprint
drift, separate from the UI hang.

Do not restart the running proxy or mutate the real capture dataset for tests.
Do not weaken fingerprint checks or rebuild completed analysis implicitly.

## Atomic implementation status

| Task | Status | Implementation / remaining work |
| --- | --- | --- |
| RES-001 Lifecycle evidence | Partial | Startup/stop attempt ID, root, timestamp and stage retained in a bounded JSONL journal. Rotation and failed-rotation tests pass; complete trigger provenance before release. |
| RES-002 Passive UI refresh | Implemented | Environment diagnosis is explicit-only; mount, completion, focus and Worker notifications cannot start it. Cached reports remain displayable. |
| RES-003 Blocking isolation | Native regression reproduced and corrected; full UI soak pending | Pipe writes use one bounded blocking slot per client; deadline covers queue/write/response; state locks exclude pipe/native operations. Native emit runs on the main thread with acknowledgement to one process-wide blocking slot. The isolated native event-bridge test reproduced a hang with off-main emit and passed 60-second and 300-second retests after correction. |
| RES-004 Completion/cleanup states | Implemented and fault-tested | The real supervisor invokes a shared finalizer tested with isolated managers, locks and simulated children. Preserve idle Workers and completed results; retain the capture lock on timeout, unconfirmed exit or remaining jobs. UI displays persistent cleanup warnings. |
| RES-005 Configuration drift | Implemented | Save category hashes when binding a new candidate; report changed categories without values; distinguish unavailable fingerprint from actual drift. Old datasets without snapshots explicitly lack category evidence. Existing invariant remains strict. |
| RES-006 Artifact preservation | Implemented | Verify declared summary/request/connection artifacts exist within the Session, are nonempty, match recorded sizes and have consistent declared generations before accepting deferred-analysis completion. Missing/truncated/mixed-generation tests pass. Cleanup roundtrips preserve all 270 completed cells. |
| RES-007 Validation | In progress | Hook tests, blocked-pipe fault test, Rust contract tests and type checking; actual long-lived native UI validation and package build remain outstanding. |

## Behavioral changes

- Use **Check Environment** or its explicit retry action to refresh diagnostics.
  Reopening the page does not automatically start a Worker. Starting capture
  continues to use the backend's own preflight checks.
- `.worker-startup.json` remains the latest snapshot. `.worker-lifecycle.jsonl`
  retains startup stages across restarts with a 1 MiB rotation threshold and one
  previous journal. These files are diagnostic, never recovery authority.
- `candidate-N-runtime-diagnostic.json` stores schema version, whole-config
  fingerprint and category hashes only. No raw proxy values are stored.
- A blocking write cannot be forcibly cancelled by dropping its async caller.
  Its permit stays occupied until it returns, preventing repeated requests from
  spawning unlimited blocked writes. Failed process exit still blocks workspace
  replacement; this is intentional ownership protection.
- Task/history polling is single-flight: a slow IPC or filesystem response
  cannot enqueue another poll every second indefinitely.
- `cleanup` is optional metadata in the pipeline manifest. It never changes
  individual capture/analysis outcomes. A healthy idle Worker is retained,
  because Session browsing still uses its client. Abnormal cleanup is bounded;
  cleanup warnings survive page changes and application restart.
- Artifact checks use metadata, not full index reads or PCAP hashing. They
  detect missing/truncated/misbound outputs but do not prove content integrity
  against same-size corruption or changes made after verification.
- The fake-Worker soak covers 128 lifecycles and 4,096 routed requests, with
  confirmed graceful exits. It is accelerated churn, not a multi-hour real
  Chrome/WebKit/capture workload.

## Release gate

Passing unit tests does not prove the historical native UI hang is fixed.
Complete remaining tasks, run isolated long-duration UI/fault validation, and
build with an explicit sibling UI source path and unique package revision.
No live-data resume, installation, commit, push or package build is implied by
this implementation checkpoint.

### Validation checkpoint

- 119 TrafficTracer Rust unit/contract tests passed with the shared tracing and
  contract fixture paths configured. The initial invocation omitted these two
  environment variables; those two fixture gates passed on rerun.
- Seven fake-Worker integration tests passed (handshake, response routing,
  cancellation, progress, crash handling, clean shutdown and accelerated churn).
- Three targeted frontend hook tests passed, including explicit diagnosis,
  pipeline-active rejection, completion/invalidation/remount behavior, and
  release of large analysis query data.
- TypeScript checking, changed frontend-file ESLint, and `git diff --check`
  passed.
- The blocked-write test verifies a 50 ms request deadline against a simulated
  400 ms pipe write and verifies that state inspection remains responsive.
- A subsequent isolated native WebKit event-bridge harness was launched; see
  [native regression evidence](native-event-bridge-soak.md). Full production
  React UI and multi-hour capture stability have not yet been verified.

### Remaining stability gates

1. Cleanup timeout/lock retention is now tested through the production supervisor
   finalization function with isolated fake transports and persisted manifests.
   This does not launch the entire capture/controller-restoration workflow.
2. Lifecycle journal rotation tests are complete; startup trigger provenance
   remains to be completed.
3. Run an isolated native UI for hours with slow IPC, event bursts, repeated
   completion and page changes; measure RSS, event-loop latency and handle/thread
   counts. The 128-cycle fake test is not evidence of flat native memory usage.
4. Do not launch a second production-ID GUI against the user's live configuration
   or install/restart the proxy to perform this test without coordination.

### Step 1: automated failure-injection gate

Eight additional tests cover healthy idle retention, shutdown without a reply,
kill failure without an active job ID, kill without an exit event, confirmed
forced exit, lifecycle-lock stall, restart/rotation history, and failed rotation.
Cleanup cases reload completed/degraded runs from disk, verify Session IDs and
saved analysis bytes are unchanged, and verify that retained locks reject a new
pipeline owner. Tests use a 100 ms outer deadline; production retains 20 seconds.

Two defects found while building the gate were corrected:

- A missing active job ID no longer releases ownership after unsuccessful
  cleanup. An uncertain process exit conservatively retains the lock.
- Failed journal rotation no longer appends beyond the rotation threshold.
  The latest startup snapshot can still be updated independently.

All fixtures are created in unique temporary directories. No production Worker,
browser, proxy, capture dataset or subscription is touched by this gate.

The six supervisor cleanup scenarios also passed 20 consecutive repetitions
(120 scenario executions). This checks repeatability of failure handling, not
multi-hour native GUI stability. Changed-page ESLint and `git diff --check` pass.

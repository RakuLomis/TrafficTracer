# Bounded UI delivery after prolonged desktop locking

## Evidence and scope

The automatic-lock observation in `lock-screen-recovery-plan.md` reproduced a
nonresponsive WebKit view after unlock, with rising renderer CPU ticks and RSS.
Native main-loop probes remained responsive. Native `emit` completion is not a
JavaScript consumption acknowledgement. An event backlog remains a hypothesis,
not a demonstrated stack-level root cause.

Do not change capture data, connection information, analysis semantics, proxy
configuration or the running production process to address this UI problem.

## Atomic status

| Task | Current status |
| --- | --- |
| LOCK-007 | Progress production/coalescing/submission/ACK counters and in-flight age implemented |
| LOCK-008 | Non-progress notification journal now precedes broadcast; disk-failure fallback remains explicit |
| LOCK-009 | Progress and journaled non-progress UI delivery bounded; 100-second native mixed-load verification passed |
| LOCK-010 | Native notice, receipt ACK and mounted pipeline/history snapshot confirmation implemented; broader view coverage and failure recovery pending |
| LOCK-011 | Progress queue/frontend ACK regression and 100-second native foreground check passed; negative native and long-lock checks pending |
| LOCK-012 | 90-minute isolated observation recovered after 62m48s lock; real Worker analysis and installer remain pending |

## Implemented first stage

The process-wide progress gate keeps at most one latest pending payload and one
submitted sequence awaiting a JS receipt ACK. The existing mapper rejects
oversized progress notifications before the gate. Repeated pending progress is
replaced, not appended. This is presentation sampling, not modification of any
pcap, connection, analysis or result artifact. This UI assumes one active Worker
job; pending progress for that job is removed on its terminal notification.

The window-lifetime frontend listener registers before enabling the gate. It
ACKs `delivery_sequence` on actual receipt of a progress event. This proves JS
receipt only, not rendering completion. Native submission is also limited to
five progress events per second. Unknown/future/duplicate ACKs do not release
an outstanding different sequence. No ACK timeout silently releases a slot.
If ACK delivery fails, progress presentation stops safely rather than creating
an unbounded queue; reliable reconnect/re-registration recovery is still work
for LOCK-010. No automatic application restart or WebView reload is introduced.

Fresh confirmed system locking pauses progress submission. Unknown OS state
does not disable the receipt bound. A periodic bounded bridge flush delivers
the latest pending value after ACK/unlock without requiring a new Worker event.
ACK registration lives for the window lifetime, independent of page remounts;
the isolated full-page cleanup baseline therefore changes from one to two
listeners (diagnostics plus ACK).

Terminal events and logs retain their existing delivery paths. Their queues
are NOT covered by the new progress ACK bound. Therefore this first stage must
not be described as bounding all WebKit IPC or as completing the entire fix.

The paragraph above describes the first-stage implementation only. The fourth
stage below adds bounds for journaled non-progress notifications.

## Terminal correctness audit

Rust `WorkerManager::spawn_exit_monitor` independently consumes terminal Worker
notifications and updates Worker/capture-lock state. Python `JobManager._finish`
updates its in-memory snapshot before notifications; `get_job` is queryable.
This does not by itself prove durable recovery after Worker restart. Preserve
terminal/log notifications until session and pipeline persistence and recovery
coverage are audited.

Frontend `mergeTrafficTracerProgress` now preserves all authoritative terminal
states against delayed progress. This closes a race that becomes more important
when progress is coalesced or delivered after a desktop pause.

## Native recovery notification (second implementation stage)

The production native desktop monitor now accepts an injected AppHandle and
submits `traffictracer://desktop-recovery` on the native main thread after
detecting an unlock. Its window-lifetime frontend listener registers before
enabling delivery. No frontend heartbeat tick is required to receive this
notification. At most one generation is in flight; subsequent generations
coalesce to the latest. Only the matching ACK releases that slot. Unknown OS
state does not trigger unlocked delivery. A failed dispatch/ACK does not cause
unbounded retry or automatic slot release; explicit failure recovery remains
pending. No application reload or proxy restart is performed.

The frontend routes both native notifications and heartbeat fallback through
one window-lifetime generation deduplicator. An event triggers the existing
single-flight pipeline/history snapshot refresh. The native ACK currently means
receipt and dispatch of that refresh request, NOT completion of the snapshot
read. The following third stage adds a separate confirmation and progress gate.

The isolated page has three persistent listeners: diagnostic event probe,
progress ACK, and recovery notification. Tests must use this ownership baseline.
The isolated-only `recovery_signal` fault injects generation 1 into notification
delivery after 20 seconds without changing OS state or the heartbeat snapshot's
generation. It can verify notification-driven recovery independently of the
heartbeat fallback, without locking the user's desktop.

Additional audit: Python `WorkerRecoveryCoordinator._publish` sends a detailed
recovery report through `worker.log`; a complete durable copy of every such
notification has not been established. Logs must not be dropped or coalesced
indiscriminately. Worker in-memory terminal snapshots are also not proof of
cross-restart durability. Both paths remain unchanged pending the full audit.

## Snapshot confirmation (third implementation stage)

Mounted pipeline/history pollers register with a window-lifetime tracker. At a
new recovery generation every currently mounted reader becomes pending. Only
reads started in that generation can confirm it. A failed child-batch read,
failed history read, lifecycle-fenced/disposed result, or skipped read is not
success. A later successful poll can recover from a failed read. Reports
distinguish `pending`, `failed`, `complete` and `not_displayed` with participant
count; removing a reader changes the displayed scope rather than pretending
that its abandoned request succeeded.

Confirmation IPC is single-flight and coalesces to one latest report. A failed
send retains one report and retries on a later heartbeat/pageshow event, not in
an immediate loop. Rust rejects stale generations and inconsistent empty-scope
success reports. After an unlock, volatile progress remains gated until the
current displayed scope is complete or explicitly not displayed. The receipt
ACK alone does not release this gate. These states are included in diagnostics.

The confirmation scope is pipeline status (including its selected child batch)
and pipeline history. It does not certify all React Query caches, a standalone
Capture Job view, painted frames, or Python analysis completion. Native emit/receipt failure recovery
and expanding coverage to other views still need dedicated validation.

## Fourth stage: receipts, explicit dispatch failures and durable notifications

Progress, recovery and notification receipt ACKs now retain one latest receipt
and at most one IPC call. Failed receipt IPC retries every two seconds; received
data is not re-emitted merely because the ACK is late. Listener disposal removes
the retry timer. Explicit native dispatch/emit failures release the corresponding
slot for at most three retries; absent completion evidence does not release it.
Exhausted retry counters remain visible in diagnostics. Re-registering progress
or notification delivery resets its explicit-failure retry allowance, not an
unacknowledged in-flight event.

Worker startup opens a new owner-readable/writable JSONL file under
`<output_root>/diagnostics/worker-notifications/<pid>-<timestamp>.jsonl`.
Every non-progress notification is appended in full before it enters the
process broadcast stream. File I/O runs on the blocking pool, sequentially;
it does not wait for UI consumption. Responses and high-frequency progress are
not duplicated. Files are not overwritten or automatically rotated/deleted.
Flush provides normal process-exit persistence, not a power-loss/fsync promise.
Opening the journal must succeed before sidecar spawn. A runtime journal write
failure increments diagnostics and records the unsaved message to the existing
system log; that message takes the legacy UI path, never silently coalesces.
Disk failure thus explicitly degrades the non-progress bound/persistence claim;
it cannot guarantee storage when the filesystem is failing.

Journaled notification presentation has a separate lane: at most 32 pending
entries and one submitted event with its receipt. Repeated event-name/job pairs
coalesce, and excess old UI entries remain available in the journal. The lane
submits at most five entries per second and pauses while locked or while the
displayed snapshot scope is recovering. Receipt is emitted after the original
notification submission. Original Worker lifecycle consumers remain independent
and still receive the unmodified message. Terminal notifications supersede
pending running-state presentation for the same job; the frontend also rejects
late nonterminal state snapshots over a known terminal state.

No packet, connection or analysis artifact is removed. Journal replay is not an
automatic task restart mechanism. A crashed Worker's in-memory job state is not
recreated from this journal; existing session/pipeline recovery remains the
authority for Resume. The journal makes notification detail inspectable even
when intermediate UI entries are no longer presented.

## Validation results

Fourth-stage validation (2026-09-09):

- Full frontend suite: 87 tests in 21 files passed; TypeScript, targeted ESLint
  and tracked whitespace checks passed.
- Seven delivery unit tests and seven Worker integration tests passed. The
  pre-broadcast journal test also passed: all 100 notifications survived a
  lagging broadcast subscriber. Two additional notification tests then passed,
  verifying the three-explicit-failure retry limit and terminal supersession
  limited to the matching job (four notification-delivery tests total).
- Mixed native run retained at
  `/tmp/traffictracer-native-soak-132274-1788956525820592/result.json`.
  This run **failed**, not passed: strict foreground mode ended after 15.035
  seconds with `EVENT_STALLED`; the desktop was locked. Native main-loop gap
  was zero at the final sample, with zero JS errors and zero journal/dispatch
  failures. Progress retained one pending value and no in-flight value;
  non-progress presentation retained 32 entries and no in-flight entry.
  The journal contains 672 consecutive synthetic notifications, with no gaps,
  including logs and completion messages. UI coalescing therefore did not
  discard their archived detail. These observations do not establish unlock
  recovery: the run stopped before the scheduled recovery injection.
- The read-only `scripts/verify-bounded-ui-delivery.mjs` checker correctly
  rejects this failed run. Do not weaken its acceptance assertions to classify
  a locked foreground run as a pass. Repeat in an unlocked desktop, then run
  the separately coordinated prolonged-lock test.
- Production Clash Verge PID 4165912 remained running. The isolated test host
  exited. No production proxy settings, desktop lock state or installation
  were changed by this validation.

After the user unlocked the desktop, the mixed-load check was repeated:

- Report: `/tmp/traffictracer-native-soak-220268-1788957448656745/result.json`.
  Passed at 100.002 seconds, with no first failure, zero JS errors and zero
  listener cleanup failures. Maximum heartbeat gap: 1,030 ms.
- 8,883 progress notifications produced, 8,583 coalesced, and 299 submitted and
  acknowledged. One latest pending value and no in-flight value remained.
- All 4,441 generated non-progress notifications appear consecutively in the
  journal. The existing mapper suppresses excess log presentation before the
  bounded UI lane: that lane received 1,777 notifications, submitted 301,
  retained 32 and left 1,444 archived-only. No journal or dispatch failures.
- Injected recovery generation 1 was acknowledged, with a completed two-reader
  snapshot confirmation. Eight remount cleanup checks passed. The read-only
  mixed-load verifier passed, including per-sample queue bounds and journal
  sequence continuity. This is synthetic backend validation, not actual analysis.

### Prolonged-lock observation after bounded delivery

Artifacts: `/tmp/traffictracer-native-soak-268759-1788957966334575`.
The user authorized locking, manually unlocked, and confirmed that interaction
was normal. The isolated example ran for the full 5,400 seconds and exited on
its own deadline; its host and WebKit children exited without forced termination.
Production Clash Verge PID 4165912 remained running and unchanged.

Read-only session observations recorded:

- Lock: 2026-09-09 20:48:28 Asia/Shanghai.
- Unlock: 2026-09-09 21:51:16 Asia/Shanghai.
- Continuous lock: 3,768.352 seconds (62 minutes 48 seconds), within the
  two-second OS sampling resolution. Post-unlock observation: about 24m50s.
- Recovery receipt appeared about 996 ms after the first sampled OS unlock;
  the first complete two-reader snapshot appeared about 6,011 ms afterward.
  Sampling origins differ slightly; these are observational timings, not an SLA.
- During lock, progress pending count stayed at one and in-flight count at zero.
  Native main-loop gap never exceeded 1,017 ms. Across the whole run there were
  zero JS errors, dispatch failures or listener-cleanup failures. Final cleanup
  checks: 445; listener peak: 13.
- Process-family RSS during lock: 541,516–668,288 KiB (about 529–653 MiB).
  After unlock: 561,540–660,992 KiB, finishing at 621,976 KiB (about 607 MiB).
  This does not reproduce the previous roughly 2.16 GiB growth. RSS sums count
  shared pages multiple times; one run does not establish absence of leaks.
- After the first 30 seconds following unlock, maximum heartbeat gap was
  1,059 ms and maximum independent event-probe gap was 6,566 ms. The slow-recovery
  scenario deliberately pauses delivery during failed/pending snapshot reads.
  Progress resumed, reaching 4,629 submitted/acknowledged updates out of 476,524
  produced updates, with 471,894 coalesced and one latest pending value.
- The user later announced remote disconnection. Sampling continued and recorded
  no second lock before the deadline. This is not a second automatic-lock test.

**Preserve the raw result:** `status=diagnostic_only`, `passed=false`, exit code 1,
and `EVENT_STALLED` at 152.428 seconds. The progress event stream intentionally
paused during the confirmed lock, so the strict foreground event-stall rule
fired. The diagnostic mode retained it and continued until the fixed deadline.
This observation supports successful prolonged-lock recovery; it is not a clean
foreground-suite pass or proof of full-application analysis stability.

The final snapshot field is `failed`, from another deliberately injected read
failure about 214 ms before the deadline. A `complete` snapshot was observed
about 3.2 seconds before the deadline, and 651 post-unlock samples were complete.
Do not rewrite the final state or claim every snapshot succeeded. This run
exercises the progress lane, not the mixed non-progress workload; the separate
100-second mixed test above covers that workload.

Next acceptance gate: isolated real Worker analysis against copied fixtures,
followed by a freshly built installer and user validation of actual Resume/
analysis. Do not mutate original captures or switch/restart the user's proxy to
obtain this evidence. Broader snapshot-view and storage-failure cases remain
tracked separately; this observation does not close every atomic plan item.

Third-stage validation:

- Full frontend suite: 82 tests passed. After adding the confirmation retry case,
  17 focused native-recovery/tracker/page-lifecycle tests passed. TypeScript,
  targeted ESLint and tracked whitespace checks passed.
- Two Rust recovery-delivery tests passed, including receipt without completion,
  stale/invalid scope confirmation, failed reads and release after current success.
- Native injected-recovery run:
  `/tmp/traffictracer-native-soak-4186862-1788955037610213/result.json`.
  Passed at 100.002 seconds, exit zero, maximum heartbeat gap 1,021 ms, zero JS
  errors and cleanup failures. The first complete two-reader confirmation was
  observed at 27.082 seconds after injection at second 20. The run exercised
  pending, failed, not-displayed and complete reports as the simulated page
  remounted and delayed/failed reads resolved. Final confirmation was complete
  with two readers; progress continued after confirmation. 8,903 updates were
  produced, 8,603 coalesced and 299 submitted/acknowledged; one latest pending
  value and no in-flight progress remained at the deadline.

This validates the mounted pipeline/history confirmation path using synthetic
reads. It does not close the long-lock, real Worker, log/terminal delivery,
standalone view coverage or failed native dispatch/receipt-ACK work items.

Second-stage validation:

- 80 frontend tests in 18 suites passed; TypeScript and targeted ESLint passed.
- Rust recovery-delivery test passed: 9,999 generations coalesce behind one
  in-flight notice; incorrect ACK cannot release it.
- Native recovery-signal injection ran for 100.002 seconds, exit zero:
  `/tmp/traffictracer-native-soak-4128351-1788954407601097/result.json`.
  Assertions confirmed `fault=recovery_signal`, heartbeat unlock generation 0,
  frontend recovery count exactly 1, native recovery ACK 1, and no recovery
  notice left in flight. Maximum heartbeat gap 1,031 ms; zero JS errors or
  cleanup failures. Progress produced 8,904 updates, coalesced 8,417, submitted
  and acknowledged 486, leaving one latest pending value and no in-flight
  progress at the deadline. The listener peak was twelve (unmounted baseline
  three). No desktop lock or production proxy changes were used in this test.

This proves native notification receipt independently of heartbeat fallback,
not successful authoritative snapshot completion or prolonged-lock recovery.

- Full frontend suite: 76 tests passed; the subsequently added terminal-state
  protection was verified in the four-test Capture Job lifecycle suite.
- Rust progress queue: two tests passed, including 10,000 updates without ACK,
  wrong ACK handling, locked submission and pending progress cleared at terminal.
- TypeScript, targeted ESLint and tracked whitespace checks passed.
- Native full-page slow-recovery foreground run: 100 seconds, exit zero,
  report `/tmp/traffictracer-native-soak-4071445-1788953794850753/result.json`.
  8,889 produced progress events, 8,404 coalesced, 485 submitted and acknowledged;
  final pending/in-flight counts zero. Maximum heartbeat gap 2,002 ms. Zero JS
  errors, denied commands or cleanup failures; eight remount cleanup checks and
  sixteen populated index reads. Window-lifetime ACK accounts for the extra
  listener (active/peak eleven; unmounted baseline two).

This is an isolated native foreground check with a synthetic backend, not a
long-lock recovery or real analysis pass. Production PID 4165912 was unchanged.
No commit, push, production installation or installer build was performed.

## Remaining acceptance cases

Test ACK loss and registration failure, wrong/duplicate ACK, emission failure,
slow consumption, many progress updates, lock/unlock, terminal-over-progress
races and source-process replacement. Verify progress counters in a real native
window, then prolonged locking with a fixed deadline. Preserve raw failures.
Finally test actual long analysis; synthetic page success is insufficient.

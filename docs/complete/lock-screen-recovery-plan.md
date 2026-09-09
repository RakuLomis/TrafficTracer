# Lock-screen and remote-desktop recovery

## Objective

Keep backend work independent of UI scheduling. Distinguish an observed hidden
page from an unknown heartbeat stall; neither loss of focus nor a disconnected
remote client proves that WebKit suspended the page. Do not relax the existing
foreground health threshold to obtain a passing test.

The 2026-09-09 two-hour attempt stopped after a heartbeat failure around minute
39 (maximum observed gap 36.8 seconds). Native sampling continued. The user
subsequently reported disconnecting the remote desktop and probable automatic
locking. This is a hypothesis, not a confirmed cause. Preserve the original
report and its failed review.

## Atomic work and status

| Task | Status | Deliverable / gate |
| --- | --- | --- |
| LOCK-001 | Manual lock reproduced; unlock and automatic lock pending | Foreground, minimized, locked/unlocked, disconnected/reconnected observations using independent JS and native probes |
| LOCK-002 | Production lock evidence implemented; native acceptance pending | Evidence-based background/unknown/frontend/native-stall classification; raw failures remain immutable |
| LOCK-003 | Partial audit | UI heartbeat only warns; finish auditing backend supervision and event retention under an actual suspended view |
| LOCK-004 | Pipeline snapshot recovery implemented | Hidden polling pause, immediate return refresh, single-flight requests, bounded recovery demand, late-response fences and disposal |
| LOCK-005 | Unit regression started; native background gate pending | Separate foreground responsiveness from background task continuity and recovery |
| LOCK-006 | Pending | Short native controls, two-hour gate, candidate build, user-controlled real Resume |

## Implemented scope

### Native session evidence and recovery, 2026-09-09

The production UI heartbeat monitor now queries `loginctl show-session auto`
sequentially from the Rust runtime, with a 1.5-second timeout and kill-on-drop
for the query process. There is no desktop mutation. It accepts only the current
effective user's x11/wayland session with explicit `LockedHint=yes/no`. Missing
tools, failed queries, non-graphical/foreign sessions and unsupported platforms
produce `unknown`; the last observation expires after six seconds using Instant.
The monitor samples every three seconds plus query duration. This is advisory
session evidence, not a claim that all desktop managers expose lock state.

A fresh confirmed lock suppresses only the frontend timer warning. It does not
cancel jobs, release capture locks, change the core, or establish native/Worker
health. Unknown state does not receive this exemption. Existing strict native
soak health rules are unchanged. The independent native-loop probe remains a
test facility, not a new production liveness watchdog.

The heartbeat response now includes `session_lock` and `unlock_generation`.
A confirmed unlock of the previously locked session increments the generation;
an intervening unknown observation cannot suppress warnings or erase this
recovery opportunity. A different session is not considered an unlock.
The frontend serializes heartbeat requests, ignores late responses after
unmount, and emits one local recovery signal when a confirmed unlock advances
the generation. Pipeline/history snapshot polls consume it using their existing
single-flight/coalescing logic, even if DOM visibility never changed. A page
mounted while already locked also recognizes its subsequent unlock.

Scope limits: the UI is not forced to run while locked. Already pending IPC is
not physically cancelled. Other query hooks and actual analysis continuity need
separate integration verification. The standalone soak still mocks the
production heartbeat command; wire the shared production observation path into
an isolated test boundary before claiming end-to-end acceptance of this fix.

Validation: 73 frontend tests passed, followed by six focused tests including
one additional initially-locked case; three Rust desktop-state tests passed.
TypeScript, targeted ESLint and tracked whitespace checks passed. Production
Clash Verge PID 4165912 remained running. No installation, commit or push was
performed. Unlock recovery and long-run gates remain pending.

The sibling UI's pipeline status and pipeline history now use
`startVisibleSnapshotPoll`. Hidden documents issue no new reads. Visibility
return or `pageshow` requests a current snapshot. When a request is still in
flight, recovery is coalesced to one follow-up read; missed periodic ticks are
not replayed. Disposal removes listeners/timers and cancels pending recovery
demand. Callers retain their existing lifecycle revision and disposed guards.

This does not cancel an already dispatched IPC request, change Worker state,
resume a stopped job, or promise that an unresolved IPC will complete. Other
query hooks are outside this first change. If disconnect does not change page
visibility, normal polling resumes when the JS scheduler runs again.

Production UI heartbeat monitoring already disables itself for reported hidden
pages and only logs a warning on a visible heartbeat timeout. It does not stop
capture or the core. The native pipeline owner heartbeat is distinct from this
UI heartbeat. These facts do not establish that every backend operation is
immune to a stalled view; that remains a native integration gate.

## Controlled reproduction procedure

Use only the isolated native example, with the full-page diagnostic build
described in `native-event-bridge-soak.md`. Do not install a candidate, restart
the production proxy, change profiles/TUN, or invoke desktop locking remotely.

1. Record an ordinary foreground baseline for 60 seconds.
2. In separate runs, have the user minimize, lock, or disconnect after the
   baseline. Record the user's action and return times, including timezone.
3. Keep a second terminal available to collect the isolated report after return.
   The existing strict monitor may fail fast after a ten-second heartbeat gap;
   such a run diagnoses suspension but does not validate recovery after unlock.
4. Compare native main-loop age, independent event-probe age, driver heartbeat,
   visibility transitions, frame age, errors, and process-family resource data.
5. If state evidence is missing, classify the cause as unknown. A stale JS probe
   alone does not separate blocked JS from blocked event/IPC delivery.

A bounded diagnostic observation mode is now implemented. Rebuild the isolated
example before using it, then run from the sibling UI repository:

```bash
TT_SOAK_OBSERVE_UNTIL_DEADLINE=1 timeout --signal=TERM --kill-after=5s 225s \
  target/debug/examples/traffictracer-ui-soak 180
```

Confirm the actual Cargo target path if this environment overrides it. This is
a diagnostic invocation, not the normal passing-gate runner. It retains the
first failure and samples until the deadline; final status is `diagnostic_only`,
`passed` is always false and exit is nonzero, even without a health failure.
The external timeout bounds exit if the native main loop cannot handle exit.
Normal runs still fail fast. Do not suppress failures based solely on the last
stale visibility sample. Native execution of this new mode is still pending.

## Acceptance

- Foreground: existing heartbeat/event/render criteria remain strict.
- Background: native/backend progress remains measurable, resource usage stays
  bounded, and no task is cancelled because the UI is inactive.
- Recovery: one authoritative current-state refresh, no event-backlog replay,
  duplicate operations, subscription leaks, or stale lifecycle overwrites.
- Native main-loop blocking and unknown pauses remain actionable failures.
- A candidate installer and real-data Resume require the native gates; mock
  frontend tests alone are insufficient.

## Initial validation

### Automatic-lock long observation: interim failure, 2026-09-09

Follow-up: the user clicked the isolated window and confirmed it did not respond,
although no OS unresponsive dialog appeared. At 5612.875 seconds, more than eleven
minutes after native unlock detection, UI recovery count was still zero; heartbeat
age was 1390.638 seconds and event-probe age 1671.586 seconds. Native-main-loop
age was 1.003 seconds. Process-family RSS reached 2,262,252 KiB. The renderer
remained runnable with increasing CPU ticks. A separate `review.json` preserves
these findings without rewriting raw results. Stop only the isolated host to
avoid further resource accumulation; the intended two-hour gate is incomplete
and prolonged-lock recovery has failed. No permanent deadlock mechanism is proven.

Run: `/tmp/traffictracer-native-soak-3886699-1788947362318187`, intended
7200 seconds, started 09:49:22Z. At the user's reconnect the run was still active;
these are interim findings, not a final two-hour report.

Independent OS samples confirmed automatic lock at 10:05:34Z and unlock at
11:11:42Z (approximately 66 minutes locked). Native production observation also
changed to unlocked/generation 1, but 48 seconds after native unlock detection
the frontend recovery count remained zero and its independent event probe was
already over 17 minutes stale. Later sampling still showed no recovery.
Native main-loop gaps remained about one second. DOM visibility stayed visible.

Process-family RSS increased from approximately 638 MiB before lock to 1689 MiB
near 4900 seconds. The WebKit renderer remained runnable with CPU tick growth;
available system memory was about 9.5 GiB, so whole-machine OOM is not established.
The bridge waits for native emit completion, not a JavaScript consumption ACK;
WebKit-side event backlog is a hypothesis requiring targeted verification.
Short-lock success must not be generalized to prolonged-lock recovery.

The user was asked to click the isolated window without closing it to test
whether foreground interaction restores responsiveness. No process was stopped,
no report rewritten, and no production proxy setting changed. Remaining gate:
record click/recovery outcome and final report, then investigate bounded native
delivery during confirmed lock and a recovery path not dependent solely on a
stalled frontend heartbeat. Preserve authoritative terminal job records.

### Real heartbeat command lock/unlock integration, 2026-09-09

Artifacts: `/tmp/traffictracer-native-soak-3802584-1788946448524092`.
The isolated native command now calls the production `tt_ui_heartbeat` instead
of returning a mock. Test-support exports expose its read-only desktop snapshot
for per-second diagnostics. The page records local desktop-recovery signals.
No production app setup or capture/profile commands are registered.

The 300-second diagnostic completed normally (deliberate nonzero diagnostic
exit). Production desktop state changed to locked at 70.222 seconds and to
unlocked, generation 1, at 178.475 seconds. Independent two-second loginctl
samples confirmed the same transitions. The user confirmed manually unlocking.
The first frontend recovery signal was observed at 180.482 seconds, about two
seconds after native detection, and the final recovery count was exactly one.
No DOM visibilitychange was observed; WebKit continued reporting visible.

Strict raw health retained a heartbeat failure at 89.266 seconds and a maximum
locked-period heartbeat gap of 52.262 seconds. This report remains
`diagnostic_only`, never a foreground pass. Native-main-loop maximum gap was
1.019 seconds. Across 123 samples after native unlock detection, maximum UI
heartbeat gap was 1.013 seconds. Final counts: zero JS errors, zero denied mock
commands, zero cleanup failures, 16 remounts and 32 populated index reads.
The production proxy PID 4165912 remained unchanged.

This verifies real session observation, production heartbeat response, and
frontend recovery-signal delivery without visibility events. Snapshot request
coalescing remains covered by unit tests and the simulated full-page driver;
it does not demonstrate real Python analysis continuity. Automatic-lock and
two-hour gates, real-worker Resume and installer handoff are still pending.

### Confirmed manual-lock observation, 2026-09-09

Artifacts: `/tmp/traffictracer-native-soak-3560383-1788943690206873`.
The new `scripts/observe-native-lock.mjs` samples the selected loginctl session
every two seconds, with single-flight calls and a 1.5-second command timeout.
The isolated child has an external duration-plus-30-second termination bound.
It never changes desktop lock state or production services.

GNOME configuration readback: idle-delay 900 seconds, lock-enabled true,
lock-delay zero. Actual automatic locking was not tested.

Manual-lock observation: session 1 changed from `LockedHint=no` to `yes` at
2026-09-09T08:49:12.186Z (approximately 62 seconds into the run). The first
heartbeat failure followed at 79.200 seconds. Maximum heartbeat gap was
92,660 ms; maximum native-main-loop probe gap was 1,008 ms. All 240 samples
were recorded, with zero JS errors. Populated WebKit visibility observations
remained `visible`, with no visibilitychange transitions, despite the OS lock.
Some independent event probes continued: this is not evidence of total JS or
native-process suspension. The precise scheduling mechanism is not yet proven.

The final report now correctly retains `status=diagnostic_only`, `passed=false`
and the first failure. At the 240-second deadline the OS still reported locked,
so unlock recovery is NOT verified. The foreground timeout remains unchanged.
This reproduction supports an OS-lock-aware diagnostic classification rather
than treating DOM visibility as authoritative. Backend analysis continuity
still requires a real-worker test; the isolated backend is synthetic.

Next: repeat with an unlock before the deadline, then implement a bounded,
explicit unknown/locked/unlocked native session signal with stale-data handling.
Do not infer lock state from focus or from a stale JS visibility probe. Keep
native responsiveness checks active while locked. Production PID 4165912 was
unchanged during this observation.

### Remote-disconnect observation, 2026-09-09

Artifacts: `/tmp/traffictracer-native-soak-3522969-1788943235997423`.
The user was prompted to disconnect after a healthy 70-second baseline and
subsequently confirmed reconnecting. All 180 one-second samples were retained.
Maximum heartbeat gap was 2003 ms, native-main-loop gap 1010 ms, and independent
event-probe gap 1078 ms. No sampled health failure or JS error occurred.
Every populated visibility probe reported `visible`; focus changed. Sampled
loginctl checks reported `LockedHint=no`, but these were not continuous OS lock
monitoring. This does not reproduce or rule out the earlier 36.8-second stall,
and is not a verified lock/unlock test or a long-run acceptance pass.

The diagnostic-mode exit path incorrectly replaced its completed report with
`interrupted`, because it only preserved `failed` reports. The original result
was not rewritten. Findings above are derived from `samples.jsonl`. The exit
guard now also preserves `diagnostic_only`; six Rust monitor tests passed,
including the new regression. A rebuilt native rerun is still needed to verify
the final-report fix end to end. Production Clash Verge PID 4165912 remained
running throughout; no proxy/profile/TUN settings were changed.

The complete frontend suite passed: 71 tests in 15 suites. The visible-poll and
existing real-page orchestration subset contains 15 tests in two suites.
TypeScript, targeted ESLint and the UI tracked whitespace check passed. Five
Rust monitor tests passed, including diagnostic deadline/first-failure rules.
These cover hidden scheduling, return synchronization,
slow-read coalescing, cleanup and existing lifecycle races. They do not simulate
an operating-system lock or a real WebKit suspension.

# Profile activation hang: repair and validation

## Incident and confidence

The September 6, 2026 detailed experiment scheduled 270 cells: five repetitions,
18 targets, and three candidates. It retained 35 capture-only Sessions. The next
cell stopped during profile activation, before creating a capture batch. No
analysis had run because the first repetition's capture barrier was incomplete.
The desktop reported an unresponsive application and the operator eventually
forced it to close.

Logs reached profile persistence and frontend change notification, but not the
activation completion checkpoint. This localizes the suspect interval; without
a native thread dump it does not prove a particular GTK/WebView deadlock. No
supporting evidence of OOM or disk exhaustion was found in the inspected logs.

## Implemented safeguards

| Task | Implementation | Verification |
| --- | --- | --- |
| FIX-001 | Persist the profile before enqueueing UI refresh. Pipeline activation no longer waits on window notification or native tray refresh. Existing controller readback and node selection checks remain authoritative. | Rust suite; final activation path review |
| FIX-002 | One dedicated notification worker, one wake token, and one latest pending refresh. Native window emission is dispatched to the main thread. A missing acknowledgement produces `PROFILE_UI_REFRESH_STALLED`; no replacement workers are spawned. | 270-enqueue coalescing test |
| FIX-003 | Immediately dispose event listeners whose asynchronous registration resolves after React cleanup. Ignore callbacks after disposal; retain existing refresh throttling. | Frontend tests, typecheck, lint |
| FIX-004 | Independent owner-heartbeat thread detects activation with no durable checkpoint for over 90 seconds, requests cooperative interruption, and writes `pipeline-stall.json`. Only the supervisor writes the pipeline manifest. | Rust suite; desktop stall injection still pending |
| FIX-005 | Preserve captured cells on recovery and resume the interrupted cell without recapturing the first 35. | 270-cell model regression with interruption at cell 36 |
| FIX-006 | Count Sessions independently of analysis quality; show pending, interrupted, and awaiting-analysis cells. Display the relevant ordinal instead of the total count when no run is active. | Rust aggregate tests and frontend checks |
| FIX-007 | Exercise recovery and repetition barriers across the complete 270-cell schedule. | Model regression passed; real desktop soak test pending |

The notification queue deliberately coalesces intermediate profile changes; it
is a latest-state refresh channel, not an audit log. Pipeline manifests retain
the execution history. Pipeline switches omit native tray rebuilding, so tray
profile labels may lag until a normal manual refresh/switch. Home and Proxies
receive the queued refresh when the window thread is responsive.

The watchdog does not forcibly cancel a native call, kill the core, or start a
second activation. Its interrupt request takes effect when the supervisor
regains control. The TrafficTracer page also displays an activation-stall alert
when its polling/rendering is responsive; no frontend alert can be guaranteed
while the entire desktop application is frozen.

## Automated validation

From the Clash Verge repository, with `TRAFFICTRACER_CONTRACT_DIR` pointing to
TrafficTracer's `test/fixtures/contracts` and `TRAFFICTRACER_GOLDEN_DIR` pointing
to `test/fixtures/tracing`:

```sh
cargo test --manifest-path src-tauri/Cargo.toml --lib
pnpm test:frontend
pnpm exec tsc --noEmit
pnpm exec eslint src/providers/app-data-provider.tsx src/pages/traffic-tracer/index.tsx --max-warnings=0
```

Results: 167 Rust tests and 42 frontend tests passed; typecheck and lint passed.
The coalescing test blocks the queue consumer, not an actual native WebView.
The 270-cell test simulates the state machine; it does not visit websites.

## Remaining release acceptance

1. Build a newly versioned package after review and record component revisions.
2. Resume a copy of the interrupted group using the supported Resume operation.
   Verify the first 35 Session IDs remain unchanged and cell 36 gets its first
   batch; do not manually change manifest statuses.
3. Verify analysis starts only after all capture attempts in that repetition
   reach the required capture barrier, before proceeding to the next repetition.
4. Exercise manual profile switching, Home/Proxies refresh, page navigation,
   minimize/restore, and interruption during a small pipeline.
5. Run the five-repetition detailed experiment while monitoring responsiveness
   and notification-worker/thread growth. Record native stacks if it hangs again.

No existing capture data or running proxy processes were modified during this
repair. The Python Worker and Mihomo protocol/correlation logic are unchanged.

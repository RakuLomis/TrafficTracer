# Resumable Capture Interruption and Capture Group History Plan

## 1. Goal

Add a user-visible action that safely interrupts the capture that is currently
running, preserves completed targets and diagnostic evidence, prevents the next
target from starting, and allows the same capture group to resume from the
interrupted target.

At the same time, make Capture Group selection deterministic. The workspace must
show the group started by the current operation, recover only a genuinely
running group automatically, and provide an explicit history selector for older
groups under the selected output root.

The latest 64-target experiment took approximately three hours and twelve
minutes. A resumable interruption is therefore an operational requirement, not
just a UI shortcut. The implementation must not sacrifice flow correlation,
packet evidence, or the ability to audit an incomplete session.

## 2. Scope

### TrafficTracer

- Add an interruption request distinct from terminal cancellation.
- Persist interruption intent and the retry cursor.
- Reuse the existing cooperative cleanup path for Chrome, NetLog, tshark,
  analysis, and packet splitting.
- Keep interrupted sessions inspectable without classifying them as corrupt.
- Resume the same immutable batch snapshot at the interrupted target.

### Clash Verge

- Expose the new worker method through Rust/Tauri and TypeScript.
- Add an `Interrupt current capture` action with confirmation and cleanup
  feedback.
- Separate the active batch identity from the batch selected for historical
  inspection.
- Add an output-root-scoped Capture Group history selector.

### Mihomo

No core change is planned. Interruption remains an orchestration concern. The
existing tracing restore and log flush behavior will be verified by integration
tests.

## 3. Required semantics

### 3.1 Batch interruption

When a serial batch is active, interruption must:

1. Record the first interruption request and reason idempotently.
2. Stop the current child at a cooperative checkpoint.
3. Close only the Chrome and capture processes owned by that child.
4. Flush NetLog, packet captures, the session journal, and the batch manifest.
5. Mark the current child and parent batch `interrupted`.
6. Keep `resume.next_index` at the interrupted target.
7. Prevent every later target from starting.

On resume, completed children are skipped, the resume attempt is incremented,
and the interrupted URL receives a new job/session identity. Existing partial
evidence is never overwritten.

### 3.2 Standalone capture

A standalone one-URL job has no batch cursor. Its existing action remains a
terminal stop and produces `cancelled`. The UI label should be `Stop capture`,
not `Interrupt`, so it does not promise unsupported resume behavior.

### 3.3 Capture Group selection

The UI must keep two independent identities:

- `activeBatchId`: the currently running batch or the batch just started by this
  workspace.
- `viewedBatchId`: an older group explicitly selected by the user.

Automatic recovery may select only a `running` batch. Failed, interrupted,
cancelled, and completed groups must never become the current group merely
because of scan order.

The active card remains authoritative while a job is running. History may be
inspected in parallel, but resume actions on historical groups are disabled
while the capture lock is held.

## 4. State and protocol design

### 4.1 Stop intent

Extend the cooperative cancellation mechanism with an explicit stop intent:

- `cancel`: terminal user cancellation.
- `interrupt`: resumable batch interruption.

An `InterruptedError` should reuse the cleanup handling of `CancelledError` but
map to `JobState.INTERRUPTED` and `BatchChildState.INTERRUPTED` at orchestration
boundaries. The first reason wins and repeated requests are no-ops.

### 4.2 Worker API

Add:

```json
{
  "method": "batch.interrupt",
  "params": {
    "batch_id": "<uuid>",
    "reason": "Interrupted from the TrafficTracer workspace."
  }
}
```

The response must contain the current batch and job snapshots plus an
`interrupt_requested_now` flag. Requests against an already interrupted batch
are idempotent. Completed and cancelled batches are not mutated.

`batch.cancel` remains available for protocol compatibility but is no longer the
primary batch action in the UI.

### 4.3 Manifest compatibility

Persist interruption metadata, including request state, reason, and timestamp.
Readers must default the new fields when loading older manifests. Resume must
clear request flags before returning the batch to `running`.

Schema changes must be backward-readable and covered by fixtures for manifests
written by released 1.0.x workers.

## 5. Resource and artifact invariants

- Never kill Clash Verge, Mihomo, a user-owned browser, or a process selected
  only by executable name.
- Chrome/CDP and tshark cleanup must target process handles owned by the current
  job.
- An interrupted session keeps all raw evidence already written.
- It is displayed as incomplete/interrupted, not corrupt.
- It is excluded from successful correlation and automatic full-group split
  statistics.
- Resume retries the whole URL in a new session rather than mixing partial and
  resumed evidence.
- No later target may begin after interruption is acknowledged.

## 6. UI behavior

### 6.1 Active capture action

For an active serial group, display `Interrupt current capture`. Confirmation
must explain that completed targets are retained, the current target will be
retried, later targets will not start, and cleanup can take several seconds.

After confirmation:

- Disable repeated actions.
- Show `Interrupting...` and a cleanup message.
- Continue polling until the persisted state is `interrupted`.
- Show the interrupted target and `Resume from interrupted target`.

For failed batches, retain `Resume from failed target`.

### 6.2 History selector

Add a Capture Group history control scoped to the selected Session Output
Directory. Entries are sorted by `created_at` descending and show creation time,
state, and completed/total targets. Basic state filters should include all,
completed, failed, and interrupted.

Selecting an entry opens its target/session detail in read-only history mode.
Provide `Back to current capture` whenever a different group is being viewed.
Corrupt manifests are reported separately and are never selectable as normal
groups.

### 6.3 Persistence

Use output-root-scoped storage keys for active and viewed identities. Changing
the output directory must not reuse a batch ID from another workspace. Missing
or moved manifests clear only the stale selection and produce a non-blocking
notice.

## 7. Atomic implementation sequence

### Phase A: TrafficTracer interruption semantics

- **TT-INT-001**: Add stop intent and `InterruptedError` to the cancellation
  primitive, preserving current cancel compatibility.
- **TT-INT-002**: Map interruption through the Job manager and add the
  `batch.interrupt` worker method and dispatcher contract.
- **TT-INT-003**: Update batch transitions, cursor persistence, idempotence, and
  resume flag clearing.
- **TT-INT-004**: Preserve interrupted session artifacts and classify them as
  incomplete rather than corrupt.
- **TT-INT-005**: Verify interruption checkpoints and owned-process cleanup for
  capture, playback, analysis, and split stages.

### Phase B: Clash Verge protocol and UI

- **CV-INT-001**: Add Rust protocol, Tauri command, fake-worker, TypeScript
  command, and type support for `batch.interrupt`.
- **CV-INT-002**: Add interrupt mutation, polling transition, confirmation UI,
  and state-specific Resume labels.
- **CV-GRP-001**: Remove automatic selection of failed/interrupted groups and
  split active and viewed batch identities.
- **CV-GRP-002**: Scope persisted selection keys to the normalized output root.
- **CV-GRP-003**: Add the Capture Group history selector, filters, refresh, and
  `Back to current capture` action.
- **CV-GRP-004**: Add active and history modes to the batch progress/detail
  components and enforce capture-lock restrictions.

### Phase C: Verification and documentation

- **INT-E2E-001**: Interrupt a three-target batch during target two and prove
  that target three never starts.
- **INT-E2E-002**: Resume the same batch, prove target one is not repeated, and
  prove target two receives a new session before target three runs.
- **INT-E2E-003**: Verify no owned Chrome/tshark process remains and no session
  is incorrectly reported as corrupt.
- **INT-E2E-004**: Verify startup selection with combinations of running,
  completed, failed, interrupted, missing, and corrupt batches across two output
  roots.
- **INT-DOC-001**: Update English QuickStart, operations, protocol, and release
  documentation.
- **INT-REL-001**: Run repository tests, commit each repository independently,
  push the designated branches, and build a versioned Linux package.

## 8. Acceptance criteria

1. A running batch can be interrupted from the UI without killing Clash Verge
   or Mihomo.
2. The current target stops safely and no next target starts.
3. The batch becomes `interrupted`, not `cancelled` or `corrupt`.
4. Resume retries exactly the interrupted target in the same capture group and
   then continues serially.
5. Completed target results and flow/packet linkage remain unchanged.
6. With no running batch, the UI does not automatically display an old failed
   or interrupted group.
7. History selection is explicit, ordered, output-root scoped, and independent
   of the active capture.
8. UI state remains synchronized across interrupt, cleanup, resume, completion,
   application reload, and output-directory changes.

## 9. Implementation boundary

The first implementation change should be TT-INT-001. UI work must not begin
until the worker state transition and resume behavior are executable through
tests. No implementation step may terminate an existing Clash Verge, Mihomo, or
Chrome process outside a test fixture explicitly created by that step.

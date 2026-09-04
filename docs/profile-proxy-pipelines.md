# Profile and proxy capture pipelines

TrafficTracer 1.0 captures one ordered target set through one active Mihomo
selection. Pipeline mode adds a durable outer orchestration layer:

```text
pipeline -> profile/selector/node candidate -> repetition -> existing serial capture batch -> Session
```

The stable candidate identity is `(profile_uid, selection_group, requested_node)`. Each concrete run additionally records a one-based `repetition_index`; the durable logical identity is `(candidate_ordinal, repetition_index)`.
Node names alone are not unique and do not identify the selector whose state
must be changed. Every selected `sites.yaml` entry remains an independent
target; entries are not deduplicated by domain.

## Ownership

Clash Verge owns the outer supervisor because it owns Profiles, effective core
configuration, TUN and system proxy state. The Python Worker remains the inner
capture and analysis engine. Mihomo exposes selector state and observed trace
evidence, but does not own the experiment state machine.

The supervisor holds one capture lock for the complete pipeline. Internal
profile and selector transitions are authorized only for that lock owner. User
changes to Profile, selector, TUN, system proxy or core remain blocked.

Before the first Batch, the supervisor materializes every queued candidate in
order. It activates the Profile, waits for the Controller, selects and resolves
the requested node, determines its leaf protocol, and binds the candidate to a
canonical semantic fingerprint of the effective runtime configuration. A stale
queue fingerprint is recorded as a rebind, not treated as a run failure. If a
Profile, selector, or node is genuinely unavailable, the first repetition fails
and the remaining repetitions are marked `skipped` without starting Workers.

## Run barrier

Before each run the supervisor activates the Profile, waits for the real
Controller API, selects and reads back the requested node, resolves the leaf
chain, closes old connections, waits for quiescence and performs environment
checks. Only then may it start the existing serial Batch. A checkpoint must be
durable before the next node is selected.

Pipeline manifest schema v6 makes this barrier evidence-based and records
`repetitions_per_candidate`, `candidate_ordinal`, `repetition_index`,
`repetition_total`, fingerprint kind, queued fingerprint, binding time, and
whether materialization refreshed the queued snapshot. The supervisor polls
Profile, runtime fingerprint, selector, resolved chain and concrete leaf
until the requested state is observed or a bounded deadline expires. It
snapshots connection IDs that existed at the transition, closes them, and
requires those old IDs to remain absent for the minimum quiet interval. New
connections created after the transition are not mistaken for undrained old
node traffic. A second chain snapshot immediately before Batch start must match
the first snapshot exactly.

The pipeline may contain different proxy protocols. The strict protocol
invariant is applied separately to every inner Batch and verified afterward
against actual trace evidence. A mismatch is never relabelled silently.

After the Batch becomes terminal, the supervisor reads Profile, selector,
chain, leaf and protocol again and compares them with the pre-Batch snapshot
and Session-scoped Mihomo trace evidence. `node_drift`, `protocol_mismatch` and
`observation_unavailable` are independent outcomes. Any of them degrades a
completed run without deleting its Sessions or rewriting valid correlation
results.

## Recovery and privacy

Completed candidate repetitions and targets are skipped on resume. The
supervisor expands candidates in candidate-major order: it finishes all
requested repetitions for one candidate before activating the next candidate.
An interrupted target is retried as a new Session inside the same Batch. A
semantic configuration change after materialization raises
`CANDIDATE_CONFIG_DRIFT`; the current repetition fails and the remaining
repetitions for that candidate are skipped. Deleted Profiles and missing nodes
are handled by the same candidate-level circuit breaker. Original Profile and
selector state is restored on every terminal path.

Restoration is not considered successful merely because a change request
returned. The original Profile fingerprint and every affected selector are
read back through the real Controller. Profile request failure, selector
request failure, Controller unavailability and readback mismatch are persisted
as separate restore checks. A failed check changes the Pipeline to
`restore_failed` and remains visible in its manifest and UI. **Retry
restoration** repeats only the bounded Profile/selector restoration transaction;
it restores the saved pre-restore terminal state and never repeats a Batch or
Session.

Manifests must not contain raw Profile YAML, subscription URLs, Controller
secrets or proxy credentials. They store identifiers, content fingerprints,
requested and resolved node evidence, and inner Batch identifiers.

## Delivery stages

The first UI records the currently active Profile, selector and node through an
**Add current pair** action. This uses Mihomo's effective runtime graph and
avoids incorrectly parsing inactive Profiles with providers, merge scripts or
enhancements. A later release may add an effective-config inspector and a
multi-Profile matrix picker.

## Durable layout and provenance

A pipeline creates one timestamped `__pipeline-<id>` directory below the configured Session output root. Its manifest freezes the ordered target snapshot, capture options, candidate order, effective Profile SHA-256 values, per-repetition run and Batch identifiers, resolved proxy chain, expected leaf protocol, and protocols actually observed in bounded Mihomo trace events.

Every repetition owns a separate run directory and inner Batch checkpoint; the same URL therefore remains distinguishable across samples. `pipeline-aggregate.json` is atomically refreshed with per-candidate run states, Session totals, and Capture/Correlation/Application counters.

Each inner Batch request carries an optional `orchestration` object. The Worker preserves it in `batch-manifest.json`, propagates it to every child capture, and writes it into the Session's `capture-context.json`. Therefore a copied Session remains attributable to its pipeline run even when it is separated from the outer directory.

## Interruption and application restart

Interrupt is resumable; cancel is terminal. A clean interrupt stops the active Batch and restores the original Profile/selector state. Resume reactivates the frozen tuple and invokes the existing Batch resume operation when a Batch ID already exists, so completed targets remain completed. The interrupted child is retried using the Batch attempt rules.

The supervisor refreshes a small `pipeline-owner.json` record beside the
Pipeline manifest. It contains only the Pipeline ID, application PID, stage,
current Batch ID and heartbeat timestamp. On a UI reload or application
restart, status recovery compares that record with the in-memory supervisor,
capture lock, Worker manager and OS process evidence before it declares the
checkpoint abandoned. It never terminates a core, browser or process merely
because a heartbeat is stale.

If no live ownership evidence remains, the next status read converts the stale
running checkpoint to `interrupted` without deleting its Batch ID. Resume then
follows the same path. It refuses to run when the target configuration hash
changed. A missing or changed Profile, selector, node, or effective Profile
fingerprint fails that run explicitly; no substitute is selected.

Batch acceptance is also reconciled by its pre-generated Job ID. A lost start
response or timeout keeps capture ownership and enters `starting_batch` or
`reconciling_batch`; it is not reported as a terminal failure while the Worker
may still be active. A terminal Batch remains in `finalizing_batch` until the
Worker Job is terminal. Generic `job.interrupt` preserves resumable semantics
when the Batch manifest is temporarily unavailable; it is never downgraded to
terminal cancellation.

## Run quality and persistent progress

`pipeline-manifest.json` schema v6 records durable Profile activation and configuration-binding evidence plus three independent quality planes for
each terminal run:

- `capture_integrity`: whether the page-attributed evidence is complete enough
  to analyze;
- `correlation`: whether the captured pre-proxy and post-proxy flows correlate
  consistently;
- `application`: whether an application-level goal such as observed YouTube
  primary playback was met.

An application failure does not rewrite valid correlation evidence as a
correlation failure. Playback-enabled Sessions that do not meet their goal are
listed in `application_issues` with their requested URL, observed final URL,
reason and primary-content duration. Non-playback Sessions are counted as
`not_applicable` on the application plane.

Each run checkpoints Profile activation as `activation_requested`,
`profile_committed`, and `controller_verified`. Runtime YAML is parsed and
canonicalized before hashing, so mapping order, indentation, and comments do not
create false drift. Real changes to proxy, DNS, TUN, rule, merge, or script
output still change the fingerprint. The capture lock blocks subscription
updates and manual Profile/node mutations while the pipeline owns the
experiment. Profile persistence is time-bounded, while tray refreshes remain
non-blocking auxiliary work.

The desktop progress card is rebuilt from the durable Pipeline and inner Batch
manifests. After navigating away and back, it shows the active or most recently
terminal run, current target URL, Batch stage and attempt, elapsed time, last
durable checkpoint, quality planes and application issues. Schema v1-v5 Pipeline manifests remain readable. Legacy byte fingerprints are marked as v1 snapshots and rebound to semantic v2 at the next safe materialization checkpoint. Schema v1-v3 manifests migrate to one repetition per historical run in memory, and all active historical manifests are persisted as schema v6 at the next checkpoint.

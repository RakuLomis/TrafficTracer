# Profile and proxy capture pipelines

TrafficTracer 1.0 captures one ordered target set through one active Mihomo
selection. Pipeline mode adds a durable outer orchestration layer:

```text
pipeline -> profile/selector/node run -> existing serial capture batch -> Session
```

The stable run identity is `(profile_uid, selection_group, requested_node)`.
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

## Run barrier

Before each run the supervisor activates the Profile, waits for the real
Controller API, selects and reads back the requested node, resolves the leaf
chain, closes old connections, waits for quiescence and performs environment
checks. Only then may it start the existing serial Batch. A checkpoint must be
durable before the next node is selected.

The pipeline may contain different proxy protocols. The strict protocol
invariant is applied separately to every inner Batch and verified afterward
against actual trace evidence. A mismatch is never relabelled silently.

## Recovery and privacy

Completed runs and targets are skipped on resume. An interrupted target is
retried as a new Session inside the same Batch. Deleted or changed Profiles and
missing nodes block that run instead of selecting a substitute. Original
Profile and selector state is restored on every terminal path.

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

A pipeline creates one timestamped `__pipeline-<id>` directory below the configured Session output root. Its manifest freezes the ordered target snapshot, capture options, candidate order, effective Profile SHA-256 values, per-run Batch identifiers, resolved proxy chain, expected leaf protocol, and protocols actually observed in bounded Mihomo trace events.

Each inner Batch request carries an optional `orchestration` object. The Worker preserves it in `batch-manifest.json`, propagates it to every child capture, and writes it into the Session's `capture-context.json`. Therefore a copied Session remains attributable to its pipeline run even when it is separated from the outer directory.

## Interruption and application restart

Interrupt is resumable; cancel is terminal. A clean interrupt stops the active Batch and restores the original Profile/selector state. Resume reactivates the frozen tuple and invokes the existing Batch resume operation when a Batch ID already exists, so completed targets remain completed. The interrupted child is retried using the Batch attempt rules.

If the desktop application exits while a supervisor is active, the next status read converts the stale running checkpoint to `interrupted` without deleting its Batch ID. Resume then follows the same path. It refuses to run when the target configuration hash changed. A missing or changed Profile, selector, node, or effective Profile fingerprint fails that run explicitly; no substitute is selected.

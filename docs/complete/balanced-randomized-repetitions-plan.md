# Balanced Randomized Repetition Plan

Status: future implementation plan

## Purpose

Repeated capture must estimate protocol effects without binding one protocol to
one time period. A fresh Chrome profile controls browser state, but it does not
control CDN, route, proxy-node, server, machine-load, or time-of-day drift.

The required experimental design is therefore:

```text
fresh Chrome profile per visit
+ balanced randomized protocol order per repetition block
+ explicit Web activity and activity-success evidence
```

## Current Limitation

The current pipeline expands candidates in candidate-major order:

```text
candidate A repeat 1..N
candidate B repeat 1..N
candidate C repeat 1..N
```

This makes candidate/protocol and elapsed experiment time strongly correlated.
The YAML target file cannot correct this ordering because it describes Web
targets, not proxy scheduling.

## Required Execution Model

Introduce repetition blocks. Every candidate appears exactly once in each
block, and candidate order is balanced across blocks.

For three candidates, one valid three-block schedule is:

```text
block 1: A -> B -> C
block 2: B -> C -> A
block 3: C -> A -> B
```

For more repetitions, generate additional seeded permutations while keeping
first, middle, and last positions as balanced as possible. Prefer a balanced
Latin-square schedule when its constraints apply; otherwise use constrained
randomization with a persisted seed.

The schedule must be generated completely before capture begins. Resume must
continue the persisted schedule and must never generate a new order.

## Manifest Contract

The pipeline manifest should persist:

```text
schedule_strategy
schedule_seed
block_count
block_index
visit_index
position_in_block
planned_candidate_order
actual_candidate_order
profile_uid
profile_fingerprint
selection_group
requested_node
expected_protocol
observed_protocol
scheduled_at
started_at
completed_at
```

Every visit must retain its existing stable `run_id`. Schedule metadata is
append-only evidence and must survive interruption, application restart, and
resume.

## Browser and Activity Controls

- Create a new temporary Chrome profile for every target visit.
- Never reuse cookies, cache, local storage, Service Workers, or open sockets
  between visits.
- Record activity success separately from capture and correlation success.
- A pipeline run may have valid packets while its Web activity is degraded.
- Provider-specific activity evidence should include playback duration, result
  page readiness, tile activity, or another measurable activity contract.

## UI Requirements

- Add an execution-order selector:
  - `Candidate-major (legacy)`
  - `Balanced randomized blocks (recommended)`
- Display the generated schedule before confirmation.
- Allow an optional seed and generate one when omitted.
- Show block, repetition, candidate position, and total visit progress.
- Persist the displayed schedule and progress across navigation and restart.
- Clearly distinguish an interrupted visit from a failed Web activity.

## Failure and Resume Semantics

- Checkpoint before and after profile activation, node selection, connection
  draining, batch start, batch completion, verification, and restoration.
- If the application stops during profile activation, recovery must identify
  whether activation committed before deciding whether to retry it.
- Resume continues the interrupted visit in its original block position.
- A retry keeps the original `run_id` and increments `resume_attempt`.
- Later blocks must not move forward until the interrupted visit reaches a
  terminal state or policy explicitly skips it.
- The original user profile and node selection must be restored at the final
  terminal state.

## Backward Compatibility

- Existing manifests without scheduling fields load as `candidate-major`.
- Existing candidate-major pipelines remain resumable.
- The first implementation should retain candidate-major as a compatibility
  mode while making balanced blocks the recommended mode for new experiments.

## Acceptance Criteria

1. With three candidates and three repetitions, each candidate occurs once in
   every block and once in every ordinal position.
2. Identical seeds and candidate identities generate identical schedules.
3. Resume after every checkpoint continues the exact persisted schedule.
4. Every visit uses a distinct temporary Chrome profile.
5. Manifest data is sufficient to reconstruct planned and actual order.
6. Protocol verification uses observed trace evidence and is not inferred only
   from the configured node label.
7. A profile-switch stall is time-bounded, leaves a recoverable checkpoint,
   and does not freeze the application UI.
8. Unit, integration, restart, and cancellation tests cover both scheduling
   modes.

## Interim Procedure

Until this plan is implemented, set repetitions per candidate to one and run
multiple capture groups with manually rotated candidate order. Record the order
and group timestamp with the dataset. Do not combine all repetitions of one
protocol before starting the next protocol when estimating protocol effects.

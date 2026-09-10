# Pipeline quality display and trace sealing

## Baseline and synchronization

On 2026-09-10, read-only fetch and HEAD comparison confirmed no divergence for
TrafficTracer Complete (`40d82a9`), Clash Verge `feat/traffic-tracer` (`c467ed53`),
and Mihomo TrafficTracer (`ca4e36f60`). Historical untracked plans and generated
artifacts were left untouched. No live proxy or capture data was changed.

The 20260909T155725.348Z pipeline contains 192 final cells and three earlier
retry Sessions. Its candidate order is 1,3,2. It has 173 completed and 19 degraded
final cells, not three universally passed candidates. The strict quality subset
contains 54 complete candidate blocks; the capture/correlation subset contains
63. These quality selections are not causal-validity certificates.

## Atomic status

| Task | Status |
| --- | --- |
| FIX-001 Candidate/progress distinction | Implemented: ordinal label, explicit whole-pipeline counts, collapsed last-sample details |
| FIX-002 Quality scope | Implemented: status includes aggregate from the same manifest snapshot; no Session scan or extra IPC; stale identity/revision rejected |
| FIX-003 Trace sealing | Implemented: immutable analysis input, Resume validation, as-of journal metadata, default-on retention control, lock-gated lossless archival |
| FIX-004 Historical audit/repair | Read-only audit complete; historical mutation/migration remains a separate approval boundary, not an automatic repair |
| FIX-005 Correlation evidence | Implemented: collapsible, scroll-bounded evidence panel; page ambiguity and global tail counts kept separate; observed URL/candidate evidence only |
| FIX-006 Sample inventory | Read-only JSON/CSV CLI implemented; final/prior Session identities and paired quality eligibility included |

## Read-only review

Validation on 2026-09-10: 90 frontend tests, 15 Rust Pipeline tests and three
read-only dataset-review tests passed. TypeScript, targeted ESLint and whitespace
checks passed. No installer was built and no new changes were committed/pushed
in this implementation step.

From the TrafficTracer repository:

```bash
python scripts/review-pipeline-dataset.py /absolute/pipeline/root
python scripts/review-pipeline-dataset.py /absolute/pipeline/root --format csv
```

Output goes to stdout. The tool does not modify manifests, run analysis, launch
Chrome or switch proxies. JSON includes artifact size discrepancies and paired
blocks. CSV includes final-run quality, retry provenance and per-row audit issues.
Quality eligibility and artifact audit are intentionally separate. Review the
audit findings before selecting files for downstream research.

The existing experiment reproduces 192 final runs, 195 discovered Sessions,
54 strict and 63 capture/correlation blocks, and 165 grown trace artifacts.
The tool is intended for completed, quiescent datasets; it is not a transactional
snapshot of an actively changing capture group. No automatic metadata repair is
provided in this first stage.

## Trace lifetime finding and required contract decision

Mihomo `component/tracer/tracer.go` retires the previous sink on configuration
rotation, but closes it only when `refs == 0`. Existing connection trackers retain
the old sink and legitimately append lifecycle events. A barrier flushes a point
in that stream; it does not revoke connection ownership or seal the file.

Therefore a Worker-side delay or a second size read cannot guarantee a final
size. Force-closing retired sinks would lose connection information. Waiting for
every connection to end would violate bounded capture completion.

Proposed revised output contract:

1. Retain the original append-only lifecycle journal; never truncate it or stop
   ongoing proxy connections to make a Session appear complete.
2. Establish a separately named immutable analysis snapshot with explicit source,
   cutoff and generation provenance. Capture-time and analysis-time boundaries
   must remain distinct, including the current causal-tail inclusion rules.
3. Register immutable snapshot size as final. Mark the continuing journal as
   append-only with an as-of size, rather than falsely certifying it as sealed.
4. Preserve late dial/bind/close events for inspection or explicit reanalysis.
   Analysis must never silently consume a different input generation on Resume.
5. Add schema compatibility, atomic snapshot publication and bounded copy/error
   tests before enabling the new layout. Existing datasets remain untouched.

This introduces an additional artifact and potentially duplicate trace storage.
The user approved this contract and requested optional journal retention,
enabled by default. The immutable analysis snapshot is mandatory in either mode.

## Optional retention implementation

`retain_trace_journal` defaults to true in Rust/Python capture options and is
accepted by capture and Batch manifest contracts. Explicit false survives
serialization; a missing field never opts historical tasks into cleanup.
The UI exposes **Keep uncompressed trace journal**, checked by default. The
choice survives local form storage, capture/Batch requests and resumed tasks.
Historical tasks are not opted into the policy by a missing field.

Implemented primitives:

- Mihomo file-backed barriers return `byte_size` while holding the writer lock,
  after flushing the marker. Stdout barriers omit this optional field.
- `publish_trace_snapshot` copies only a caller-confirmed byte boundary using
  bounded buffers, SHA-256, a temporary file and exclusive atomic publication.
  It rejects partial final records, short/replaced sources and existing target
  generations; failures remove only the owned temporary file.
- Snapshot creation never modifies the source. Later appends cannot alter
  the snapshot. File-copy deadline checks occur between regular-file reads;
  they are not a guarantee against an uninterruptible kernel filesystem stall.

New captures now include an immutable-input policy in capture context. On first
analysis, the Worker samples the journal EOF and freezes the complete JSONL
prefix, including available causal-tail events. The copied capture context keeps
the original capture cutoff; freezing does not widen flow eligibility.

The committed bundle is `raw/trace-input/`, containing `trace.jsonl.gz`,
`capture-context.json` and `snapshot.json`. Metadata records size, trace/context
SHA-256 and the analysis-start boundary kind. All three files are registered as
analysis artifacts. Files and the containing directory are synced before atomic
bundle publication. Resume and ordinary reanalysis reuse and verify the bundle;
they never silently adopt later journal appends. Tampered or incomplete bundles
fail explicitly. Historical captures without the policy retain their old layout.
Copy/hash loops support cancellation; no historical journal is modified.
New snapshots use schema version 2 and gzip level 6. `size_bytes` and `sha256`
always describe the logical JSONL prefix; `stored_size_bytes` and `stored_sha256`
describe the compressed file. Existing schema version 1 `trace.jsonl` bundles
remain readable and are never automatically migrated. NetLog and PCAP are not
compressed by this change. See [capture reliability and snapshot compression](capture-reliability-and-snapshot-compression.md).

Validation: 688 Python tests, 94 frontend tests and 133 Rust TrafficTracer tests
passed. Mihomo tracer and controller-route tests passed, including the shared
writer-lock lifetime and failed reconfiguration checks. The tracer race-detector
run, TypeScript check and targeted zero-warning ESLint check also passed. Final
read-only review still reports 192 final runs, 195 Sessions, 54 strict paired
blocks, 63 capture/correlation blocks and 165 historical size discrepancies;
no historical metadata was rewritten to hide those discrepancies. No installer has been
built, no release version changed, and no real capture journal removed here.

## Lossless archival and safety boundaries

On Linux, every core sink takes a shared advisory file lock before writing and
keeps it until its descriptor closes, including retired sinks with outstanding
connection references. File barriers advertise `journal_locking: true`; capture
context persists this capability. The Worker requires it and a nonblocking
exclusive lock before archival. Old cores and other platforms retain the source.
An elapsed grace period or lack of recent growth is never sufficient evidence.

When retention is disabled, the Worker verifies that the full journal still
contains the analysis snapshot prefix, gzip-compresses **all** journal bytes
(including late lifecycle events), verifies the archive by decompression and
SHA-256, then atomically publishes `raw/trace-archive/`:

```text
raw/
├── trace-input/
│   ├── trace.jsonl.gz
│   ├── capture-context.json
│   └── snapshot.json
└── trace-archive/
    ├── journal.jsonl.gz
    └── archive.json
```

Archive files are capture artifacts, independent of analysis generations. The
original `raw/mihomo-trace.jsonl` is removed only after the replacement manifest
and analysis publication commit while the exclusive lock is still held. The
archive is lossless, not a filter that discards late connection information.
If manifest publication fails, the original remains. If unlink fails, a redundant
original remains. Resume verifies/reuses existing bundles rather than replacing
them or selecting newly appended analysis input.

A busy writer, unsupported core, deadline or archival error retains the original
and records `TRACE_JOURNAL_RETENTION_PENDING` in Session warnings. There is one
attempt per analysis, not a background scan or unbounded wait. Explicit reanalysis
retries pending archival. Copy/decompression loops check cancellation and a
30-second housekeeping deadline; kernel filesystem stalls are not interruptible
by that cooperative deadline. Source files on retained/pending paths remain
usable. No proxy connections are terminated to force archival.

Continuing journals use `size_semantics: as_of` in Session v2 artifacts. The UI
labels their size as recorded rather than final. The read-only audit accepts
growth only for this explicit semantic; missing/shrunken journals still fail the
audit. Snapshot and archive artifacts retain exact-size semantics. Historical
manifests remain untouched and their old size discrepancies remain visible.

## Release checkpoint

These changes require a coordinated UI/Worker/core build and updated component
pins. Do not bundle a new UI with an older Worker schema. Commit/push, version
selection, installer construction and live capture validation are subsequent
release steps. Historical migration would need its own reviewed policy: an old
growing journal cannot be retroactively certified as the exact input of an
already-published analysis without recorded input hashes.

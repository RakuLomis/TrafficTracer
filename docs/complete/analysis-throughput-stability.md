# Analysis throughput and stability repair

## September 8 incident

The 64-target, three-candidate experiment completed initial capture of 192
cells. Recovery recorded 184 final cells, five application-retry-pending cells,
and three captured cells awaiting analysis. Logging stopped after cell 189
analysis and the next Worker start. Available logs did not establish OOM or a
specific native deadlock. Do not diagnose the final three speed-test targets as
the crash cause without evidence that their analysis started.

## Atomic work status

| Task | Implementation status | Delivered scope |
| --- | --- | --- |
| ANA-001 Worker lifecycle evidence | Implemented | Per-workspace startup checkpoints; application logs record instance, PID, exit code and signal |
| ANA-002 Safe lifecycle switching | Implemented | Spawn/stop run off the async executor; pending exit retains ownership and prevents overlapping Workers; ready follows SIGTERM handler installation |
| ANA-003 Analysis health | Implemented | Stage/process memory, event/source/packet counters, scoped cancellation and 300-second no-progress warning |
| ANA-004 Child supervision | Implemented | Job-scoped v1/v2 extraction and source recovery, split-group child coverage, process-group termination, command deadline, bounded stderr and streamed metric output |
| ANA-005 Checkpoint recovery | Locally validated | 192-cell test preserves 169 completed + 15 degraded + five retry-pending + three captured cells through recovery and reload |
| ANA-006 Baseline measurement | Locally validated | Reproducible read-only benchmark; real NetLog semantic hashes and TUN/physical PCAP equivalence checks; broad hardware/data-size characterization is a release validation follow-up |
| ANA-007 NetLog graph work | Implemented | Reverse-edge deduplication, exact score bounds, scoped immutable-property reuse, pruning of URL roots that cannot bind to CDP |
| ANA-008 Incremental parsing | Implemented | Event-at-a-time JSON and legacy ZIP reading, CDP object reuse, chunked temporary repair, explicit malformed/oversized-value failures |
| ANA-009 PCAP extraction | Implemented | At most 32 filters per Wireshark pass, followed by one byte-preserving packet dispatch pass; native counts and conservative ordinary-extraction fallback |
| ANA-010 UI and soak | Locally validated | Inactive analysis indexes released; existing bounded/throttled event bridge retained; 192 actual serial Job lifecycles checked for thread/descriptor growth; installed full-traffic soak remains the user's unified validation gate |

The implementation batch is ready for unified installed-application validation.
This is not proof that the original native UI hang has been reproduced or that
every full-size workload is crash-free. No capture, resume, production proxy
operation, commit, push or installer build was performed during this continuation.
Prior sites.yaml changes remain separate.

## Final implementation details and limits

Worker roots remain isolated: there is deliberately no cross-Session Worker
pool. A kill request alone no longer releases ownership; matching process exit
must be observed before another Worker can start. Spawn and kill use blocking
executor tasks rather than executing native calls on the async runtime thread.
The OS spawn call itself is not forcibly cancellable; creating another Worker
on a spawn timeout would risk an orphan, so that is not attempted.

Parsing retains the normalized source graph required for full connection
evidence. Its memory use still scales with graph size. The incremental reader
removes the redundant raw event tree, not the need to store all useful source
information. It bounds its decode buffer at 64 MiB and fails explicitly for an
oversized individual value. Duplicate root keys are rejected rather than given
ambiguous streaming semantics. Source property caches are traversal-scoped;
path scores are never cached without their visited/depth context.

The no-progress policy is warning-only after 300 seconds. A heartbeat is not
progress, and the warning does not recapture a URL. Job-scoped external commands
have a default 1,800-second deadline, overridable through
`TRAFFICTRACER_ANALYSIS_COMMAND_TIMEOUT_SECONDS`. Cancellation/deadline failures
propagate through publication rollback. Diagnostic stderr retains only an 8 KiB
tail; large metric/recovery output is spooled and consumed line by line.

Wireshark's [Listener API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Listener.html)
evaluates the existing display filters. Listeners record packet ordinals, then
Python copies original capture headers, metadata and selected packet records.
An initial Lua Dumper experiment failed nanosecond-precision equivalence testing
and was replaced, not enabled as a lossy fast path. The final dispatcher preserves
packet bytes, order, wire/captured lengths, timestamp precision and interface
records. Interface capture-statistics blocks retain their original capture-level
meaning; derived packet counts come from the generated artifact/index metrics.
Unsupported capture blocks, unavailable Lua, or missing completion markers use
ordinary extraction instead of publishing a partial batch. Raw inputs never change.

The UI drops inactive coverage/request/connection query data (`gcTime: 0`).
Capture progress, selection and task history persistence are unchanged. Event
bridge payload limits and log throttling were already present and are retained.

## Final measured evidence

On the read-only Cloudflare SS sample (run 188), both eager and incremental
reading produced nine transport connections with the same SHA-256:
`6a3174ff1bb8e4fdd5554ae8926d8da800e56a27aaafc32283a1beb0ed92e2ee`.
After scoped property reuse, eager/streamed runs took 32.47/33.98 seconds with
112,808/115,748 KiB peak RSS. Before that property reuse, a run took 212.43
seconds. Cache/load conditions differ; this is not a guaranteed speedup, and
this sample does not demonstrate a memory reduction from streaming alone.

Four-filter extraction: TUN batch 0.68 s versus ordinary 1.41 s; physical batch
1.31 s versus ordinary 3.49 s. Ordered timestamps, lengths and transport fields
matched. Synthetic tests additionally compare raw bytes, overlapping filters,
empty results, multi-interface nanosecond PCAPNG and truncated packets.

Reproduce without changing original data:

```bash
PYTHONPATH=. python scripts/benchmark-analysis-paths.py /absolute/path/to/session/raw
```

The benchmark writes only temporary derived files. Its eager reference uses the
same current graph logic to isolate reading semantics; it is not an archived
release-to-release benchmark. A full 64-URL, three-protocol installed-UI run,
including resume and cancellation, remains required before release approval.

## Implemented behavior

- `.worker-startup.json` is an atomic, best-effort latest startup checkpoint in
  the requested workspace. It is diagnostic only, not ownership authority.
- `.analysis-health.json` is a latest snapshot per Session containing Job ID,
  PID, stage, elapsed time and Linux RSS/high-water/swap/thread observations.
  A heartbeat indicates liveness, not successful parsing progress. It does not
  kill a slow parser or change Session completion status.
- Dependency score pruning uses the existing maximum score of 1,000 and edge
  penalty of 10. No source-ID-only cache ignores visited/depth context.
- Native metrics preserve original wire lengths rather than captured lengths.
  Classic PCAP endian/timestamp variants and common PCAPNG Enhanced Packet Blocks
  are supported. Other containers/block types fall back to existing tshark
  inspection instead of silently dropping packet records. Malformed supported
  containers fail inspection.
- Job-scoped extraction uses separately owned process groups with cancellable
  polling and termination/reaping. Cancellation propagates through v2 splitting
  rather than becoming an empty successful result. Technical cancellation does
  not initiate application recapture.
- Worker installs its SIGTERM handler before publishing ready. The old order
  allowed an immediate stop request to terminate without graceful cleanup.

## Evidence and limitations

Final regression: 656 Python tests, 169 Rust library tests and 43 frontend tests
passed; TypeScript checking and diff whitespace checks passed. The Python suite
includes 192 actual serial analysis Job publication/cleanup cycles and checks
that health threads and file descriptors do not accumulate. Those captures are
empty to isolate ownership; this is not a multi-hour full-traffic WebKit test.

Before release, build from the matched repositories and verify:

1. Resume without changing raw files. The three captured cells must reuse their
   existing raw Sessions; the five application retries are separate new visits.
2. Confirm previously completed/degraded cells are not captured again and their
   final quality states are preserved.
3. Run all 64 targets and three candidates. Exercise UI navigation, cancellation
   and late-stage responsiveness; inspect output completeness as well as status.
4. Compare request/flow bindings, shared carriers, ambiguous/unmatched outcomes
   and ordered packet records, not only completed Job counts.
5. Preserve health/startup snapshots and application logs if a hang recurs.

The following notes describe earlier intermediate code, not the final reader.

### Earlier implementation checkpoints (historical)

CDP attribution now consumes the JSON object already loaded for the visit URL,
rather than opening and decoding the file twice. Raw CDP references are released
before transport tracing. Raw NetLog references are released after event
normalization; normalized events may still share nested objects, so this is not
a streaming parser or a guarantee of a fixed memory ceiling.

Transport tracing checks job cancellation around JSON decoding, every 1,024
events during normalization/description, and every 128 sources during tracing.
Health snapshots include operation, processed/total counters and seconds since
the last counter change. Reading JSON and a single expensive dependency search
can still delay cancellation; no automatic stall termination is enabled.

Only JSON decoding errors trigger NetLog repair. Runtime failures and memory
exhaustion from the initial tracing attempt propagate instead of causing an
additional whole-file read. Cancellation and memory exhaustion during repaired
parsing also propagate. Valid JSON with a parser defect is not silently treated
as corrupt input.

Additional regression cases cover loaded/file CDP equivalence, non-JSON repair
exclusion, event-loop cancellation, and health counter isolation between jobs.
The complete second-batch Python regression passed: 636 tests in 29.27 seconds.

Final first-batch regression: 628 Python tests and 167 UI Rust library tests
passed. Earlier failing lifecycle tests were investigated as described below,
not excluded from the suite. No installer was built from this batch.

A read-only parse of the former final Cloudflare Session produced eight
connections in 78.35 seconds with a 268,156 KiB peak RSS. The historical stage
took approximately 157 seconds, but load/cache conditions differ; this is not a
controlled speedup claim or a complete semantic equivalence proof.

For the same Session's physical PCAP, native metrics returned 41,092 packets and
51,834,081 wire bytes in 0.144 seconds, exactly matching tshark. No original or
derived experiment artifact was changed. Tests cover endian variants, malformed
lengths, unknown-block fallback, randomized cyclic-graph score equivalence,
child cancellation/reaping and health snapshot termination.

Full-regression testing also exposed a test-harness issue: mixing select() with
TextIO.readline() can miss a prefetched ready notification. The test now buffers
raw descriptor reads while retaining its five-second message deadline.

Future packet-dispatch optimization must compare ordered packet records,
request/connection bindings, ambiguous/unmatched outcomes, terminal no-socket
semantics and shared carriers. Do not increase Session concurrency before
memory and lifecycle bounds have been measured.

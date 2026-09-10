# Capture reliability and compressed analysis inputs

## Scope and baseline

Before implementation, the remote branch heads were verified as:

- TrafficTracer Complete: `91ea1fd62aebde71cee594e17aa9f92389b192a1`.
- Clash Verge feat/traffic-tracer: `cb34c0b169cfb2af874eddcaf1f3435a0469b324`.
- Mihomo TrafficTracer: `fcacc8696dfd574d0faa2770c5d3151e21dd9bbc`.

No core protocol changes, historical capture migration, proxy restart, or
NetLog/CDP/PCAP compression is included. Existing untracked files are preserved.

## Atomic implementation checklist

- CAP-001: require live tshark plus a complete PCAPNG section/interface header;
  bounded, cancellable startup; clean up unpublished processes on failure;
  recheck both interfaces before launching Chrome.
- CAP-002: monitor sensors on a job-owned thread throughout browser activity;
  expose failure through the CDP/capture checkpoint token without cancelling
  the parent batch. Never restart a failed sensor inside the same visit.
- CAP-003: close and verify owned Chrome processes before stopping sensors;
  bounded tail grace and stop waits; reject abnormal exits and truncated final
  PCAPNG blocks. This is a bounded framing check, not a full packet-file audit.
- CAP-004: persist monotonic lifecycle evidence and independent drop status;
  expose it in analysis summaries and UI. Unavailable drop statistics remain
  `unknown`, never zero. Legacy sessions have no inferred coverage guarantee.
- SNAP-001/002: schema version 2, streaming gzip level 6, logical/stored sizes
  and SHA-256, decompression verification before exclusive publication.
- SNAP-003/004: unified streaming reader for raw/gzip inputs, legacy bundle
  compatibility, Resume reuse, logical-byte journal-prefix verification.
  Validation is cached only inside one analysis and invalidated by file
  device/inode/size/mtime/ctime changes. No cross-job validation cache exists.
- SNAP-005: separate original journal, snapshot, archive and other metadata
  storage totals; explain the unchanged retention checkbox in the UI.
- Verification: startup faults, cancellation, sensor death, quiescence order,
  truncation, legacy bundles, gzip corruption, publication failure, archive
  reuse, full Python regression and frontend checks. Installer and full real
  browser-batch acceptance remain separate release steps.

## Capture lifecycle

Sensors launch on the TUN and physical interfaces before Chrome. Each managed
capture explicitly requests PCAPNG. Readiness does not require a first packet.
On the local tshark 4.2.2 installation, an isolated two-second loopback capture
with a narrow unused UDP-port filter published its header after approximately
251 ms and finished with zero packets. This demonstrates why a fixed 150 ms
process-alive check was insufficient; it is not a portable timing guarantee.

The startup deadline defaults to ten seconds. A 100 ms health monitor detects
unexpected exits; cooperative checkpoints propagate the failure. Existing CDP
command timeouts still bound time spent inside an outstanding command.
Cleanup does not depend on the failed health token. Only owned browser
processes are closed. Sensor monitoring continues through Chrome quiescence
and a default 200 ms tail grace (bounded to at most two seconds).

`packet_coverage` in capture context stores the readiness, browser launch,
CDP navigation request where available, browser quiescence and sensor-stop
times. These are monotonic seconds for ordering within the same process/boot,
not wall-clock timestamps for comparing different machines. Capture coverage
is distinct from request attribution and from kernel/interface packet drops.
Trace cutoff and causal-tail selection rules remain unchanged.

## Snapshot format and retention

New first analyses publish `raw/trace-input/trace.jsonl.gz` together with
`capture-context.json` and `snapshot.json`. They freeze the same complete JSONL
prefix as before; compression does not filter events or change page eligibility.
Metadata `size_bytes`/`sha256` describe logical input. The `stored_*` fields
describe disk-file contents. Compression ratio is stored bytes / logical bytes.

Readers stream gzip without creating an unpacked file. Corrupt bundles fail
explicitly; later journal appends do not replace an existing snapshot. Legacy
schema version 1 bundles and captures without immutable-input policy retain
their previous behavior. An old worker must not be used to analyze a schema
version 2 bundle: build and deploy the updated bundled worker with the UI.

**Keep uncompressed trace journal** still defaults to enabled. Disabling it
does not disable snapshots or recording. The complete original journal is
archived only after the cooperating core writers release their locks and the
replacement manifest is durable. Prefix verification uses logical snapshot
bytes, never compressed size. No historical files are automatically rewritten.

## Remaining acceptance boundaries

Readiness and cleanup tests cannot prove zero packet loss. The bounded final
block check cannot prove every interior packet block is valid. A full real
TUN/physical-interface capture and long-batch Resume test must be performed
with the newly built installer before making production completeness claims.
No running proxy is restarted as part of development verification.

## Development verification (2026-09-10)

- Full Python suite: 702 tests passed.
- Full frontend suite: 94 tests passed across 23 files.
- TypeScript no-emit check and targeted zero-warning ESLint passed.
- Both repository diffs passed whitespace checks.
- The new managed capture implementation passed a real quiet-loopback smoke
  test: readiness approximately 251 ms, exit code 0, no forced kill, valid
  PCAPNG header and final block.
- Reanalysis preserves failed coverage as `PACKET_CAPTURE_INCOMPLETE` in
  page/global quality instead of treating successful parsing as complete capture.

These are source-level and isolated verification results, not a completed
production TUN/browser batch acceptance test. Packaging is tracked in the
[1.0.24 release notes](../releases/v1.0.24.md). Mihomo source is unchanged.

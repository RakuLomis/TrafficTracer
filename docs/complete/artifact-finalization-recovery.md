# Artifact-finalization recovery

TrafficTracer Complete 1.0.28 introduced the capture-time runtime proxy
semantics snapshot. Its Session artifact mapper emitted the valid logical role
`proxy_semantics`, but the Session v2 JSON Schema did not list that role. The
capture itself could finish cleanly and still fail while registering the final
artifact.

The affected failure has this exact shape:

```text
CONTRACT_VALIDATION_FAILED: session_v2/artifacts/<index>/role:
value is not one of the allowed values
```

Affected Sessions normally remain in `capturing`, their Batch children are
failed, and the pipeline has no attached Session identity. This is a
finalization defect, not evidence that Chrome, tshark, Mihomo tracing, or proxy
semantics collection failed.

## Fixed behavior

The Session v2 contract now accepts `proxy_semantics`. Capture finalization also
registers raw artifacts one at a time. If a future artifact fails validation,
already registered evidence is retained and the Session still reaches a
terminal `failed` state with the original code and message. The pipeline stores
the Batch child error instead of the generic `BATCH_CHILD_FAILED` placeholder.

No protocol fields are removed by this fix. The redacted
`raw/proxy-semantics.json` remains a first-class capture artifact. Configured and
effective SS cipher/plugin/mux, VLESS transport/TLS/REALITY/Vision/mux,
Hysteria2 obfuscation, and the corresponding supported semantics for other
protocols remain available subject to the closed allowlist documented in
[Runtime proxy semantics evidence](../proxy/runtime-semantics-evidence.md).

## Recover an affected capture group

Preserve the capture group in place. Run the tool from a matching TrafficTracer
source checkout or packaged Worker environment. Start with the read-only
inspection:

```bash
PYTHONPATH=. python scripts/repair-finalization-failures.py \
  /absolute/path/to/TIMESTAMP__pipeline-ID \
  --dry-run
```

The command exits successfully only when every pipeline run is eligible. For
each Session it verifies all of the following before offering recovery:

- the pipeline Batch contains the exact artifact-role contract failure;
- the Session is schema v2, still `capturing`, and has no analysis artifact;
- target URL and domain agree between the Session and capture context;
- both packet captures exist, pass footer validation, and stopped cleanly;
- Chrome ended with the expected exit status;
- NetLog and CDP evidence are valid JSON;
- the declared Mihomo trace boundary exists in the trace journal;
- runtime proxy semantics passed start/end verification and is authoritative
  for capture time.

Apply the audited manifest repair only after the dry-run reports every expected
run as eligible:

```bash
PYTHONPATH=. python scripts/repair-finalization-failures.py \
  /absolute/path/to/TIMESTAMP__pipeline-ID \
  --apply
```

For every recovered Session, the tool:

1. saves the original manifest as
   `diagnostics/finalization-repair/manifest.before.json`;
2. registers existing raw artifacts with their size, modification time, and
   SHA-256 digest;
3. adds `RECOVERED_AFTER_ARTIFACT_CONTRACT_FAILURE` to the warnings;
4. transitions only the capture phase to `completed`;
5. writes `finalization-repair-report.json` at the capture-group root.

The tool does not launch Chrome or tshark, switch profiles or nodes, modify raw
evidence, or silently alter the pipeline manifest. It is intentionally
single-use and refuses to overwrite an existing audit backup.

To analyze every recovered Session serially without recapture, combine the
operations:

```bash
PYTHONPATH=. python scripts/repair-finalization-failures.py \
  /absolute/path/to/TIMESTAMP__pipeline-ID \
  --apply --analyze
```

If `--apply` was already completed, use the normal Session analysis workflow
instead of running the repair command a second time. Analysis failures remain
explicit in the repair report and do not roll back the capture evidence.

## Reconcile the UI pipeline

After recovered Sessions have completed analysis, select the same capture group
in TrafficTracer and run **Reconcile existing analyses**. Reconciliation accepts
a recovered Session only when its target identity matches the pipeline run, its
repair warning is present, and the registered `proxy_semantics` artifact is
present. It then attaches the Session identity to the original failed attempt
and recalculates that attempt from the existing analysis evidence.

Do not use this procedure for packet loss, browser failure, a missing trace
boundary, failed semantics verification, or any other contract error. Those

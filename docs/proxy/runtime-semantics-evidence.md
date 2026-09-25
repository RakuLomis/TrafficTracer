# Runtime Proxy Semantics Evidence

TrafficTracer records a redacted runtime semantics snapshot for a concrete
Mihomo leaf adapter when a capture has a scoped proxy selection. This evidence
answers which protocol behavior was configured and effective without exporting
credentials, endpoint identities, SNI, Host values, paths, or node names.

## Evidence boundaries

The snapshot separates four evidence layers:

- `configured`: accepted user-facing options.
- `effective`: defaults and normalized options applied by Mihomo.
- `negotiated`: connection-specific handshake results when observable.
- `observed`: connection-specific runtime behavior when observable.

Every field has an explicit state: `known`, `unknown`, `not_applicable`, or
`unsupported`. A missing field must never be interpreted as `false`. Coverage
is relative to the versioned schema and implementation and lists missing
fields with reasons.

The artifact records provenance separately for each evidence layer. It does
not apply an `effective` source label to configured, negotiated, or observed
facts.

The initial implementation covers Shadowsocks, VLESS, Hysteria2, Trojan,
VMess, and AnyTLS. It exports protocol behavior only through a strict nested
allowlist. Unknown plugin names, arbitrary plugin options, headers, endpoints,
SNI, Host values, paths, user IDs, passwords, and certificates are not copied
into this evidence.

## Capture artifact

Each scoped Session stores `raw/proxy-semantics.json` (or the equivalent legacy
logs name). It contains start and end snapshots plus a verification result:

- `passed`: the same runtime adapter and behavior remained active.
- `adapter_replaced_same_behavior`: the adapter instance changed, but its
  protocol and versioned behavior fingerprint remained equivalent.
- `configuration_drift`: effective protocol behavior changed during capture.
- `core_binary_changed`: the running executable identity changed.
- `binary_identity_unavailable`: behavior was stable, but an executable hash
  was unavailable, so binary equality is not claimed.
- `end_snapshot_unavailable`: capture-end verification could not be completed.

The capture context contains only a compact summary and the artifact path.
`behavior_fingerprint` is deterministic over normalized, allowed behavior
fields. It excludes endpoints and identity aliases. No deployment fingerprint
is emitted by default.

The controller lookup uses a JSON request body rather than a query parameter,
so a private node name is not placed in request URLs or URL-based access logs.

## Connection ownership

Start and end snapshots are drift checks, not proof that the selected adapter
handled a connection. Mihomo attaches the following reference to actual dial,
logical-carrier binding, and carrier lifecycle events:

```text
snapshot_id
config_generation
adapter_instance_id
adapter_protocol
behavior_fingerprint
```

TrafficTracer preserves a complete reference as `proxy_semantics` in normalized
flow and connection records. Partial references are treated as unavailable.
This event-bound reference is authoritative for connection ownership and
survives dynamic providers, hot reloads, equivalent adapter replacement, and
shared carrier reuse.

Configured mux support does not prove that a capture used multiplexing. Actual
carrier binding and lifecycle events remain the evidence for reuse. A carrier
that is still open at the capture boundary is right-censored rather than
assumed to have closed normally.

## Build identity

Snapshots include the running executable SHA-256 and available VCS/build
identity. Complete-core builds also inject the Git revision, dirty state,
tracked source digest, dependency-lock digest, and build-manifest digest. This
allows a dataset to verify that the running binary matches the intended build,
instead of relying on a source checkout label.

## Research limitations

This evidence documents configuration and binds it to runtime connections. It
does not infer byte-level initial/relay phase boundaries, negotiated properties
that Mihomo does not expose, or complete application routing from configuration
alone. Route decision, outbound establishment, browser activity success, flow
correlation, and carrier attribution remain separate quality dimensions.

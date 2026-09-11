# Local Quality and Failure Provenance

TrafficTracer must not describe every browser-visible anomaly as a proxy,
protocol, or remote-site failure. This policy separates recorded facts into
independent quality planes and preserves uncertainty when the evidence cannot
identify a cause.

## Epistemic boundary

The classifier does not promise that every remaining anomaly was caused by a
remote system. It promises the narrower, testable properties below:

- explicit loopback activity is never counted as a remote resource failure;
- a final successful document response is not degraded solely because an
  intermediate response failed;
- automatic retries require an explicitly retryable or legacy-classified
  transient outcome;
- ambiguous request attribution is not resolved without unique evidence;
- local capture health is reported independently from application health.

Origins currently emitted by the analysis are:

| Origin | Meaning |
| --- | --- |
| `local_expected` | Explicit `localhost`, `127.0.0.0/8`, or `::1` page probe. |
| `local_runtime` | Chrome lifecycle, packet sensor, or trace-boundary evidence. |
| `remote_site` | An HTTP response returned an error status. |
| `remote_network` | DNS, timeout, or connection evidence on a non-loopback endpoint. |
| `browser_policy` | Chrome canceled or blocked the resource locally. |
| `browser_activity` | Playback or another browser-observed application action. |
| `evidence_limit` | Available records cannot safely identify one cause or connection. |

`remote_site` and `remote_network` describe the observation point, not a causal
claim that the proxy, access network, CDN, and origin server have already been
distinguished.

## Navigation recovery

A main-document chain such as `401 -> 200` or `403 -> 200` is classified as
`passed`. The summary retains:

```json
{
  "recovered": true,
  "recovery": {
    "observed": true,
    "kind": "http_status_recovered",
    "intermediate_statuses": [401],
    "final_status": 200
  }
}
```

A final `4xx`, `5xx`, incomplete redirect, missing response, or network error
remains a failure or indeterminate outcome according to its direct evidence.

## Resource health

The remote critical-resource denominator contains Script, Stylesheet, and Font
requests for the main target, excluding:

- explicit loopback endpoints;
- failures explicitly blocked or aborted by browser policy.

Excluded events remain available under `local_observations` and
`browser_policy_observations`; they are not deleted. Private LAN addresses are
not loopback and remain eligible remote resources.

A remote resource failure burst still requires at least three unrecovered
failures and a failure ratio of at least 20 percent. Its summary includes
failure origins, host counts, and an explicit `retryable` flag.

## Local runtime plane

Each new analysis summary contains `local_runtime`, with independent checks for:

- expected versus unexpected Chrome exit;
- packet-capture lifecycle coverage;
- a bounded and verified Mihomo trace barrier.

Legacy Sessions without these fields remain readable and report unavailable
checks as `not_applicable`. Reanalysis cannot convert an explicitly failed
packet-capture lifecycle into a pass.

The pipeline UI displays this as `Sample Local runtime`, alongside Capture,
Correlation, and Application. Application issues also expose their source and
whether an automatic retry is justified.

## Attribution ambiguity

Multiple simultaneously active transport candidates remain `ambiguous` unless
a unique request ID, response endpoint lifecycle, CDP reuse chain, or packet
observation selects one candidate. Such unresolved records carry
`origin: evidence_limit`. Candidate IDs and evidence are retained for offline
analysis; no connection is selected by ordering or proximity alone.

## Regression scenarios

The automated suite covers the observed production patterns:

- iQiyi loopback probes refused on ports 16422/16423;
- Reuters/Stack Overflow intermediate HTTP error followed by final 2xx;
- QQ News remote critical-resource connection failures;
- browser-policy resource blocking;
- expected and unexpected Chrome lifecycles;
- verified and legacy unbounded trace inputs;
- unresolved response-endpoint ambiguity.

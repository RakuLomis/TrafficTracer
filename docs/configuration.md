# Target Configuration

TrafficTracer accepts one manual target or a YAML file containing a non-empty `sites` list. The UI loads the file through the Worker, validates and normalizes safe target fields, displays a preview, and submits only the selected entries.

The selected path must be absolute, point to a regular UTF-8 `.yaml` or `.yml` file, and be no larger than 1 MiB.

## Recommended format

```yaml
sites:
  - domain: example.com
    url: https://example.com/
    page_type: main-page
    wait: 10
    wait_load_timeout: 30
    traffic_type: all

  - domain: example.com
    url: https://example.com/video/1?quality=auto
    page_type: video-play1
    wait: 20
    wait_load_timeout: 45
    traffic_type: all
```

Use one entry for each page visit. Multiple entries for the same domain are valid and remain separate Sessions under one capture group.

## Site fields

| Field | Required | Default | Validation and meaning |
| --- | --- | --- | --- |
| `domain` | Yes | — | Valid DNS name, normalized to lowercase without a trailing dot. It groups related page Sessions in the output tree. |
| `url` | Yes | — | Absolute `http://` or `https://` URL without whitespace. The complete URL is preserved in metadata and request results. |
| `page_type` | Recommended | Derived | Readable directory label using lowercase letters, digits, and hyphens; maximum 64 characters. Must be unique after normalization within the loaded target set. |
| `wait` | No | `10` | Observation duration in seconds, from 1 through 86,400. |
| `wait_load_timeout` | No | `30` | Maximum navigation/load wait in seconds, from 1 through 3,600. |
| `traffic_type` | No | `all` | `tcp`, `udp`, or `all` selects captured network traffic. Other safe values are interpreted as legacy run labels and make the network selector default to `all`. |

Unknown global settings are not imported into a UI target preview. The UI owns runtime core, controller, interfaces, Chrome, storage, and cache-mode choices.

## Proxy protocol invariant

The capture form controls this runtime invariant; it is intentionally not a
sites.yaml field.

Strict single protocol is the recommended mode for comparison experiments. Before
packet capture starts, TrafficTracer resolves every selected proxy group to its
active leaf node. A batch freezes the observed leaf protocol once and persists it
in the batch manifest, including across resume. Mixed proxy protocols or a mismatch
with an explicitly expected protocol block the capture before evidence is written.

Observe only permits mixed or changing leaf protocols and reports the selected and
actually observed protocols afterward. DIRECT, reject, DNS, pass, compatible, and
other no-proxy/no-socket outcomes are excluded from the single-protocol set.

The optional expected protocol is case-insensitive and accepts a short identifier
such as hysteria2. Leave it empty to freeze the single selected leaf protocol
automatically.

## Bounded YouTube playback

YouTube video targets can request best-effort playback observation:

```yaml
- domain: youtube.com
  url: https://www.youtube.com/watch?v=VIDEO_ID
  page_type: youtube-video-play-1
  wait: 35
  traffic_type: all
  playback:
    provider: youtube
    ad_policy: click_visible_skip
    desired_primary_seconds: 25
```

`wait` remains the fixed capture window and starts when TrafficTracer issues the
navigation command. It is never extended or shortened because of an
advertisement. After a five-second preparation guard, the Worker uses scoped,
visible YouTube player controls and coordinate-based CDP mouse events to start
playback or click an offered Skip control. An unskippable ad is allowed to end
normally. All traffic remains in the raw evidence, including ads.

Primary content is confirmed only when a ready, unpaused, non-ad video advances
across consecutive observations. A player state that says "playing" while its
media time is stalled is not sufficient. `primary_content_observed` is therefore
the main scenario result. `desired_primary_seconds` is a quality goal, not a
second timeout: primary playback below the target is `degraded`, while a window
with no confirmed primary playback is `unavailable`. Neither condition changes
the completed state of the capture job itself.

The playback evidence also distinguishes no ad, an ad with no Skip control, a
Skip attempt, and a confirmed Skip followed by advancing primary content. A run
where no ad is served is valid and is not reported as an automation failure.
Playback requires CDP collection and is accepted only for `youtube.com`
subdomains or `youtu.be` URLs.

## Page-type normalization

Explicit `page_type` is authoritative. It must match:

```text
^[a-z0-9][a-z0-9-]{0,63}$
```

When `page_type` is absent, TrafficTracer derives it from `traffic_type` for compatibility:

- underscores and dots become hyphens;
- unsupported characters become hyphens;
- `Video-mainpage`, `video-main-page`, and `mainpage` normalize to `main-page`;
- repeated derived labels receive stable one-based suffixes;
- duplicate explicit labels are rejected.

New configurations should always set `page_type` and reserve `traffic_type` for `tcp`, `udp`, or `all`.

## Run-label warning

This warning is informational:

```text
sites[0].traffic_type='Video-mainpage' is a run label; network defaults to 'all'.
```

It means the legacy value is safe as a label but is not a network selector. The target remains usable. The normalized preview will show `network: all` and a derived page type. To remove the warning, use:

```yaml
page_type: main-page
traffic_type: all
```

## URL and directory names

The Session directory includes a readable URL slug:

```text
<page-type>__<scheme>_<host>_<path>
```

Unsafe path characters are replaced. Query strings and fragments cause an eight-character SHA-256 guard to be appended, and long slugs are truncated with the same guard. The full URL remains in `session.json` and the request index; directory names are only readable identifiers.

## Execution order

The preview preserves YAML order. When the user selects a subset, the selected targets retain their original order and execute serially. TrafficTracer never starts multiple page captures in parallel.

Before the next target begins, the Worker:

1. completes analysis or records the terminal failure;
2. closes only the Chrome processes it owns;
3. waits for its Chrome profile and debugging port to become quiescent;
4. advances the persistent batch cursor.

A resumable interruption stops the current child only after managed Chrome, packet capture, and tracing cleanup completes. Completed targets remain intact, later targets do not start, and the persistent cursor stays on the interrupted target. Resume creates a new child Session for that URL inside the same timestamped capture group. Terminal cancellation remains available through the Worker API for non-resumable administrative shutdowns.

### Bounded application retry

The UI option **Retry classified activity failure once** is outside
`sites.yaml`, defaults to enabled, can be explicitly disabled, and is frozen
into the Batch snapshot. It is evaluated only after a target has completed
capture, Chrome cleanup, and analysis. A retry requires an explicit failed or
indeterminate `activity_outcome.reason` from the Worker's fixed transient
allowlist. A systemic render-critical resource failure burst is the only
degraded state eligible for retry. The policy does not parse exception text or
infer failure from a slow page.

Eligible reasons cover transient main-document network, timeout, unknown
response, HTTP 408/429, HTTP 5xx, critical-resource bursts, and classified
playback startup or progress failures. Deterministic HTTP 4xx responses such as
404, recovered navigation, and positive playback below its duration goal are
recorded but are not retried.

At most one automatic retry is created for a target. It uses a new Job UUID,
managed Chrome profile/process, and Session directory. Batch manifest v2 keeps
both entries in the child's attempts list and keeps the child's top-level
session_id pointed at the effective final attempt. Resume never resets the
automatic retry budget.

## Runtime options outside the target file

These values are selected in the UI and are not overridden by `sites` entries:

- Session output root;
- TUN and physical interfaces;
- Chrome executable;
- `Cold` or `Warm` cache mode;
- `Standard` or `Full` analysis storage;
- active Mihomo profile, core, node, TUN, and system-proxy state.
- bounded application retry policy.

This separation prevents a target list from silently changing privileged networking or filesystem behavior.

## Cache modes

`Cold` is the UI default for new captures. Each Session gets an isolated browser profile, HTTP cache is disabled for navigation, Service Workers are bypassed, and the temporary profile is removed after the Worker-owned Chrome instance exits.

`Warm` reuses the profile scope intended for cache experiments. Use it only when cached or Service Worker behavior is part of the measurement. Legacy jobs that do not record a cache mode are interpreted as `Warm` for compatibility.

Even in `Cold` mode, the analysis reports what Chrome actually observed. Browser-internal, disk-cache, Service Worker, or prefetch-only target documents are not presented as network flows.

## Legacy standalone configuration

The Python library still understands a top-level `global` section for standalone CLI operation. TrafficTracer Complete UI imports only `sites` target data because Clash Verge owns the live proxy and TUN state. See `sites.example.yaml` and `sites.clash-verge.example.yaml` only when maintaining legacy CLI workflows.

## Machine-readable contract

The normalized preview conforms to `contracts/target-config.schema.json` and contains:

- source path and SHA-256;
- schema version;
- normalized target index, domain, URL, duration, network, run label, load timeout, and page type;
- validation warnings;
- an optional suggested output root.

The file SHA-256 and original target index are copied into Session provenance so a result can be traced back to the exact selected configuration.

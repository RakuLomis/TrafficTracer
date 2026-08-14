# Operations and Troubleshooting

This guide covers the live system state required by TrafficTracer Complete. Run diagnostics from the UI before changing configuration manually.

## Operational rules

- Do not run the entire application as root.
- Do not force-kill a working Clash Verge or Mihomo instance during a build or package verification.
- Do not start a development UI while the installed UI owns the same controller or service socket.
- Do not change the active core, profile, node, TUN, tracing, service, or system-proxy state during capture.
- Store Sessions in an absolute, writable, user-owned path with enough space for two raw PCAP streams.
- Treat proxy profiles, controller secrets, browser profiles, NetLog files, PCAP files, and Sessions as sensitive.

## Environment Check

Environment Check is the primary preflight. It validates:

- the selected core is the TrafficTracer build;
- Worker and Mihomo protocol capabilities match the component lock;
- the controller is reachable and authorized;
- tracing is available and not owned by a conflicting operation;
- the privileged service and IPC socket are ready when required;
- TUN state and the effective TUN device;
- the physical egress interface;
- Chrome discovery and debugging prerequisites;
- `dumpcap`/`tshark` availability and capture permissions;
- output-root existence, type, ownership, and writability;
- active-job and recovery state.

Resolve blocking diagnostics before capture. Warnings describe degraded or potentially ambiguous evidence but do not always prevent a run.

## Capture permissions

On Ubuntu, a narrowly scoped setup is:

```bash
sudo apt install tshark
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
getcap "$(command -v dumpcap)"
dumpcap -D
```

If package upgrades replace `dumpcap`, capabilities may need to be applied again. Distributions that use the `wireshark` group require a new login session after membership changes.

If interfaces appear in `dumpcap -D` but capture still fails, check that the selected names exactly match the active devices and that no security policy blocks packet capture.

## TUN interface

TrafficTracer distinguishes desired configuration from effective runtime state. The default TrafficTracer-aware Mihomo TUN device is normally `Meta`.

Leave the Traffic Tracer TUN field empty to use runtime discovery. Set an explicit value only when the active interface has a different known name. Verify with:

```bash
ip link show
ip address show
```

A profile or Settings field displaying another device name does not prove that device is active. Environment Check resolves the interface visible to `dumpcap` and the operating system.

## Physical interface

The physical interface must carry the outer proxy or direct socket after Mihomo routing. Find the default route with:

```bash
ip route show default
```

VPNs, multiple routing tables, policy routing, containers, and IPv6 can make the default route insufficient. Confirm the actual route to the selected proxy server when results show TUN packets but no physical-side evidence:

```bash
ip route get <proxy-ip>
ip -6 route get <proxy-ipv6>
```

Do not select a bridge, loopback, stale TUN device, or an interface that only carries unrelated management traffic.

## Service and IPC

The Linux service socket is:

```text
/run/clash-verge-service/service.sock
```

Service installation invokes a privileged helper and therefore displays an authentication prompt. `IPC path not ready` is not a proxy-node error. It means the application could not complete its post-install service handshake.

Check, without terminating the UI:

```bash
systemctl status clash-verge-service --no-pager
ls -l /run/clash-verge-service/service.sock
journalctl -u clash-verge-service --no-pager -n 100
```

Common causes are:

- the service failed before creating the socket;
- a package/helper and UI use incompatible service protocols;
- the socket path or parent permissions are wrong;
- the service is ready but the desktop process is still using older installed code;
- the installer returned before readiness and the bounded retry expired.

Use the service, install helper, and UI from the same Complete package. After an upgrade, exit the old UI normally and start the newly installed binary before retrying. Do not kill the core merely to inspect service state.

## All proxy nodes show error

If every latency test fails only in a new build and recovers after rollback, first suspect a mismatched packaged component or runtime configuration rather than every provider node failing at once.

Verify:

1. the active profile parses without errors;
2. the selected core is `verge-mihomo-tt`;
3. the packaged standard/alpha/TrafficTracer sidecars all exist;
4. `COMPONENTS` matches the source and service bundle;
5. the controller endpoint and secret come from the effective generated configuration;
6. DNS, rule data, and geodata resources are present;
7. service and UI were both restarted normally after installation.

Use application logs and controller diagnostics before changing multiple repositories or proxy rules.

## Output directory

The Session root can be any absolute directory the desktop user can create and write. Recommended checks are:

```bash
test -d /data/traffic_capture
test -w /data/traffic_capture
df -h /data/traffic_capture
```

TrafficTracer switches roots only while the Worker is idle. The UI sends the selected absolute path to the Worker, which validates it before accepting new jobs. Existing capture groups stay at their original paths.

Do not select:

- a relative path;
- a regular file;
- a root owned only by `root`;
- a removable or network mount that may disappear during capture;
- the application data directory when you intend to delete application state independently;
- `/tmp` for long-lived results.

When a custom root fails, inspect the Environment Check result for the resolved path, filesystem permissions, and active-job lock instead of manually copying partial Sessions.

## Session selection and corrupt Sessions

The UI opens one timestamped capture-group directory, not an aggregate of every directory under the Session root. When idle, it intentionally shows no implicit historical scope; select a timestamp folder explicitly.

A directory is recognized only when it matches a supported layout and contains a valid Session manifest. Chrome profile directories, batch internals, extension manifests, and arbitrary JSON files are ignored.

If a Session is marked corrupt:

1. open the exact selected timestamp folder;
2. identify the reported Session path and manifest error;
3. verify `session.json` is complete UTF-8 JSON and uses schema 1 or 2;
4. verify registered artifact paths remain relative and inside the Session;
5. do not replace the manifest with a Chrome extension `manifest.json`;
6. preserve raw evidence before attempting manual recovery.

The scanner reports one damaged Session without invalidating healthy siblings.

## Capture appears stuck

The capture card reports target number, stage, elapsed progress, and terminal error. A long configured `wait` is not a deadlock. Navigation, Chrome shutdown, packet finalization, and analysis each have separate bounded phases.

For a YAML batch that remains on one target:

- check whether the observation duration is still active;
- check the current stage and last progress notification;
- inspect whether Chrome navigation reached its load timeout;
- inspect managed Chrome quiescence status;
- inspect analysis logs for packet parsing or contract validation;
- request cancellation from the UI instead of killing the Worker.

Cancellation may take a bounded cleanup interval because raw artifacts and tracing must be finalized safely.

## Analysis failed

Analysis validates all serialized contracts. Typical classes are:

- malformed or incomplete pre/post tuple fields;
- missing required raw artifacts;
- invalid IP address or port formats;
- stale artifacts from a different analysis generation;
- inconsistent canonical and legacy projections;
- corrupted NetLog or tracing JSONL;
- selected interfaces with no relevant packets.

The terminal Session error includes a stable code and stage. Preserve the full Session, especially `raw/`, before re-analysis. A new analysis generation should be created instead of editing canonical output manually.

For a timestamp-group packet split, use **Split missing** for untouched Standard Sessions and **Repair incomplete** only for `partial` or `stale` items. Inspect `packet-split-manifest.json` for the last child error and final status. Do not create placeholder split directories or copy indexes between Sessions. After interruption, restart the group operation and let it rescan published evidence.

## Capture completed but quality is degraded

This can be correct. Common reasons include:

- target document served only from disk cache, Service Worker, or prefetch;
- navigation failed before a socket was dispatched;
- the page was reachable but no target document network request occurred;
- the browser emitted background traffic but no page-attributed transport;
- a route was intentionally rejected;
- egress failed before an outbound socket;
- packet evidence was not applicable or not requested in `Standard` mode.

Inspect page quality, request observations, attribution scope, post-flow disposition, and egress establishment separately. Do not judge correctness from one aggregate count.

## Network reachability changes between nodes

Changing a proxy node can change DNS behavior, IP family, route, transport protocol, remote filtering, and proxy reachability. A site-specific failure after node selection does not necessarily indicate a TrafficTracer regression.

Record the selected node and effective configuration from the Session context, then compare:

- direct and proxy route decisions;
- DNS answers and IPv4/IPv6 availability;
- terminal Mihomo errors;
- proxy-server reachability;
- target document request observation;
- physical-interface packets.

TrafficTracer classifies known reject and failure outcomes so they remain valid evidence instead of aborting the entire batch when policy semantics explain them.

## Installation path errors

These commands are different:

```bash
sudo apt install ./TrafficTracer-Complete_1.0.0_linux_x86_64.deb
sudo dpkg -i ./TrafficTracer-Complete_1.0.0_linux_x86_64.deb
```

`apt install` resolves dependencies; `dpkg -i` only installs the local package and may leave dependencies unresolved. Without `./` or an absolute path, `apt` searches package repositories and reports that it cannot locate the package.

An `_apt` unsandboxed-download notice for a local file usually means `_apt` cannot traverse one of its parent directories. The install can still succeed, but the cleaner fix is to place the package in a readable directory or adjust parent traversal permissions without exposing private data.

## Logs to collect for a bug report

Provide sanitized copies of:

- TrafficTracer UI/backend logs;
- Worker terminal error and stage;
- `session.json` and `summary.json`;
- `capture-context.json` with secrets removed;
- exact package `VERSION` and `COMPONENTS`;
- the normalized target preview or a credential-free reproduction YAML;
- relevant service status/journal excerpts.

Do not publish subscription URLs, controller secrets, proxy credentials, browser profiles, complete private URLs, NetLog, tracing logs, or PCAP without reviewing their contents.

# TrafficTracer CDP Collection Design

## Overview

Add CDP (Chrome DevTools Protocol) request-level semantic collection to the existing Mihomo + tshark + Chrome NetLog capture pipeline. Fix Chrome shutdown to reduce NetLog truncation, and add NetLog JSON repair.

## Architecture Decision

**CDP client is async internally, wrapped in a sync interface for pipeline.py.** The pipeline remains synchronous (time.sleep, subprocess) while the CDP client uses asyncio + websockets internally. Each sync wrapper method calls `asyncio.run()`.

## New Files

### `traffictracer/capture/cdp.py`

Async CDP client using `websockets` library.

```
CDPClient (asyncio)
├── connect_to_page()      → GET /json/version → ws connect
├── start_reader()         → background asyncio task consuming ws
│   ├── has "id"          → resolve pending command Future
│   └── no "id"           → append to events list
├── send(method, params, timeout) → send command, await matching response
├── enable_domains()       → Network.enable + Page.enable
├── navigate(url)          → Page.navigate → wait Page.loadEventFired or timeout
├── collect(seconds)       → sleep + snapshot events list
├── close_browser()        → Browser.close
├── close()                → cancel reader + close ws
└── SyncCDPClient           → sync wrapper calling asyncio.run()
```

Key design rules:
- All commands carry a timeout (default 10s)
- Never `ws.recv()` directly after `ws.send()` — reader task handles all
- Reader task is a background `asyncio.create_task`, canceled on close
- No waiting for WebSocket close or Network.loadingFinished
- Events saved as list[dict] for JSON export

### `traffictracer/capture/netlog_fix.py`

Standalone NetLog JSON repair:

- `validate_json(path) → bool` — `json.load()` success check
- `repair_truncated_netlog(path) → bool`:
  1. If valid, return True (no-op)
  2. Copy original to `*.truncated.bak`
  3. Strip trailing comma from last line
  4. Append `]}\n`
  5. Re-validate; on failure, restore backup, return False

## Modified Files

### `traffictracer/config.py`

Extend `ChromeConfig` (all new fields have defaults):
- `enable_cdp: bool = True`
- `remote_debugging_port: int = 9222`
- `netlog_capture_mode: str = "Default"`
- `graceful_close_timeout: int = 20`

Extend `SiteConfig`:
- `wait_load_timeout: int = 30`

Backward compatible — existing `sites.yaml` works without changes.

### `traffictracer/capture/chrome.py`

Extend `launch_chrome()` signature:
- `remote_debugging_port: int | None = None`
- `netlog_capture_mode: str = "Default"`
- `open_url: bool = True`
- `extra_args: list[str] | None = None`

When CDP enabled (remote_debugging_port is set):
- Add `--remote-debugging-port={port}` and `--remote-allow-origins=*`
- Open `about:blank` instead of target URL
- Add `--net-log-capture-mode={mode}`

Add `wait_chrome_exit(proc, timeout=20) → bool`:
- `proc.wait(timeout)`, return True on exit, False on timeout

Rename `kill_chrome` → `terminate_chrome` (same logic: SIGTERM → wait 10s → SIGKILL).

### `traffictracer/capture/pipeline.py`

`_capture_domain()` restructured with CDP path:

```
CDP enabled:
  1. launch Chrome (about:blank, CDP port)
  2. SyncCDPClient: connect → enable domains → navigate(url)
  3. CDP client collect events for site.wait seconds
  4. CDP Browser.close
  5. wait_chrome_exit(timeout)
  6. if not exited: terminate_chrome()
  7. Export CDP events → logs/cdp_{domain}_{run_tag}.json

CDP disabled (original path):
  1. launch Chrome (target URL)
  2. sleep(site.wait)
  3. terminate Chrome

Shared after Chrome close:
  1. repair NetLog
  2. stop tshark
  3. disable tracing
```

Output: `logs/cdp_{domain}_{run_tag}.json` in addition to existing artifacts.

### `sites.example.yaml` and `README.md`

Update example config with new CDP fields. Update README to document CDP collection, NetLog repair, and graceful shutdown.

## CDP Events Collected

Network domain:
- `requestWillBeSent`, `requestWillBeSentExtraInfo`
- `responseReceived`, `responseReceivedExtraInfo`
- `loadingFinished`, `loadingFailed`
- `webSocketCreated`, `webSocketWillSendHandshakeRequest`
- `webSocketHandshakeResponseReceived`, `webSocketFrameSent`, `webSocketFrameReceived`

Page domain:
- `frameStartedLoading`, `frameStoppedLoading`
- `loadEventFired`, `domContentEventFired`

## Data Link

```
CDP request → NetLog URL_REQUEST / socket / QUIC session → Mihomo pre/post proxy mapping → pcap flow
```

## Implementation Order

1. `config.py` — add new fields (no dependencies)
2. `netlog_fix.py` — standalone utility
3. `cdp.py` — CDP client (depends on websockets)
4. `chrome.py` — extend launch + add wait/terminate
5. `pipeline.py` — wire everything together
6. `sites.example.yaml` + `README.md` — docs
7. Tests — `test_netlog_fix.py`, `test_cdp.py`, update existing tests

## Testing

| Test | Scope |
|------|-------|
| `test_netlog_fix.py` | Valid/truncated/malformed JSON, backup |
| `test_cdp.py` | CDPClient with mocked websocket |
| `test_chrome.py` | Extended with wait_chrome_exit |
| `test_config.py` | New fields, backward compat |
| `test_capture_pipeline.py` | Config with/without CDP |

## Dependencies

New: `websockets` (pip install websockets) for async WebSocket.

## Backward Compatibility

- `enable_cdp: false` → original flow, no `cdp_*.json` generated
- Old `sites.yaml` → all new fields have defaults
- `--only` CLI unchanged
- Existing output files unchanged

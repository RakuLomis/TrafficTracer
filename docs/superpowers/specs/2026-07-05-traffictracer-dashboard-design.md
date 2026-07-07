# TrafficTracer Dashboard Design Spec

## Overview

A web-based dashboard for TrafficTracer that provides site configuration, one-click capture/analysis, real-time log streaming, and correlation result browsing. Complements metacubexd (proxy management) to form a complete workflow:

```
metacubexd (:9099/ui)              TrafficTracer Dashboard (:5080)
─────────────────────────          ─────────────────────────────────
Configure proxy nodes              Configure target sites
Enable TUN mode                    One-click capture
Verify connectivity                One-click analysis
Manage rules                       View correlation results
                                   Browse session history
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  mihomo REST API (:9099)                            │
│  ├─ /proxies     ← metacubexd 调用                 │
│  ├─ /connections                                    │
│  ├─ /experimental/tracing                           │
│  └─ /ui → metacubexd (静态文件, external-ui)         │
├─────────────────────────────────────────────────────┤
│  TrafficTracer Dashboard (:5080)                    │
│  ├─ FastAPI + uvicorn                               │
│  ├─ WebSocket 实时日志推送                            │
│  ├─ subprocess 调用 capture.py / analyze.py         │
│  └─ 读写 sites.yaml + session 目录                   │
├─────────────────────────────────────────────────────┤
│  TrafficTracer Core                                 │
│  ├─ capture.py (CLI, 无改动)                        │
│  ├─ analyze.py (CLI, 无改动)                        │
│  └─ traffictracer/  (core logic, 无改动)            │
└─────────────────────────────────────────────────────┘
```

## Technology Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Backend | FastAPI + uvicorn | Async, WebSocket, lightweight |
| Frontend | HTML + HTMX + vanilla JS | Zero build step, single-file templates |
| Storage | Filesystem (session directories) | No database needed |
| Process mgmt | `subprocess.Popen` + `asyncio` | Reuse existing CLI pipelines |

## Page Structure

### `/` — Home (Site Configuration + Capture)

- Editable form for `sites.yaml` fields:
  - Mihomo binary path, config path, API URL
  - Chrome binary, user_data_dir, headless toggle
  - Network: TUN interface, physical interface
  - Output base directory
  - Sites list: domain, URL, wait, traffic_type (add/remove rows)
- `[Save Config]` — writes `sites.yaml`
- `[Run Capture]` — starts capture in background, transitions to live log view
- Site selector (single site or all)

### `/sessions` — Session History

- Table of all capture sessions:
  - Timestamp
  - Status badge (capturing / captured / analyzed / error)
  - Stats: tun.pcap size, phys.pcap size, flow count, subdomain count
  - Click row → session detail
  - Sort by time (newest first)

### `/session/<id>` — Session Detail

- Overview card:
  - Session path, timestamp, duration
  - File sizes: tun.pcap, phys.pcap, netlog, mihomo trace
- If analyzed: correlation summary table
  - Domain | Relation | Flows
  - Expandable per-flow detail:
    - pre_proxy: src → dst
    - post_proxy: src → dst
- `[Run Analysis]` button (if not yet analyzed)
- Live log panel (collapsible, auto-scroll)

### `/capture/<id>/log` — Live Log (WebSocket)

- Real-time streaming of `capture.py` / `analyze.py` stdout
- Auto-scroll to bottom
- Color-coded: INFO (green), WARNING (yellow), ERROR (red)
- Status indicator: running spinner / checkmark / error icon

## API Endpoints

### Configuration

```
GET  /api/config
  → { "global": {...}, "sites": [...] }

PUT  /api/config
  ← { "global": {...}, "sites": [...] }
  → { "ok": true }
```

### Capture

```
POST /api/capture/start
  ← { "only": "bilibili.com" }   # optional, omit for all sites
  → { "session_id": "2026-07-05_21-45-51", "status": "running" }

GET  /api/capture/<id>/status
  → { "session_id": "...", "status": "running|done|error",
      "session_dir": "/data/datasets/ttTest-0705/2026-07-05_21-45-51",
      "error": null }

WS   /api/capture/<id>/log
  → 推送每一行 stdout
  → {"line": "2026-07-05 ... [INFO] Starting Mihomo..."}
  → {"line": "..."}
```

### Sessions

```
GET  /api/sessions
  → [
      {
        "id": "2026-07-05_21-45-51",
        "path": "/data/datasets/ttTest-0705/2026-07-05_21-45-51",
        "status": "analyzed",
        "stats": {
          "tun_pcap_bytes": 844288,
          "phys_pcap_bytes": 16384,
          "netlog_bytes": 5452595,
          "trace_bytes": 23552,
          "total_flows": 17,
          "subdomains": ["www.bilibili.com", "api.bilibili.com", ...]
        }
      },
      ...
    ]

GET  /api/session/<id>
  → {
      "id": "...",
      "status": "analyzed",
      "stats": { ... },
      "correlation": { "bilibili.com": [ ... ] }
    }

POST /api/session/<id>/analyze
  → { "status": "running" }
  → starts backend analysis, returns immediately

WS   /api/session/<id>/log
  → 推送 analyze.py stdout
```

## Data Flow

```
User clicks [Run Capture]
  → POST /api/capture/start
  → FastAPI spawns subprocess: python3 capture.py --config sites.yaml --only <domain>
  → stdout lines are pushed via WebSocket to frontend
  → on process exit, session status updated to "done" or "error"
  → frontend updates session list

User clicks [Run Analysis] on session detail page
  → POST /api/session/<id>/analyze
  → FastAPI spawns: python3 analyze.py --session <dir>
  → stdout lines pushed via WebSocket
  → on complete, correlation.json is read and returned
  → frontend refreshes correlation table
```

## Error Handling

- **Capture fails**: mihomo crash, tshark permission, Chrome unavailable → error logged, WS pushes error line, session marked "error", error message shown on detail page
- **NetLog truncated**: analysis may fail with JSON parse error → shown in log, user can fix manually or retry
- **Config invalid**: PUT /api/config validates YAML syntax before saving → 400 with error detail
- **Session not found**: 404 with message

## Non-Requirements

- pcap file viewer (out of scope)
- proxy node management (handled by metacubexd)
- authentication / multi-user (single local machine)
- database persistence (filesystem is sufficient)

## File Layout

```
TrafficTracer/
├── dashboard/
│   ├── server.py              # FastAPI app, routes, WebSocket handlers
│   ├── templates/
│   │   ├── base.html          # layout, nav, HTMX setup
│   │   ├── index.html         # home: config form + capture control
│   │   ├── sessions.html      # session history table
│   │   └── session.html       # session detail + correlation
│   └── static/
│       └── app.js             # WebSocket client, HTMX extensions
├── capture.py                 # existing CLI (no changes)
├── analyze.py                 # existing CLI (no changes)
├── sites.yaml                 # existing config (no changes)
└── traffictracer/             # existing core (no changes)
```

## Deployment

```bash
# Install dependency
pip install fastapi uvicorn pyyaml

# Start dashboard
cd TrafficTracer
python -m uvicorn dashboard.server:app --host 127.0.0.1 --port 5080

# metacubexd is served by mihomo's external-ui at :9099/ui
```

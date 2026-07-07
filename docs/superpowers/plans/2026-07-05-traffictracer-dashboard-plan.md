# TrafficTracer Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a FastAPI web dashboard for configuring TrafficTracer, running capture/analysis pipelines with real-time log streaming, and browsing session history with correlation results.

**Architecture:** FastAPI serves HTML templates (Jinja2 + HTMX), WebSocket for live log streaming, and `subprocess.Popen` with `asyncio` to execute the existing `capture.py` and `analyze.py` CLIs. No changes to the core pipelines.

**Tech Stack:** FastAPI, uvicorn, Jinja2, HTMX, vanilla JS (WebSocket client), Python asyncio subprocess

## Global Constraints

- Python 3.10+ with pyyaml already available
- No changes to existing `capture.py`, `analyze.py`, `traffictracer/` package
- Dashboard runs on `:5080` (hardcoded for now)
- Single-user, local machine, no authentication
- Filesystem-based storage (session directories), no database
- Frontend: zero build step, single-file HTML templates with HTMX loaded from CDN

---

### Task 1: Scaffold dashboard module and FastAPI server

**Files:**
- Create: `dashboard/__init__.py`
- Create: `dashboard/server.py`

**Interfaces:**
- Produces: `app` (FastAPI instance), `start_dashboard()` entry point

- [ ] **Step 1: Create `dashboard/__init__.py`**

```python
"""TrafficTracer Web Dashboard."""
```

- [ ] **Step 2: Create `dashboard/server.py` with minimal FastAPI app**

```python
"""TrafficTracer Dashboard — FastAPI server."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parent.parent

app = FastAPI(title="TrafficTracer Dashboard")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.get("/")
async def index():
    """Redirect to dashboard home."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/config")


def start_dashboard(host: str = "127.0.0.1", port: int = 5080):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_dashboard()
```

- [ ] **Step 3: Install FastAPI and test startup**

```bash
pip install fastapi uvicorn python-multipart
cd /data/ytluo/projects/TrafficTracer
python -c "from dashboard.server import app; print('OK')"
# Expected: OK
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/__init__.py dashboard/server.py
git commit -m "feat: scaffold dashboard module with FastAPI server"
```

---

### Task 2: Config API — read and write sites.yaml

**Files:**
- Create: `dashboard/config_manager.py`
- Modify: `dashboard/server.py` — add `/api/config` routes

**Interfaces:**
- Consumes: `app` (from Task 1)
- Produces: `load_config_dict(path: str) -> dict`, `save_config_dict(path: str, data: dict) -> None`

- [ ] **Step 1: Create `dashboard/config_manager.py`**

```python
"""Read and write TrafficTracer sites.yaml configuration."""

from pathlib import Path
import yaml

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent.parent / "sites.yaml")


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    """Load sites.yaml and return normalized dict."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_config(data: dict, path: str = DEFAULT_CONFIG_PATH) -> None:
    """Write dict back to sites.yaml, preserving structure."""
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
```

- [ ] **Step 2: Add GET /api/config and PUT /api/config to server.py**

```python
from dashboard.config_manager import load_config, save_config


@app.get("/api/config")
async def api_get_config():
    return load_config()


@app.put("/api/config")
async def api_put_config(data: dict):
    save_config(data)
    return {"ok": True}
```

- [ ] **Step 3: Test the API**

```bash
cd /data/ytluo/projects/TrafficTracer
python -m uvicorn dashboard.server:app --port 5080 &
sleep 2
curl -s http://127.0.0.1:5080/api/config | python3 -c "import json,sys; d=json.load(sys.stdin); print(list(d.keys()))"
# Expected: ['global', 'sites']
curl -s -X PUT http://127.0.0.1:5080/api/config -H "Content-Type: application/json" -d '{"test":1}'
# Expected: {"ok":true}
kill %1
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/config_manager.py dashboard/server.py
git commit -m "feat: add config API endpoints for sites.yaml"
```

---

### Task 3: Base HTML template with navigation

**Files:**
- Create: `dashboard/templates/base.html`
- Create: `dashboard/static/app.js`

**Interfaces:**
- Consumes: templates engine (from Task 1)
- Produces: base layout Jinja2 template used by all pages

- [ ] **Step 1: Create `dashboard/templates/base.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrafficTracer Dashboard</title>
    <script src="https://unpkg.com/htmx.org@2.0.4"></script>
    <script src="https://unpkg.com/htmx-ext-ws@2.0.0/ws.js"></script>
    <script src="/static/app.js" defer></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: ui-monospace, monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
        nav { display: flex; gap: 16px; margin-bottom: 24px; padding-bottom: 12px; border-bottom: 1px solid #30363d; }
        nav a { color: #58a6ff; text-decoration: none; font-size: 14px; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 1100px; margin: 0 auto; }
        table { width: 100%; border-collapse: collapse; margin: 12px 0; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d; font-size: 13px; }
        th { color: #8b949e; font-weight: normal; }
        button, .btn { background: #238636; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
        button:hover { background: #2ea043; }
        button.secondary { background: #30363d; color: #c9d1d9; }
        button.secondary:hover { background: #484f58; }
        input, select { background: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 10px; border-radius: 6px; font-size: 13px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
        .badge-green { background: #23863633; color: #3fb950; }
        .badge-yellow { background: #9e6a0333; color: #d2991d; }
        .badge-red { background: #da363333; color: #f85149; }
        .log-panel { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; max-height: 400px; overflow-y: auto; font-size: 12px; font-family: ui-monospace, monospace; white-space: pre-wrap; }
        .log-info { color: #3fb950; }
        .log-warn { color: #d2991d; }
        .log-error { color: #f85149; }
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <strong>TrafficTracer</strong>
            <a href="/config">Config</a>
            <a href="/sessions">Sessions</a>
        </nav>
        {% block content %}{% endblock %}
    </div>
</body>
</html>
```

- [ ] **Step 2: Create `dashboard/static/app.js` with WebSocket log helper**

```javascript
function startLogStream(wsUrl, panelId) {
    const panel = document.getElementById(panelId);
    if (!panel) return;
    panel.innerHTML = '';
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (e) => {
        const data = JSON.parse(e.data);
        const line = document.createElement('div');
        let cls = 'log-info';
        if (data.line.includes('[WARNING') || data.line.includes('[WARN')) cls = 'log-warn';
        if (data.line.includes('[ERROR')) cls = 'log-error';
        line.className = cls;
        line.textContent = data.line;
        panel.appendChild(line);
        panel.scrollTop = panel.scrollHeight;
    };
    ws.onclose = () => {
        const line = document.createElement('div');
        line.className = 'log-info';
        line.textContent = '--- Log stream ended ---';
        panel.appendChild(line);
    };
    ws.onerror = () => {
        const line = document.createElement('div');
        line.className = 'log-error';
        line.textContent = '--- Log stream error ---';
        panel.appendChild(line);
    };
}
```

- [ ] **Step 3: Add a test route to verify template rendering**

```python
@app.get("/test-base")
async def test_base(request: Request):
    return templates.TemplateResponse("base.html", {"request": request, "content": "<p>OK</p>"})
```

Add `from fastapi import Request` to imports. Test:

```bash
cd /data/ytluo/projects/TrafficTracer
python -m uvicorn dashboard.server:app --port 5080 &
sleep 1
curl -s http://127.0.0.1:5080/test-base | grep -o "TrafficTracer Dashboard"
# Expected: TrafficTracer Dashboard
kill %1
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/templates/base.html dashboard/static/app.js dashboard/server.py
git commit -m "feat: add base HTML template, nav, and WebSocket log helper"
```

---

### Task 4: Config page — editable sites.yaml form

**Files:**
- Create: `dashboard/templates/config.html`
- Modify: `dashboard/server.py` — add `/config` route

**Interfaces:**
- Consumes: base.html template, /api/config endpoints
- Produces: Config management page at `/config`

- [ ] **Step 1: Create `dashboard/templates/config.html`**

```html
{% extends "base.html" %}
{% block content %}
<h2>Site Configuration</h2>

<form id="config-form" hx-put="/api/config" hx-swap="none">
  <h3>Global</h3>
  <table>
    <tr><th>Mihomo Binary</th><td><input name="mihomo_binary" style="width:400px"></td></tr>
    <tr><th>Mihomo Config</th><td><input name="mihomo_config" style="width:400px"></td></tr>
    <tr><th>Mihomo API</th><td><input name="mihomo_api" style="width:300px"></td></tr>
    <tr><th>Chrome Binary</th><td><input name="chrome_binary" style="width:400px"></td></tr>
    <tr><th>Chrome User Data Dir</th><td><input name="chrome_user_data_dir" style="width:400px"></td></tr>
    <tr><th>Headless</th><td><select name="chrome_headless"><option value="true">true</option><option value="false">false</option></select></td></tr>
    <tr><th>TUN Interface</th><td><input name="tun_interface"></td></tr>
    <tr><th>Physical Interface</th><td><input name="phys_interface"></td></tr>
    <tr><th>Output Base Dir</th><td><input name="output_base_dir" style="width:400px"></td></tr>
  </table>

  <h3>Sites</h3>
  <table id="sites-table">
    <thead><tr><th>Domain</th><th>URL</th><th>Wait (s)</th><th>Traffic Type</th><th></th></tr></thead>
    <tbody></tbody>
  </table>
  <button type="button" class="secondary" onclick="addSiteRow()">+ Add Site</button>

  <br><br>
  <button type="submit">Save Config</button>
</form>

<script>
function addSiteRow() {
    const tbody = document.querySelector('#sites-table tbody');
    const i = tbody.children.length;
    const row = document.createElement('tr');
    row.innerHTML = `
        <td><input name="site_${i}_domain"></td>
        <td><input name="site_${i}_url" style="width:300px"></td>
        <td><input name="site_${i}_wait" type="number" value="10" style="width:60px"></td>
        <td><input name="site_${i}_traffic_type" value="all"></td>
        <td><button type="button" class="secondary" onclick="this.closest('tr').remove()">X</button></td>
    `;
    tbody.appendChild(row);
}

fetch('/api/config').then(r => r.json()).then(cfg => {
    const g = cfg.global || {};
    document.querySelector('[name=mihomo_binary]').value = g.mihomo?.binary || '';
    document.querySelector('[name=mihomo_config]').value = g.mihomo?.config || '';
    document.querySelector('[name=mihomo_api]').value = g.mihomo?.api || '';
    document.querySelector('[name=chrome_binary]').value = g.chrome?.binary || '';
    document.querySelector('[name=chrome_user_data_dir]').value = g.chrome?.user_data_dir || '';
    document.querySelector('[name=chrome_headless]').value = String(g.chrome?.headless || false);
    document.querySelector('[name=tun_interface]').value = g.network?.tun_interface || '';
    document.querySelector('[name=phys_interface]').value = g.network?.phys_interface || '';
    document.querySelector('[name=output_base_dir]').value = g.output?.base_dir || '';
    (cfg.sites || []).forEach(s => {
        addSiteRow();
        const i = document.querySelectorAll('#sites-table tbody tr').length - 1;
        document.querySelector(`[name=site_${i}_domain]`).value = s.domain || '';
        document.querySelector(`[name=site_${i}_url]`).value = s.url || '';
        document.querySelector(`[name=site_${i}_wait]`).value = s.wait || 10;
        document.querySelector(`[name=site_${i}_traffic_type]`).value = s.traffic_type || 'all';
    });
    if (!cfg.sites || cfg.sites.length === 0) addSiteRow();
});

document.getElementById('config-form').addEventListener('htmx:beforeRequest', function(evt) {
    const fd = new FormData(evt.target);
    const sites = [];
    let i = 0;
    while (fd.has(`site_${i}_domain`)) {
        sites.push({
            domain: fd.get(`site_${i}_domain`),
            url: fd.get(`site_${i}_url`),
            wait: parseInt(fd.get(`site_${i}_wait`)) || 10,
            traffic_type: fd.get(`site_${i}_traffic_type`) || 'all'
        });
        i++;
    }
    const body = {
        global: {
            mihomo: {
                binary: fd.get('mihomo_binary'),
                config: fd.get('mihomo_config'),
                api: fd.get('mihomo_api')
            },
            chrome: {
                binary: fd.get('chrome_binary'),
                user_data_dir: fd.get('chrome_user_data_dir'),
                headless: fd.get('chrome_headless') === 'true'
            },
            network: {
                tun_interface: fd.get('tun_interface'),
                phys_interface: fd.get('phys_interface')
            },
            output: {
                base_dir: fd.get('output_base_dir')
            }
        },
        sites: sites.filter(s => s.domain)
    };
    evt.detail.body = JSON.stringify(body);
    evt.detail.headers = {'Content-Type': 'application/json'};
});
</script>
{% endblock %}
```

- [ ] **Step 2: Add `/config` route to server.py**

```python
@app.get("/config")
async def page_config(request: Request):
    return templates.TemplateResponse("config.html", {"request": request})
```

- [ ] **Step 3: Test the page**

```bash
cd /data/ytluo/projects/TrafficTracer
python -m uvicorn dashboard.server:app --port 5080 &
sleep 1
curl -s http://127.0.0.1:5080/config | grep -o "Site Configuration"
# Expected: Site Configuration
kill %1
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/templates/config.html dashboard/server.py
git commit -m "feat: add config page with editable sites.yaml form"
```

---

### Task 5: Session scanner — discover and list sessions from filesystem

**Files:**
- Create: `dashboard/session_store.py`
- Modify: `dashboard/server.py` — add `/api/sessions` and `/sessions` page route

**Interfaces:**
- Consumes: `app` (from Task 1)
- Produces: `list_sessions(base_dir: str) -> list[dict]`, `get_session(base_dir: str, session_id: str) -> dict | None`

- [ ] **Step 1: Create `dashboard/session_store.py`**

```python
"""Session discovery from filesystem output directories."""

from pathlib import Path
import json
import os


def list_sessions(base_dir: str) -> list[dict]:
    """Scan output directory and return all sessions sorted newest first."""
    base = Path(base_dir)
    if not base.exists():
        return []
    sessions = []
    for d in sorted(base.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        sid = d.name
        stats = _session_stats(d)
        status = _session_status(d, stats)
        sessions.append({
            "id": sid,
            "path": str(d),
            "status": status,
            "stats": stats,
        })
    return sessions


def get_session(base_dir: str, session_id: str) -> dict | None:
    """Get a single session with correlation data."""
    d = Path(base_dir) / session_id
    if not d.exists():
        return None
    stats = _session_stats(d)
    status = _session_status(d, stats)
    correlation = None
    corr_path = d / "results" / "correlation.json"
    if corr_path.exists():
        try:
            with open(corr_path) as f:
                correlation = json.load(f)
        except Exception:
            pass
    return {
        "id": session_id,
        "path": str(d),
        "status": status,
        "stats": stats,
        "correlation": correlation,
    }


def _session_stats(d: Path) -> dict:
    """Collect file sizes and flow counts for a session."""
    stats = {"tun_pcap_bytes": 0, "phys_pcap_bytes": 0, "netlog_bytes": 0, "trace_bytes": 0, "total_flows": 0, "subdomains": []}
    caps_dir = d / "captures"
    logs_dir = d / "logs"

    for domain_dir in caps_dir.glob("*"):
        if domain_dir.is_dir():
            tun = domain_dir / "tun.pcap"
            phys = domain_dir / "phys.pcap"
            if tun.exists():
                stats["tun_pcap_bytes"] += tun.stat().st_size
            if phys.exists():
                stats["phys_pcap_bytes"] += phys.stat().st_size
            flows_dir = domain_dir / "flows"
            if flows_dir.exists():
                for subdomain_dir in flows_dir.glob("*/*"):
                    if subdomain_dir.is_dir():
                        stats["total_flows"] += 1
                        stats["subdomains"].append(subdomain_dir.name)
                        break
                for subdomain_dir in flows_dir.glob("*/*"):
                    if subdomain_dir.is_dir() and subdomain_dir.name not in stats["subdomains"]:
                        stats["subdomains"].append(subdomain_dir.name)

    if logs_dir.exists():
        for f in logs_dir.glob("netlog_*.json"):
            stats["netlog_bytes"] += f.stat().st_size
        for f in logs_dir.glob("mihomo_trace_*.jsonl"):
            stats["trace_bytes"] += f.stat().st_size

    stats["subdomains"] = list(set(stats["subdomains"]))
    return stats


def _session_status(d: Path, stats: dict) -> str:
    """Determine session status."""
    if (d / "results" / "correlation.json").exists():
        return "analyzed"
    if any((d / "logs").glob("*.json*")):
        return "captured"
    caps = d / "captures"
    if caps.exists() and any(caps.glob("*/*.pcap")):
        return "captured"
    return "empty"
```

- [ ] **Step 2: Add `/api/sessions` and `/api/session/<id>` routes**

```python
from dashboard.session_store import list_sessions, get_session
from dashboard.config_manager import load_config


@app.get("/api/sessions")
async def api_sessions():
    cfg = load_config()
    base_dir = cfg.get("global", {}).get("output", {}).get("base_dir", "./output")
    return list_sessions(base_dir)


@app.get("/api/session/{session_id}")
async def api_session(session_id: str):
    cfg = load_config()
    base_dir = cfg.get("global", {}).get("output", {}).get("base_dir", "./output")
    s = get_session(base_dir, session_id)
    if s is None:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "not found"}, status_code=404)
    return s
```

- [ ] **Step 3: Test the API**

```bash
cd /data/ytluo/projects/TrafficTracer
python -m uvicorn dashboard.server:app --port 5080 &
sleep 1
curl -s http://127.0.0.1:5080/api/sessions | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d), 'sessions')"
# Expected: N sessions (where N is count in /data/datasets/ttTest-0705)
kill %1
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/session_store.py dashboard/server.py
git commit -m "feat: add session discovery and listing from filesystem"
```

---

### Task 6: Sessions page — history list

**Files:**
- Create: `dashboard/templates/sessions.html`
- Modify: `dashboard/server.py` — add `/sessions` route

**Interfaces:**
- Consumes: base.html, /api/sessions
- Produces: Sessions list page at `/sessions`

- [ ] **Step 1: Create `dashboard/templates/sessions.html`**

```html
{% extends "base.html" %}
{% block content %}
<h2>Sessions</h2>
<table>
    <thead>
        <tr>
            <th>Session</th>
            <th>Status</th>
            <th>TUN (pcap)</th>
            <th>Phys (pcap)</th>
            <th>Flows</th>
            <th>Subdomains</th>
            <th></th>
        </tr>
    </thead>
    <tbody id="sessions-body">
        <tr><td colspan="7">Loading...</td></tr>
    </tbody>
</table>

<script>
fetch('/api/sessions').then(r => r.json()).then(sessions => {
    const tbody = document.getElementById('sessions-body');
    tbody.innerHTML = '';
    if (sessions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7">No sessions found</td></tr>';
        return;
    }
    sessions.forEach(s => {
        const tr = document.createElement('tr');
        const badge = s.status === 'analyzed' ? 'badge-green' : s.status === 'captured' ? 'badge-yellow' : 'badge-red';
        const tunKb = Math.round((s.stats.tun_pcap_bytes || 0) / 1024);
        const physKb = Math.round((s.stats.phys_pcap_bytes || 0) / 1024);
        tr.innerHTML = `
            <td>${s.id}</td>
            <td><span class="badge ${badge}">${s.status}</span></td>
            <td>${tunKb} KB</td>
            <td>${physKb} KB</td>
            <td>${s.stats.total_flows || '-'}</td>
            <td>${(s.stats.subdomains || []).length || '-'}</td>
            <td><a href="/session/${s.id}">View</a></td>
        `;
        tbody.appendChild(tr);
    });
});
</script>
{% endblock %}
```

- [ ] **Step 2: Add `/sessions` route**

```python
@app.get("/sessions")
async def page_sessions(request: Request):
    return templates.TemplateResponse("sessions.html", {"request": request})
```

- [ ] **Step 3: Test the page**

```bash
curl -s http://127.0.0.1:5080/sessions | grep -o "Sessions"
# Expected: Sessions
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/templates/sessions.html dashboard/server.py
git commit -m "feat: add sessions history page"
```

---

### Task 7: Capture runner — subprocess management with WebSocket log

**Files:**
- Create: `dashboard/runner.py`
- Modify: `dashboard/server.py` — add capture start, status, and WebSocket routes

**Interfaces:**
- Consumes: `app`, existing `capture.py` CLI
- Produces: `start_capture(config_path: str, only_domain: str | None, ws_handler) -> str`, `capture_runs: dict[str, dict]`

- [ ] **Step 1: Create `dashboard/runner.py`**

```python
"""Async subprocess runner for capture.py and analyze.py with live log streaming."""

import asyncio
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


async def run_pipeline(ws_queue: asyncio.Queue, cmd: list[str], cwd: str | None = None):
    """Run a subprocess and push stdout lines to ws_queue. Put None when done."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=cwd,
    )
    async for line in proc.stdout:
        text = line.decode("utf-8", errors="replace").rstrip("\n")
        ws_queue.put_nowait({"line": text})
    await proc.wait()
    ws_queue.put_nowait(None)  # signal end


def run_capture(config_path: str, only_domain: str | None, cwd: str | None = None) -> asyncio.Queue:
    """Start capture.py and return a queue for WebSocket streaming."""
    cmd = ["python3", str(ROOT / "capture.py"), "--config", config_path]
    if only_domain:
        cmd.extend(["--only", only_domain])
    q: asyncio.Queue = asyncio.Queue()
    asyncio.create_task(run_pipeline(q, cmd, cwd=cwd))
    return q


def run_analysis(session_dir: str, cwd: str | None = None) -> asyncio.Queue:
    """Start analyze.py and return a queue for WebSocket streaming."""
    cmd = ["python3", str(ROOT / "analyze.py"), "--session", session_dir]
    q: asyncio.Queue = asyncio.Queue()
    asyncio.create_task(run_pipeline(q, cmd, cwd=cwd))
    return q
```

- [ ] **Step 2: Add capture and WebSocket routes to server.py**

```python
import asyncio
from fastapi import WebSocket, WebSocketDisconnect

from dashboard.runner import run_capture, run_analysis
from dashboard.config_manager import load_config


capture_queues: dict[str, asyncio.Queue] = {}
analysis_queues: dict[str, asyncio.Queue] = {}


@app.post("/api/capture/start")
async def api_capture_start(data: dict):
    cfg = load_config()
    config_path = data.get("config_path", str(ROOT / "sites.yaml"))
    only_domain = data.get("only")
    queue = run_capture(config_path, only_domain, cwd=str(ROOT))
    sid = _next_session_id()
    capture_queues[sid] = queue
    return {"session_id": sid, "status": "running"}


@app.websocket("/api/capture/{session_id}/log")
async def ws_capture_log(websocket: WebSocket, session_id: str):
    await websocket.accept()
    q = capture_queues.get(session_id)
    if q is None:
        await websocket.send_json({"line": "[ERROR] Session not found"})
        await websocket.close()
        return
    try:
        while True:
            item = await asyncio.wait_for(q.get(), timeout=300)
            if item is None:
                await websocket.send_json({"line": "--- Capture complete ---"})
                break
            await websocket.send_json(item)
    except asyncio.TimeoutError:
        await websocket.send_json({"line": "[ERROR] Timeout waiting for capture output"})
    except WebSocketDisconnect:
        pass


@app.post("/api/session/{session_id}/analyze")
async def api_session_analyze(session_id: str):
    cfg = load_config()
    base_dir = cfg.get("global", {}).get("output", {}).get("base_dir", "./output")
    session_dir = str(Path(base_dir) / session_id)
    if not Path(session_dir).exists():
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "session not found"}, status_code=404)
    queue = run_analysis(session_dir, cwd=str(ROOT))
    analysis_queues[session_id] = queue
    return {"status": "running"}


@app.websocket("/api/session/{session_id}/log")
async def ws_session_log(websocket: WebSocket, session_id: str):
    await websocket.accept()
    q = analysis_queues.get(session_id)
    if q is None:
        await websocket.send_json({"line": "[ERROR] No analysis running for this session"})
        await websocket.close()
        return
    try:
        while True:
            item = await asyncio.wait_for(q.get(), timeout=300)
            if item is None:
                await websocket.send_json({"line": "--- Analysis complete ---"})
                break
            await websocket.send_json(item)
    except asyncio.TimeoutError:
        await websocket.send_json({"line": "[ERROR] Timeout waiting for analysis output"})
    except WebSocketDisconnect:
        pass


def _next_session_id():
    """Generate a unique session ID. Actual ID comes from capture.py output."""
    import uuid
    return uuid.uuid4().hex[:12]
```

- [ ] **Step 3: Ensure ROOT is defined in server.py**

Add to imports at top:
```python
ROOT = Path(__file__).resolve().parent.parent
```

- [ ] **Step 4: Test with dummy capture**

```bash
# Create a test endpoint to verify runner works
# Add to server.py temporarily:
# @app.get("/test-runner")
# async def test_runner():
#     q = run_capture(str(ROOT / "sites.yaml"), None, str(ROOT))
#     return {"ok": True, "queue_id": id(q)}
```

- [ ] **Step 5: Commit**

```bash
git add dashboard/runner.py dashboard/server.py
git commit -m "feat: add async subprocess runner with WebSocket log streaming"
```

---

### Task 8: Session detail page — stats, correlation table, analyze button, live log

**Files:**
- Create: `dashboard/templates/session.html`
- Modify: `dashboard/server.py` — add `/session/<id>` route

**Interfaces:**
- Consumes: base.html, /api/session/<id>, WebSocket log stream
- Produces: Session detail page

- [ ] **Step 1: Create `dashboard/templates/session.html`**

```html
{% extends "base.html" %}
{% block content %}
<h2 id="session-title">Session</h2>

<div id="session-content">Loading...</div>

<div id="log-section" style="margin-top:24px">
    <h3>Live Log</h3>
    <div id="log-panel" class="log-panel" style="height:200px"></div>
</div>

<script>
const path = window.location.pathname;
const sessionId = path.split('/').pop();

fetch('/api/session/' + sessionId).then(r => r.json()).then(s => {
    const st = s.stats || {};
    const tunKb = Math.round((st.tun_pcap_bytes || 0) / 1024);
    const physKb = Math.round((st.phys_pcap_bytes || 0) / 1024);
    const badge = s.status === 'analyzed' ? 'badge-green' : s.status === 'captured' ? 'badge-yellow' : 'badge-red';

    let html = `
        <p><strong>ID:</strong> ${s.id}</p>
        <p><strong>Status:</strong> <span class="badge ${badge}">${s.status}</span></p>
        <p><strong>Path:</strong> <code>${s.path}</code></p>
        <h3>File Sizes</h3>
        <table>
            <tr><th>TUN pcap</th><td>${tunKb} KB</td></tr>
            <tr><th>Phys pcap</th><td>${physKb} KB</td></tr>
            <tr><th>NetLog</th><td>${Math.round((st.netlog_bytes || 0) / 1024)} KB</td></tr>
            <tr><th>Mihomo Trace</th><td>${Math.round((st.trace_bytes || 0) / 1024)} KB</td></tr>
            <tr><th>Total Flows</th><td>${st.total_flows || '-'}</td></tr>
            <tr><th>Subdomains</th><td>${(st.subdomains || []).join(', ') || '-'}</td></tr>
        </table>
    `;

    if (s.correlation) {
        html += '<h3>Correlation Results</h3>';
        const domains = Object.keys(s.correlation);
        domains.forEach(domain => {
            const flows = s.correlation[domain];
            html += `<h4>${domain} (${flows.length} flows)</h4>`;
            html += '<table><thead><tr><th>Name</th><th>Relation</th><th>Pre-Proxy</th><th>Post-Proxy</th></tr></thead><tbody>';
            flows.forEach(f => {
                const pre = f.pre_proxy || {};
                const post = f.post_proxy || {};
                html += `<tr>
                    <td>${f.name || '?'}</td>
                    <td>${f.relation || ''}</td>
                    <td><code>${pre.src || '?'} → ${pre.dst || '?'}</code></td>
                    <td><code>${post.src || '?'} → ${post.dst || '?'}</code></td>
                </tr>`;
            });
            html += '</tbody></table>';
        });
    } else if (s.status !== 'empty') {
        html += `<br><button onclick="runAnalysis()">Run Analysis</button>`;
    }

    document.getElementById('session-content').innerHTML = html;
    document.getElementById('session-title').textContent = 'Session: ' + s.id;
});

function runAnalysis() {
    fetch('/api/session/' + sessionId + '/analyze', {method: 'POST'}).then(r => r.json()).then(resp => {
        const wsUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
        startLogStream(wsUrl + '/api/session/' + sessionId + '/log', 'log-panel');
        setTimeout(() => location.reload(), 3000);
    });
}
</script>
{% endblock %}
```

- [ ] **Step 2: Add `/session/<id>` route**

```python
@app.get("/session/{session_id}")
async def page_session(request: Request, session_id: str):
    return templates.TemplateResponse("session.html", {"request": request})
```

- [ ] **Step 3: Test the page**

```bash
# Get a session ID from the API first
SID=$(curl -s http://127.0.0.1:5080/api/sessions | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['id'])")
curl -s "http://127.0.0.1:5080/session/$SID" | grep -o "Session"
# Expected: Session
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/templates/session.html dashboard/server.py
git commit -m "feat: add session detail page with correlation table, analyze button, live log"
```

---

### Task 9: Wire capture button on config page

**Files:**
- Modify: `dashboard/templates/config.html` — add capture button and log panel

**Interfaces:**
- Consumes: /api/capture/start, WebSocket /api/capture/<id>/log
- Produces: Functional capture button on config page

- [ ] **Step 1: Add capture button and log panel to config.html**

Add after the `</form>` closing tag in `config.html`:

```html
<br>
<h3>Capture</h3>
<div>
    <label>Single site (optional): </label>
    <input id="only-domain" placeholder="e.g. bilibili.com" style="width:200px">
    <button id="capture-btn" onclick="startCapture()">Run Capture</button>
    <span id="capture-status"></span>
</div>
<div style="margin-top:16px">
    <div id="capture-log" class="log-panel" style="height:300px"></div>
</div>

<script>
function startCapture() {
    const only = document.getElementById('only-domain').value || null;
    const btn = document.getElementById('capture-btn');
    btn.disabled = true;
    btn.textContent = 'Capturing...';
    document.getElementById('capture-status').innerHTML = '<span class="badge badge-yellow">running</span>';

    fetch('/api/capture/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({only: only})
    }).then(r => r.json()).then(data => {
        const wsUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
        const panel = document.getElementById('capture-log');
        panel.innerHTML = '';

        const ws = new WebSocket(wsUrl + '/api/capture/' + data.session_id + '/log');
        ws.onmessage = (e) => {
            const d = JSON.parse(e.data);
            const line = document.createElement('div');
            let cls = 'log-info';
            if (d.line.includes('[WARNING') || d.line.includes('[WARN')) cls = 'log-warn';
            if (d.line.includes('[ERROR')) cls = 'log-error';
            line.className = cls;
            line.textContent = d.line;
            panel.appendChild(line);
            panel.scrollTop = panel.scrollHeight;
        };
        ws.onclose = () => {
            document.getElementById('capture-status').innerHTML = '<span class="badge badge-green">done</span>';
            btn.disabled = false;
            btn.textContent = 'Run Capture';
            const line = document.createElement('div');
            line.className = 'log-info';
            line.textContent = '--- Capture complete. Check Sessions page for results. ---';
            panel.appendChild(line);
        };
        ws.onerror = () => {
            document.getElementById('capture-status').innerHTML = '<span class="badge badge-red">error</span>';
            btn.disabled = false;
            btn.textContent = 'Run Capture';
        };
    }).catch(() => {
        document.getElementById('capture-status').innerHTML = '<span class="badge badge-red">error</span>';
        btn.disabled = false;
        btn.textContent = 'Run Capture';
    });
}
</script>
```

- [ ] **Step 2: Test the flow**

```bash
curl -s -X POST http://127.0.0.1:5080/api/capture/start \
  -H "Content-Type: application/json" \
  -d '{"only":null}'
# Expected: {"session_id":"...","status":"running"}
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/templates/config.html
git commit -m "feat: wire capture button on config page with live log"
```

---

### Task 10: Integration test and README update

**Files:**
- Create: `test/test_dashboard.py`
- Modify: `README.md` — add Dashboard section

**Interfaces:**
- Consumes: All dashboard APIs
- Produces: Integration test, documentation

- [ ] **Step 1: Create `test/test_dashboard.py`**

```python
"""Integration tests for TrafficTracer Dashboard API."""

import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.server import app

client = TestClient(app)


def test_config_api():
    resp = client.get("/api/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "global" in data
    assert "sites" in data


def test_session_api():
    resp = client.get("/api/sessions")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_session_detail():
    resp = client.get("/api/sessions")
    sessions = resp.json()
    if sessions:
        sid = sessions[0]["id"]
        resp2 = client.get(f"/api/session/{sid}")
        assert resp2.status_code == 200
        assert resp2.json()["id"] == sid


def test_session_not_found():
    resp = client.get("/api/session/nonexistent")
    assert resp.status_code == 404


def test_pages_render():
    for path in ["/config", "/sessions"]:
        resp = client.get(path)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

- [ ] **Step 2: Run tests**

```bash
cd /data/ytluo/projects/TrafficTracer
pip install pytest httpx
python test/test_dashboard.py -v
# Expected: All 5 tests pass
```

- [ ] **Step 3: Add Dashboard section to README**

Insert at the end of Quick Start, before `## Mihomo Proxy Operations`:

```markdown
### Dashboard

A web UI for managing captures without CLI commands.

```bash
# Install dashboard dependency
pip install fastapi uvicorn python-multipart

# Start dashboard
cd TrafficTracer
python dashboard/server.py
# or: python -m uvicorn dashboard.server:app --host 127.0.0.1 --port 5080
```

Then open `http://127.0.0.1:5080` in browser:
- **Config** — edit sites.yaml, save, and run capture with live log
- **Sessions** — browse capture history, view stats and correlation results
- **Session detail** — per-flow pre/post proxy 5-tuples, run analysis
```

- [ ] **Step 4: Commit**

```bash
git add test/test_dashboard.py README.md
git commit -m "test: add dashboard API integration tests and README docs"
```

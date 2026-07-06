"""TrafficTracer Dashboard — FastAPI server."""

import asyncio
import uuid
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dashboard.config_manager import load_config, save_config
from dashboard.runner import run_capture, run_analysis
from dashboard.session_store import list_sessions, get_session

ROOT = Path(__file__).resolve().parent.parent

app = FastAPI(title="TrafficTracer Dashboard")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

capture_queues: dict[str, asyncio.Queue] = {}
analysis_queues: dict[str, asyncio.Queue] = {}


def _next_session_id():
    """Generate a unique session ID. Actual ID comes from capture.py output."""
    return uuid.uuid4().hex[:12]


@app.get("/")
async def index():
    """Redirect to dashboard home."""
    return RedirectResponse(url="/config")


@app.get("/test-base")
async def test_base(request: Request):
    return templates.TemplateResponse(request, "base.html", {"content": "<p>OK</p>"})


@app.get("/api/config")
async def api_get_config():
    return load_config()


@app.put("/api/config")
async def api_put_config(data: dict):
    save_config(data)
    return {"ok": True}


@app.get("/config")
async def page_config(request: Request):
    return templates.TemplateResponse(request, "config.html")


@app.get("/sessions")
async def page_sessions(request: Request):
    return templates.TemplateResponse(request, "sessions.html")


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
        return JSONResponse({"error": "not found"}, status_code=404)
    return s


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


@app.get("/session/{session_id}")
async def page_session(request: Request, session_id: str):
    return templates.TemplateResponse("session.html", {"request": request})


def start_dashboard(host: str = "127.0.0.1", port: int = 5080):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_dashboard()

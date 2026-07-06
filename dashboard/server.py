"""TrafficTracer Dashboard — FastAPI server."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dashboard.config_manager import load_config, save_config
from dashboard.session_store import list_sessions, get_session

ROOT = Path(__file__).resolve().parent.parent

app = FastAPI(title="TrafficTracer Dashboard")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.get("/")
async def index():
    """Redirect to dashboard home."""
    from fastapi.responses import RedirectResponse
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


def start_dashboard(host: str = "127.0.0.1", port: int = 5080):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_dashboard()

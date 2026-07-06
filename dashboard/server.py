"""TrafficTracer Dashboard — FastAPI server."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dashboard.config_manager import load_config, save_config

ROOT = Path(__file__).resolve().parent.parent

app = FastAPI(title="TrafficTracer Dashboard")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.get("/")
async def index():
    """Redirect to dashboard home."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/config")


@app.get("/api/config")
async def api_get_config():
    return load_config()


@app.put("/api/config")
async def api_put_config(data: dict):
    save_config(data)
    return {"ok": True}


def start_dashboard(host: str = "127.0.0.1", port: int = 5080):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_dashboard()

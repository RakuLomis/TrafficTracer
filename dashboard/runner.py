"""Async subprocess runner for capture.py and analyze.py with live log streaming."""

import asyncio
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
    ws_queue._proc = proc
    async for line in proc.stdout:
        text = line.decode("utf-8", errors="replace").rstrip("\n")
        ws_queue.put_nowait({"line": text})
    await proc.wait()
    if proc.returncode != 0:
        ws_queue.put_nowait({"line": f"[ERROR] Process exited with code {proc.returncode}"})
        ws_queue.put_nowait({"error": True, "code": proc.returncode})
    else:
        ws_queue.put_nowait(None)


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

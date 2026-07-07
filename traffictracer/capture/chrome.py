"""Chrome browser subprocess management for NetLog capture."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import websocket

from ..utils import logger

CDP_PORT = 9223


def launch_chrome(
    binary: str,
    url: str,
    netlog_path: str,
    user_data_dir: str,
    headless: bool = False,
    proxy_server: str = "",
) -> subprocess.Popen:
    Path(netlog_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        binary,
        f"--user-data-dir={user_data_dir}",
        f"--log-net-log={netlog_path}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if headless:
        cmd.append("--headless=new")
        cmd.append(f"--remote-debugging-port={CDP_PORT}")
        cmd.append("--autoplay-policy=no-user-gesture-required")
        cmd.append("--disable-features=PreloadMediaEngagementData,MediaEngagementBypassAutoplayPolicies")
        cmd.append("--disable-background-timer-throttling")
        cmd.append("--mute-audio")
    if proxy_server:
        cmd.append(f"--proxy-server={proxy_server}")
    cmd.append(url)
    logger.info("Launching Chrome: %s -> %s", binary, url)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if headless:
        time.sleep(3)
        _interact_page(url)
    return proc


def _interact_page(url: str, timeout: float = 8.0) -> None:
    """Use CDP to simulate user interaction: wait for load, scroll, play media."""
    try:
        ws_url = _get_cdp_ws_url()
        if not ws_url:
            return
        ws = websocket.create_connection(ws_url, timeout=5)

        # Enable necessary domains
        _cdp_send(ws, "Page.enable")
        _cdp_send(ws, "Runtime.enable")

        # Wait for page load
        _cdp_wait_event(ws, "Page.loadEventFired", timeout)

        # Scroll to trigger lazy-loading
        _cdp_send(ws, "Input.dispatchMouseEvent", {
            "type": "mouseWheel", "x": 500, "y": 400,
            "deltaX": 0, "deltaY": 800, "modifiers": 0,
        })
        time.sleep(1)

        # Find and play video/audio elements (muted to avoid autoplay blocks)
        _cdp_send(ws, "Runtime.evaluate", {
            "expression": """
                (() => {
                    const media = document.querySelectorAll('video, audio');
                    media.forEach(el => {
                        el.muted = true;
                        el.setAttribute('autoplay', '');
                        el.setAttribute('playsinline', '');
                        const playPromise = el.play();
                        if (playPromise) playPromise.catch(() => {});
                    });
                    return 'found ' + media.length + ' media elements';
                })()
            """
        })

        ws.close()
        logger.info("CDP interaction completed")
    except Exception as e:
        logger.warning("CDP interaction failed: %s", e)


def _get_cdp_ws_url() -> str | None:
    """Get the DevTools WebSocket URL from Chrome's debugging endpoint."""
    import urllib.request
    try:
        resp = urllib.request.urlopen(
            f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=5
        )
        data = json.loads(resp.read().decode())
        return data.get("webSocketDebuggerUrl")
    except Exception as e:
        logger.warning("Failed to get CDP URL: %s", e)
        return None


def _cdp_send(ws: websocket.WebSocket, method: str, params: dict | None = None) -> None:
    msg = {"id": int(time.time() * 1000), "method": method}
    if params:
        msg["params"] = params
    ws.send(json.dumps(msg))


def _cdp_wait_event(ws: websocket.WebSocket, event: str, timeout: float) -> None:
    ws.settimeout(timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = ws.recv()
            msg = json.loads(raw)
            if msg.get("method") == event:
                return
        except Exception:
            break


def kill_chrome(proc: subprocess.Popen) -> None:
    if proc is None or proc.poll() is not None:
        return
    logger.info("Killing Chrome (PID %d)", proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

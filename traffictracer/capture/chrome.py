"""Chrome browser subprocess management for NetLog capture."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..utils import logger


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
    if proxy_server:
        cmd.append(f"--proxy-server={proxy_server}")
    cmd.append(url)
    logger.info("Launching Chrome: %s -> %s", binary, url)
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


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

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
    remote_debugging_port: int | None = None,
    netlog_capture_mode: str = "Default",
    open_url: bool = True,
    extra_args: list[str] | None = None,
) -> subprocess.Popen:
    Path(netlog_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        binary,
        f"--user-data-dir={user_data_dir}",
        f"--log-net-log={netlog_path}",
        f"--net-log-capture-mode={netlog_capture_mode}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if headless:
        cmd.append("--headless=new")
        cmd.append("--autoplay-policy=no-user-gesture-required")
        cmd.append("--disable-features=PreloadMediaEngagementData,MediaEngagementBypassAutoplayPolicies")
        cmd.append("--disable-background-timer-throttling")
        cmd.append("--mute-audio")
    if proxy_server:
        cmd.append(f"--proxy-server={proxy_server}")
    if remote_debugging_port is not None:
        cmd.append(f"--remote-debugging-port={remote_debugging_port}")
        cmd.append("--remote-allow-origins=*")
    if extra_args:
        cmd.extend(extra_args)
    if open_url:
        cmd.append(url)
    else:
        cmd.append("about:blank")
    logger.info("Launching Chrome: %s (CDP=%s) url=%s", binary,
                remote_debugging_port is not None,
                url if open_url else "about:blank")
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_chrome_exit(proc: subprocess.Popen, timeout: float = 20) -> bool:
    if proc is None or proc.poll() is not None:
        return True
    logger.info("Waiting for Chrome (PID %d) to exit...", proc.pid)
    try:
        proc.wait(timeout=timeout)
        logger.info("Chrome exited cleanly")
        return True
    except subprocess.TimeoutExpired:
        logger.warning("Chrome did not exit within %ss", timeout)
        return False


def terminate_chrome(proc: subprocess.Popen, timeout: float = 15) -> None:
    if proc is None or proc.poll() is not None:
        return
    logger.info("Terminating Chrome (PID %d)", proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Chrome did not respond to SIGTERM, sending SIGKILL")
        proc.kill()
        proc.wait()


def kill_chrome(proc: subprocess.Popen) -> None:
    terminate_chrome(proc)

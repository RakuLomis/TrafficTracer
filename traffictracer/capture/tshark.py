"""tshark subprocess management with graceful shutdown."""

from __future__ import annotations

import subprocess
import signal
from pathlib import Path

from ..utils import logger


def start_tshark(interface: str, output_path: str,
                 capture_filter: str = "") -> subprocess.Popen:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = ["tshark", "-i", interface, "-w", output_path]
    if capture_filter:
        cmd.extend(["-f", capture_filter])
    logger.info("Starting tshark on %s -> %s", interface, output_path)
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def stop_tshark(proc: subprocess.Popen, timeout: int = 5) -> None:
    if proc is None or proc.poll() is not None:
        return
    logger.info("Stopping tshark (PID %d) gracefully...", proc.pid)
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=timeout)
        logger.info("tshark exited cleanly")
    except subprocess.TimeoutExpired:
        logger.warning("tshark did not exit, sending SIGKILL")
        proc.kill()
        proc.wait()

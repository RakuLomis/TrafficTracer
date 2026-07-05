"""Shared utilities for TrafficTracer."""

import os
import logging
import signal
import subprocess
from pathlib import Path

logger = logging.getLogger("traffictracer")


def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def cleanup_processes(processes: list[subprocess.Popen]) -> None:
    for proc in processes:
        if proc is None or proc.poll() is not None:
            continue
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def signal_handler(signum, frame):
    logger.info("Received signal %s, cleaning up...", signum)
    raise KeyboardInterrupt

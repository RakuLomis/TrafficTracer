"""Mihomo process management and API control for tracing."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path

from ..utils import logger


class MihomoManager:
    def __init__(self, binary: str, config_path: str, api_url: str):
        self.binary = binary
        self.config_path = config_path
        self.api_url = api_url.rstrip("/")

    def start(self) -> subprocess.Popen:
        logger.info("Starting Mihomo: %s -f %s", self.binary, self.config_path)
        proc = subprocess.Popen(
            [self.binary, "-f", self.config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        return proc

    def stop(self, proc: subprocess.Popen) -> None:
        if proc is None or proc.poll() is not None:
            return
        logger.info("Stopping Mihomo (PID %d)", proc.pid)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def _api_request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.api_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            logger.error("Mihomo API error: %s %s: %s", method, path, e)
            raise

    def get_tracing_status(self) -> dict:
        return self._api_request("GET", "/experimental/tracing")

    def enable_tracing(self, output_path: str) -> dict:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        logger.info("Enabling Mihomo tracing -> %s", output_path)
        return self._api_request("PATCH", "/experimental/tracing", {
            "enabled": True,
            "output": output_path,
        })

    def disable_tracing(self) -> dict:
        logger.info("Disabling Mihomo tracing")
        return self._api_request("PATCH", "/experimental/tracing", {
            "enabled": False,
        })

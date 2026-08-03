#!/usr/bin/env python3
"""Protocol smoke test for a source or packaged TrafficTracer Worker command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a Worker command is required after --")
    command = [
        str(Path(item).resolve()) if Path(item).exists() else item
        for item in command
    ]

    with tempfile.TemporaryDirectory(prefix="traffictracer-worker-smoke-") as root:
        requests = "\n".join([
            _request("hello", "hello", {}),
            _request("diagnose", "environment.diagnose", {
                "tun_interface": "smoke-missing-tun",
                "physical_interface": "smoke-missing-physical",
                "chrome_binary": command[0],
                "output_root": str(Path(root) / "sessions"),
                "min_free_bytes": 0,
            }),
            _request("shutdown", "worker.shutdown", {}),
        ]) + "\n"
        completed = subprocess.run(
            [*command, "--output-root", str(Path(root) / "sessions")],
            input=requests,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            cwd=root,
            check=False,
        )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Worker exited with {completed.returncode}: {completed.stderr.strip()}"
        )
    messages = []
    for line in completed.stdout.splitlines():
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise RuntimeError("Worker stdout contained a non-object JSON message")
        messages.append(payload)
    ready = [item for item in messages if item.get("method") == "worker.ready"]
    responses = {
        item.get("id"): item
        for item in messages
        if item.get("type") == "response"
    }
    if not ready:
        raise RuntimeError("Worker did not emit worker.ready")
    if responses.get("hello", {}).get("result", {}).get("api_version") != 2:
        raise RuntimeError("Worker hello handshake failed")
    checks = responses.get("diagnose", {}).get("result", {}).get("checks")
    if not isinstance(checks, list) or len(checks) != 7:
        raise RuntimeError("Worker diagnose smoke failed")
    if responses.get("shutdown", {}).get("result", {}).get("shutdown") is not True:
        raise RuntimeError("Worker shutdown smoke failed")
    print("TrafficTracer Worker hello/diagnose smoke passed.")
    return 0


def _request(request_id: str, method: str, params: dict) -> str:
    return json.dumps({
        "api_version": 2,
        "type": "request",
        "id": request_id,
        "method": method,
        "params": params,
    }, separators=(",", ":"))


if __name__ == "__main__":
    raise SystemExit(main())

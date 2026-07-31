"""Subprocess protocol smoke tests for the Complete Worker executable."""

import json
from pathlib import Path
import subprocess
import sys

from traffictracer.contracts import validate_worker_message


ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "traffictracer_worker.py"


def _request(request_id, method, params=None):
    return json.dumps({
        "api_version": 1,
        "type": "request",
        "id": request_id,
        "method": method,
        "params": params or {},
    })


def test_worker_hello_diagnose_shutdown_stdout_is_protocol_only(tmp_path):
    requests = "\n".join([
        _request("hello", "hello"),
        _request("diagnose", "environment.diagnose", {
            "tun_interface": "missing-tun",
            "physical_interface": "missing-physical",
            "chrome_binary": sys.executable,
            "min_free_bytes": 0,
        }),
        _request("shutdown", "worker.shutdown"),
    ]) + "\n"
    completed = subprocess.run(
        [sys.executable, str(WORKER), "--output-root", str(tmp_path / "sessions")],
        input=requests,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        cwd=ROOT,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    messages = [json.loads(line) for line in completed.stdout.splitlines()]
    assert all(validate_worker_message(message) is message for message in messages)
    assert any(
        message.get("method") == "worker.ready" for message in messages
    )
    responses = {
        message["id"]: message
        for message in messages
        if message.get("type") == "response"
    }
    assert responses["hello"]["result"]["api_version"] == 1
    assert len(responses["diagnose"]["result"]["checks"]) == 7
    assert responses["shutdown"]["result"] == {
        "shutdown": True,
        "jobs_stopped": True,
    }


def test_worker_eof_exits_cleanly_after_ready_notification(tmp_path):
    completed = subprocess.run(
        [sys.executable, str(WORKER), "--output-root", str(tmp_path / "sessions")],
        input="",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        cwd=ROOT,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    messages = [json.loads(line) for line in completed.stdout.splitlines()]
    assert messages[-1]["method"] == "worker.ready"
    assert all(validate_worker_message(message) is message for message in messages)


def test_worker_sigterm_exits_without_hanging(tmp_path):
    process = subprocess.Popen(
        [sys.executable, str(WORKER), "--output-root", str(tmp_path / "sessions")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=ROOT,
    )
    assert process.stdout is not None
    while True:
        line = process.stdout.readline()
        assert line
        message = json.loads(line)
        validate_worker_message(message)
        if message.get("method") == "worker.ready":
            break
    process.terminate()
    assert process.wait(timeout=10) == 0

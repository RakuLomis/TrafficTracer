"""Subprocess protocol smoke tests for the Complete Worker executable."""

from io import BytesIO
import json
from pathlib import Path
import selectors
import subprocess
import sys
from uuid import UUID

from traffictracer.contracts import validate_worker_message
from traffictracer.session.manifest import ComponentVersion, ComponentVersions, SessionTarget
from traffictracer.session.store import SessionStore
from traffictracer.worker.protocol import JsonlWriter
from traffictracer_worker import _write_response


ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "traffictracer_worker.py"


def _request(request_id, method, params=None):
    return json.dumps({
        "api_version": 2,
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
    assert responses["hello"]["result"]["api_version"] == 2
    assert "batch.resume" in responses["hello"]["result"]["methods"]
    assert len(responses["diagnose"]["result"]["checks"]) == 7
    assert responses["shutdown"]["result"] == {
        "shutdown": True,
        "jobs_stopped": True,
    }


def test_worker_can_switch_between_isolated_session_roots(tmp_path):
    first_root = tmp_path / "first sessions"
    second_root = tmp_path / "second sessions"
    component = ComponentVersion("complete", "unknown")
    manifest = SessionStore(
        first_root,
        id_factory=lambda: UUID("5027aee9-c6e4-41de-8625-7ea0869a3307"),
    ).create(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=ComponentVersions(component, component, component),
    )

    def inspect(root):
        completed = subprocess.run(
            [sys.executable, str(WORKER), "--output-root", str(root)],
            input="\n".join([
                _request("sessions", "session.list"),
                _request("shutdown", "worker.shutdown"),
            ]) + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            cwd=ROOT,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        messages = [json.loads(line) for line in completed.stdout.splitlines()]
        ready = next(message for message in messages if message.get("method") == "worker.ready")
        assert Path(ready["params"]["output_root"]) == root.resolve()
        return next(
            message["result"]
            for message in messages
            if message.get("type") == "response" and message.get("id") == "sessions"
        )

    first = inspect(first_root)
    second = inspect(second_root)
    assert [item["session_id"] for item in first["sessions"]] == [manifest.session_id]
    assert second["sessions"] == []


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


def test_worker_dispatches_request_while_stdin_remains_open(tmp_path):
    process = subprocess.Popen(
        [sys.executable, str(WORKER), "--output-root", str(tmp_path / "sessions")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=ROOT,
    )
    selector = selectors.DefaultSelector()
    assert process.stdin is not None
    assert process.stdout is not None
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while True:
            assert selector.select(timeout=5), "Worker ready notification timed out"
            message = json.loads(process.stdout.readline())
            if message.get("method") == "worker.ready":
                break

        process.stdin.write(_request("live", "hello") + "\n")
        process.stdin.flush()
        assert selector.select(timeout=5), "live Worker request was buffered"
        response = json.loads(process.stdout.readline())
        assert response["id"] == "live"
        assert response["result"]["api_version"] == 2

        process.stdin.write(_request("shutdown", "worker.shutdown") + "\n")
        process.stdin.flush()
        assert process.wait(timeout=10) == 0
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


def test_oversized_response_returns_error_without_poisoning_writer():
    stream = BytesIO()
    writer = JsonlWriter(stream, max_message_bytes=512)
    _write_response(writer, {
        "api_version": 2,
        "type": "response",
        "id": "large",
        "result": {"padding": "x" * 2048},
    })
    writer.write({
        "api_version": 2,
        "type": "response",
        "id": "after",
        "result": {"ok": True},
    })

    messages = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert messages[0]["id"] == "large"
    assert messages[0]["error"]["code"] == "RESPONSE_TOO_LARGE"
    assert messages[0]["error"]["data"]["actual_bytes"] > 512
    assert messages[1]["id"] == "after"
    assert messages[1]["result"] == {"ok": True}

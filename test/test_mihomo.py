"""Tests for Mihomo manager (no live Mihomo required)."""

import json
import os
from pathlib import Path
import socketserver
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.mihomo import MihomoApiError, MihomoManager


class _UnixHandler(socketserver.StreamRequestHandler):
    requests = []

    def handle(self):
        request_line = self.rfile.readline().decode().strip()
        method, path, _ = request_line.split()
        headers = {}
        while True:
            line = self.rfile.readline().decode().strip()
            if not line:
                break
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
        body = self.rfile.read(int(headers.get("content-length", "0")))
        self.requests.append((method, path, headers, body))
        payload = json.dumps({"ok": True, "path": path}).encode()
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )


def test_mihomo_manager_init():
    mgr = MihomoManager(
        binary="/usr/bin/mihomo",
        config_path="/etc/mihomo/config.yaml",
        api_url="http://127.0.0.1:9090",
        secret="token",
    )
    assert mgr.api_url == "http://127.0.0.1:9090"
    assert mgr.secret == "token"
    assert MihomoManager("mihomo", "cfg.yaml", "http://localhost:9090/").api_url == "http://localhost:9090"


def test_unix_socket_request_and_bearer(tmp_path):
    socket_path = tmp_path / "mihomo.sock"
    _UnixHandler.requests = []
    server = socketserver.UnixStreamServer(str(socket_path), _UnixHandler)
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    try:
        mgr = MihomoManager("mihomo", "cfg.yaml", f"unix://{socket_path}", "s3cret")
        assert mgr._api_request("PATCH", "/experimental/tracing", {"enabled": True})["ok"]
    finally:
        thread.join(timeout=2)
        server.server_close()
    method, path, headers, body = _UnixHandler.requests[0]
    assert (method, path) == ("PATCH", "/experimental/tracing")
    assert headers["authorization"] == "Bearer s3cret"
    assert json.loads(body) == {"enabled": True}


def test_tracing_session_restores_exact_state(tmp_path):
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    calls = []
    previous = {
        "enabled": True,
        "output": "/old/trace.jsonl",
        "session_id": "previous-session",
        "active_sessions": 2,
    }

    def fake_request(method, path, body=None, timeout=10):
        calls.append((method, path, body))
        return previous if method == "GET" else body

    mgr._api_request = fake_request
    with mgr.tracing_session(str(tmp_path / "new.jsonl")):
        pass
    assert calls[-1] == (
        "PATCH",
        "/experimental/tracing",
        {
            "enabled": True,
            "output": "/old/trace.jsonl",
            "session_id": "previous-session",
        },
    )


def test_api_error_preserves_status():
    error = MihomoApiError("GET", "/x", 401, "unauthorized")
    assert error.status == 401
    assert "401" in str(error)


def test_enable_tracing_resolves_external_output_path(tmp_path, monkeypatch):
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    calls = []
    mgr.patch_tracing = lambda state: calls.append(state) or state
    monkeypatch.chdir(tmp_path)
    mgr.enable_tracing("relative/trace.jsonl")
    assert calls == [{
        "enabled": True,
        "output": str(tmp_path / "relative" / "trace.jsonl"),
    }]


def test_enable_tracing_propagates_session_id(tmp_path):
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    calls = []
    mgr.patch_tracing = lambda state: calls.append(state) or state
    mgr.enable_tracing(str(tmp_path / "trace.jsonl"), session_id="session-1")
    assert calls == [{
        "enabled": True,
        "output": str(tmp_path / "trace.jsonl"),
        "session_id": "session-1",
    }]


def test_restore_tracing_clears_session_ownership_when_previously_absent():
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    calls = []
    mgr.patch_tracing = lambda state: calls.append(state) or state
    mgr.restore_tracing({"enabled": False, "output": ""})
    assert calls == [{"enabled": False, "output": "", "session_id": ""}]

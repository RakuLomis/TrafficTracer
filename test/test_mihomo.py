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


def test_trace_barrier_calls_stable_endpoint_and_validates_result():
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    calls = []
    expected = {
        "session_id": "session-1",
        "event_seq": 42,
        "ts": "2026-08-12T00:00:00Z",
        "output": "/tmp/trace.jsonl",
    }
    mgr._api_request = lambda method, path, body=None: calls.append((method, path, body)) or expected
    assert mgr.trace_barrier() == expected
    assert calls == [("POST", "/experimental/tracing/barrier", None)]



def test_proxy_info_resolves_nested_groups_to_protocol_leaf():
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    proxies = {
        "automatic": {"type": "URLTest", "now": "region"},
        "region": {"type": "Selector", "now": "hy2-node"},
        "hy2-node": {
            "type": "Hysteria2",
            "server": "203.0.113.7",
            "port": 443,
            "network": "udp",
        },
        "DIRECT": {"type": "Direct"},
    }
    mgr._api_request = lambda method, path: {"proxies": proxies}

    rows = mgr.get_proxy_info()
    automatic = next(row for row in rows if row["group"] == "automatic")
    assert automatic["node"] == "region"
    assert automatic["leaf_node"] == "hy2-node"
    assert automatic["leaf_type"] == "Hysteria2"
    assert automatic["selection_chain"] == [
        "automatic", "region", "hy2-node",
    ]

    snapshot = mgr.get_proxy_protocol_snapshot()
    assert snapshot["status"] == "single"
    assert snapshot["protocols"] == ["hysteria2"]
    assert snapshot["expected_protocol"] == "hysteria2"


def test_proxy_protocol_snapshot_reports_mixed_selected_leaf_types():
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    proxies = {
        "group-a": {"type": "Selector", "now": "hy2-node"},
        "group-b": {"type": "Fallback", "now": "vless-node"},
        "direct-group": {"type": "Selector", "now": "DIRECT"},
        "hy2-node": {"type": "Hysteria2"},
        "vless-node": {"type": "Vless"},
        "DIRECT": {"type": "Direct"},
    }
    mgr._api_request = lambda method, path: {"proxies": proxies}

    snapshot = mgr.get_proxy_protocol_snapshot()
    assert snapshot["status"] == "mixed"
    assert snapshot["protocols"] == ["hysteria2", "vless"]
    assert snapshot["expected_protocol"] == ""


def test_proxy_info_stops_at_group_cycle():
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    proxies = {
        "a": {"type": "Selector", "now": "b"},
        "b": {"type": "Selector", "now": "a"},
    }
    mgr._api_request = lambda method, path: {"proxies": proxies}

    rows = mgr.get_proxy_info()
    row = next(item for item in rows if item["group"] == "a")
    assert row["selection_chain"] == ["a", "b"]
    assert row["leaf_type"] == "Selector"

def test_restore_tracing_clears_session_ownership_when_previously_absent():
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    calls = []
    mgr.patch_tracing = lambda state: calls.append(state) or state
    mgr.restore_tracing({"enabled": False, "output": ""})
    assert calls == [{"enabled": False, "output": "", "session_id": ""}]

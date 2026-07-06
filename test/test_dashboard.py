"""Integration tests for TrafficTracer Dashboard API."""

import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.server import app

client = TestClient(app)


def test_config_api():
    resp = client.get("/api/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "global" in data
    assert "sites" in data


def test_session_api():
    resp = client.get("/api/sessions")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_session_detail():
    resp = client.get("/api/sessions")
    sessions = resp.json()
    if sessions:
        sid = sessions[0]["id"]
        resp2 = client.get(f"/api/session/{sid}")
        assert resp2.status_code == 200
        assert resp2.json()["id"] == sid


def test_session_not_found():
    resp = client.get("/api/session/nonexistent")
    assert resp.status_code == 404


def test_pages_render():
    for path in ["/config", "/sessions"]:
        resp = client.get(path)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

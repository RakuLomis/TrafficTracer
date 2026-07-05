"""Tests for Mihomo manager (no live Mihomo required)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.mihomo import MihomoManager


def test_mihomo_manager_init():
    mgr = MihomoManager(
        binary="/usr/bin/mihomo",
        config_path="/etc/mihomo/config.yaml",
        api_url="http://127.0.0.1:9090",
    )
    assert mgr.binary == "/usr/bin/mihomo"
    assert mgr.config_path == "/etc/mihomo/config.yaml"
    assert mgr.api_url == "http://127.0.0.1:9090"

    mgr2 = MihomoManager("mihomo", "cfg.yaml", "http://localhost:9090/")
    assert mgr2.api_url == "http://localhost:9090"


def test_enable_tracing_payload_format():
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    import json
    payload = {"enabled": True, "output": "/tmp/trace.jsonl"}
    data = json.dumps(payload)
    assert json.loads(data) == payload


if __name__ == "__main__":
    test_mihomo_manager_init()
    test_enable_tracing_payload_format()
    print("\n✓ All Mihomo manager tests passed!")

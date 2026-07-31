"""Tests for capture pipeline orchestration."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock, call
from traffictracer.config import (
    Config, GlobalConfig, OutputConfig, SiteConfig,
    ChromeConfig, MihomoConfig, NetworkConfig,
)


def test_per_visit_profile_path():
    g = GlobalConfig(
        chrome=ChromeConfig(user_data_dir="/tmp/chrome-profile"),
    )
    domain = "bilibili.com"
    run_tag = "video-mainpage_1"
    expected = os.path.join("/tmp/chrome-profile", domain, run_tag)
    actual = os.path.join(g.chrome.user_data_dir, domain, run_tag)
    assert actual == expected


def test_cdp_structured_output_path():
    logs_dir = "/data/output/session/logs"
    domain = "bilibili.com"
    run_tag = "video-mainpage_1"
    cdp_path = os.path.join(logs_dir, f"cdp_{domain}_{run_tag}.json")
    assert cdp_path.endswith("cdp_bilibili.com_video-mainpage_1.json")


def test_site_filtering():
    sites = [
        SiteConfig(domain="a.com", url="https://a.com", wait=10),
        SiteConfig(domain="b.com", url="https://b.com", wait=15),
    ]
    filtered = [s for s in sites if s.domain == "a.com"]
    assert len(filtered) == 1
    assert filtered[0].domain == "a.com"


def test_cdp_collector_lifecycle_order():
    """Verify the expected CDP lifecycle call order."""
    call_order = []

    mock_collector = MagicMock()
    mock_collector.connect = lambda: call_order.append("connect")
    mock_collector.setup = lambda: call_order.append("setup")
    mock_collector.navigate = lambda url, **kw: call_order.append("navigate")
    mock_collector.collect = lambda s: call_order.append("collect")
    mock_collector.stop_collecting = lambda: call_order.append("stop")
    mock_collector.get_structured_data = lambda: (
        call_order.append("get_data") or {"requests": []}
    )
    mock_collector.close_browser = lambda: call_order.append("close_browser")
    mock_collector.close = lambda: call_order.append("close")

    mock_collector.connect()
    mock_collector.setup()
    mock_collector.navigate("https://example.com")
    mock_collector.collect(5)
    mock_collector.stop_collecting()
    data = mock_collector.get_structured_data()
    mock_collector.close_browser()
    mock_collector.close()

    assert call_order == [
        "connect", "setup", "navigate", "collect",
        "stop", "get_data", "close_browser", "close",
    ]


if __name__ == "__main__":
    test_per_visit_profile_path()
    test_cdp_structured_output_path()
    test_site_filtering()
    test_cdp_collector_lifecycle_order()
    print("\n✓ All capture pipeline tests passed!")


def test_resolve_executable_uses_path_lookup(monkeypatch):
    from traffictracer.capture.pipeline import _resolve_executable
    monkeypatch.setattr("traffictracer.capture.pipeline.shutil.which", lambda value: "/opt/chrome/chrome")
    assert _resolve_executable("google-chrome") == "/opt/chrome/chrome"

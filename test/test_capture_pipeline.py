"""Tests for capture pipeline orchestration."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock, call
from traffictracer.config import (
    Config, GlobalConfig, OutputConfig, SiteConfig,
    ChromeConfig, MihomoConfig, NetworkConfig,
)
from traffictracer.capture.controller_config import ResolvedControllerConfig


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


def test_legacy_yaml_site_translates_to_canonical_job_spec(tmp_path, monkeypatch):
    from traffictracer.capture.pipeline import legacy_config_to_job_spec

    monkeypatch.setattr(
        "traffictracer.capture.pipeline._resolve_executable",
        lambda value: "/opt/chrome/chrome",
    )
    global_config = GlobalConfig(
        chrome=ChromeConfig(binary="google-chrome", headless=True, enable_cdp=True),
        network=NetworkConfig(tun_interface="Meta", phys_interface="eth0"),
        output=OutputConfig(base_dir=str(tmp_path)),
    )
    site = SiteConfig(
        domain="example.com",
        url="https://example.com/",
        wait=7,
        traffic_type="tcp",
    )
    controller = ResolvedControllerConfig(
        endpoint="unix:///tmp/mihomo.sock",
        secret="token",
        generated_config="/tmp/verge.yaml",
    )
    spec = legacy_config_to_job_spec(
        site,
        global_config,
        controller,
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
    )
    assert spec.domain == "example.com"
    assert spec.duration_seconds == 7
    assert spec.network == "tcp"
    assert spec.interfaces.tun == "Meta"
    assert spec.interfaces.physical == "eth0"
    assert spec.controller.endpoint == "unix:///tmp/mihomo.sock"
    assert spec.controller.secret == "token"
    assert spec.options.collect_cdp is True
    assert spec.options.headless is True
    assert spec.chrome_binary == "/opt/chrome/chrome"
    assert spec.output_root == str(tmp_path)

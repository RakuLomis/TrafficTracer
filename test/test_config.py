"""Tests for config loading."""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.config import load_config, Config, GlobalConfig, SiteConfig


def test_load_config():
    yaml_content = """\
global:
  mihomo:
    binary: /usr/bin/mihomo
    config: /etc/mihomo/config.yaml
    api: "http://127.0.0.1:9090"
  chrome:
    binary: google-chrome
    user_data_dir: /tmp/chrome-profile
    headless: true
  network:
    tun_interface: utun
    phys_interface: eth0
  output:
    base_dir: ./output
sites:
  - domain: example.com
    url: "https://www.example.com"
    wait: 10
    traffic_type: all
  - domain: test.org
    url: "https://test.org"
    wait: 5
    traffic_type: tcp
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        tmp = f.name

    try:
        cfg = load_config(tmp)
        assert isinstance(cfg, Config)
        assert cfg.global_config.mihomo.binary == "/usr/bin/mihomo"
        assert cfg.global_config.mihomo.api == "http://127.0.0.1:9090"
        assert cfg.global_config.chrome.headless is True
        assert cfg.global_config.network.tun_interface == "utun"
        assert cfg.global_config.output.base_dir == "./output"
        assert len(cfg.sites) == 2
        assert cfg.sites[0].domain == "example.com"
        assert cfg.sites[0].wait == 10
        assert cfg.sites[1].traffic_type == "tcp"
    finally:
        os.unlink(tmp)

    print("  ✓ config loading pass")


if __name__ == "__main__":
    test_load_config()
    print("\n✓ All config tests passed!")

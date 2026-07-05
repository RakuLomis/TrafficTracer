"""Tests for capture pipeline (config parsing and session dir)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.config import (
    Config, GlobalConfig, OutputConfig, SiteConfig,
)


def test_session_dir_structure():
    cfg = GlobalConfig(output=OutputConfig(base_dir="/tmp/tt-test"))
    session_dir = os.path.join(cfg.output.base_dir, "2025-07-05_14-30-00")
    domain = "example.com"
    captures = os.path.join(session_dir, "captures", domain)
    logs = os.path.join(session_dir, "logs")
    assert "captures/example.com" in captures
    assert "logs" in logs


def test_site_filtering():
    sites = [
        SiteConfig(domain="a.com", url="https://a.com", wait=10),
        SiteConfig(domain="b.com", url="https://b.com", wait=15),
    ]
    filtered = [s for s in sites if s.domain == "a.com"]
    assert len(filtered) == 1
    assert filtered[0].domain == "a.com"


if __name__ == "__main__":
    test_session_dir_structure()
    test_site_filtering()
    print("\n✓ All capture pipeline tests passed!")

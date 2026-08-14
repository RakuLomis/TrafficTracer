"""Tests for config loading."""

import sys
import os
import tempfile
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.config import (
    Config,
    ConfigValidationError,
    GlobalConfig,
    SiteConfig,
    load_config,
    load_target_config,
)


def test_load_config():
    yaml_content = """\
global:
  mihomo:
    binary: /usr/bin/mihomo
    config: /etc/mihomo/config.yaml
    api: "unix:///tmp/verge/verge-mihomo.sock"
    secret: test-secret
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
        assert cfg.global_config.mihomo.api == "unix:///tmp/verge/verge-mihomo.sock"
        assert cfg.global_config.mihomo.secret == "test-secret"
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


def test_load_target_config_normalizes_legacy_sites(tmp_path):
    path = tmp_path / "sites.yaml"
    path.write_text(
        """
global:
  mihomo:
    secret: must-not-leak
  output:
    base_dir: ./sessions
sites:
  - domain: Example.COM.
    url: https://www.example.com/
    wait: 15
    traffic_type: tcp
  - domain: example.com
    url: https://www.example.com/video
    wait: 20
    traffic_type: video-play
    wait_load_timeout: 45
""",
        encoding="utf-8",
    )
    preview = load_target_config(path)
    payload = preview.to_dict()
    assert payload["config_path"] == str(path.resolve())
    assert len(payload["sha256"]) == 64
    assert [target["index"] for target in payload["targets"]] == [0, 1]
    assert payload["targets"][0]["domain"] == "example.com"
    assert payload["targets"][0]["network"] == "tcp"
    assert payload["targets"][1]["network"] == "all"
    assert payload["targets"][1]["run_label"] == "video-play"
    assert payload["targets"][1]["wait_load_timeout"] == 45
    assert "must-not-leak" not in str(payload)
    assert len(payload["warnings"]) == 1
    assert [target["page_type"] for target in payload["targets"]] == [
        "tcp", "video-play"
    ]
    assert payload["suggested_output_root"] == str((tmp_path / "sessions").resolve())


def test_load_target_config_rejects_unsafe_label(tmp_path):
    path = tmp_path / "sites.yaml"
    path.write_text(
        "sites:\n  - domain: example.com\n    url: https://example.com\n    traffic_type: ../escape\n",
        encoding="utf-8",
    )
    try:
        load_target_config(path)
    except ConfigValidationError as exc:
        assert exc.field_path == "sites[0].traffic_type"
        assert "../escape" not in str(exc)
    else:
        raise AssertionError("unsafe run label was accepted")


def test_load_target_config_requires_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sites.yaml").write_text("sites: []\n", encoding="utf-8")
    try:
        load_target_config("sites.yaml")
    except ConfigValidationError as exc:
        assert exc.field_path == "config_path"
    else:
        raise AssertionError("relative target config path was accepted")


def test_target_config_normalizes_youtube_playback_policy(tmp_path):
    path = tmp_path / "sites.yaml"
    path.write_text(
        """
sites:
  - domain: youtube.com
    url: https://www.youtube.com/watch?v=example
    page_type: video-play
    wait: 35
    playback:
      provider: youtube
      ad_policy: click_visible_skip
      desired_primary_seconds: 25
""",
        encoding="utf-8",
    )
    (target,) = load_target_config(path).to_dict()["targets"]
    assert target["duration_seconds"] == 35
    assert target["playback"] == {
        "provider": "youtube",
        "ad_policy": "click_visible_skip",
        "desired_primary_seconds": 25,
    }


def test_target_config_rejects_playback_goal_longer_than_wait(tmp_path):
    path = tmp_path / "sites.yaml"
    path.write_text(
        """
sites:
  - domain: youtube.com
    url: https://www.youtube.com/watch?v=example
    wait: 20
    playback:
      provider: youtube
      desired_primary_seconds: 25
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError) as raised:
        load_target_config(path)
    assert raised.value.field_path == (
        "sites[0].playback.desired_primary_seconds"
    )


def test_target_config_rejects_youtube_policy_on_other_host(tmp_path):
    path = tmp_path / "sites.yaml"
    path.write_text(
        """
sites:
  - domain: example.com
    url: https://example.com/video
    wait: 35
    playback:
      provider: youtube
      desired_primary_seconds: 25
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError) as raised:
        load_target_config(path)
    assert raised.value.field_path == "sites[0].playback.provider"


if __name__ == "__main__":
    test_load_config()
    print("\n✓ All config tests passed!")

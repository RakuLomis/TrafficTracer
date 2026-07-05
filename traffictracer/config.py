"""YAML configuration loading and validation for TrafficTracer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import yaml


@dataclass
class MihomoConfig:
    binary: str = "mihomo"
    config: str = ""
    api: str = "http://127.0.0.1:9090"


@dataclass
class ChromeConfig:
    binary: str = "google-chrome"
    user_data_dir: str = "/tmp/chrome-profile"
    headless: bool = False


@dataclass
class NetworkConfig:
    tun_interface: str = ""
    phys_interface: str = ""


@dataclass
class OutputConfig:
    base_dir: str = "./output"


@dataclass
class GlobalConfig:
    mihomo: MihomoConfig = field(default_factory=MihomoConfig)
    chrome: ChromeConfig = field(default_factory=ChromeConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


@dataclass
class SiteConfig:
    domain: str
    url: str
    wait: int = 10
    traffic_type: str = "all"


@dataclass
class Config:
    global_config: GlobalConfig
    sites: list[SiteConfig]


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError("Config file must be a YAML mapping")

    g = raw.get("global", {})
    if not isinstance(g, dict):
        raise ValueError("Missing or invalid 'global' section")

    m = g.get("mihomo", {})
    mihomo = MihomoConfig(
        binary=m.get("binary", "mihomo"),
        config=m.get("config", ""),
        api=m.get("api", "http://127.0.0.1:9090"),
    )

    c = g.get("chrome", {})
    chrome = ChromeConfig(
        binary=c.get("binary", "google-chrome"),
        user_data_dir=c.get("user_data_dir", "/tmp/chrome-profile"),
        headless=c.get("headless", False),
    )

    n = g.get("network", {})
    network = NetworkConfig(
        tun_interface=n.get("tun_interface", ""),
        phys_interface=n.get("phys_interface", ""),
    )

    o = g.get("output", {})
    output = OutputConfig(base_dir=o.get("base_dir", "./output"))

    global_config = GlobalConfig(mihomo=mihomo, chrome=chrome,
                                  network=network, output=output)

    sites_raw = raw.get("sites", [])
    if not isinstance(sites_raw, list):
        raise ValueError("Missing or invalid 'sites' section")

    sites = []
    for s in sites_raw:
        if not isinstance(s, dict):
            continue
        sites.append(SiteConfig(
            domain=s["domain"],
            url=s["url"],
            wait=s.get("wait", 10),
            traffic_type=s.get("traffic_type", "all"),
        ))

    if not sites:
        raise ValueError("No sites defined in config")

    return Config(global_config=global_config, sites=sites)

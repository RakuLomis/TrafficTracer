"""YAML configuration loading and validation for TrafficTracer."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from urllib.parse import urlsplit
import yaml

from traffictracer.contracts import validate_target_config


TARGET_CONFIG_SCHEMA_VERSION = 1
MAX_TARGET_CONFIG_BYTES = 1024 * 1024
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_RUN_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ConfigValidationError(ValueError):
    """A value-safe error identifying the invalid configuration field."""

    def __init__(self, field_path: str, message: str) -> None:
        self.field_path = field_path
        self.message = message
        super().__init__(f"{field_path}: {message}")


@dataclass
class MihomoConfig:
    binary: str = "mihomo"
    config: str = ""
    api: str = "http://127.0.0.1:9090"
    secret: str = ""
    managed: bool = True


@dataclass
class ChromeConfig:
    binary: str = "google-chrome"
    user_data_dir: str = "/tmp/chrome-profile"
    headless: bool = False
    enable_cdp: bool = True
    remote_debugging_port: int = 9222
    netlog_capture_mode: str = "Default"
    graceful_close_timeout: int = 20
    disable_background_networking: bool = False


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
    wait_load_timeout: int = 30


@dataclass
class Config:
    global_config: GlobalConfig
    sites: list[SiteConfig]


@dataclass(frozen=True)
class TargetConfigEntry:
    index: int
    domain: str
    url: str
    duration_seconds: int
    network: str
    run_label: str
    wait_load_timeout: int

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "domain": self.domain,
            "url": self.url,
            "duration_seconds": self.duration_seconds,
            "network": self.network,
            "run_label": self.run_label,
            "wait_load_timeout": self.wait_load_timeout,
        }


@dataclass(frozen=True)
class TargetConfigPreview:
    config_path: str
    sha256: str
    targets: tuple[TargetConfigEntry, ...]
    warnings: tuple[str, ...] = ()
    schema_version: int = TARGET_CONFIG_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "config_path": self.config_path,
            "sha256": self.sha256,
            "targets": [target.to_dict() for target in self.targets],
            "warnings": list(self.warnings),
        }
        validate_target_config(payload)
        return payload


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
        secret=m.get("secret", ""),
        managed=m.get("managed", True),
    )

    c = g.get("chrome", {})
    chrome = ChromeConfig(
        binary=c.get("binary", "google-chrome"),
        user_data_dir=c.get("user_data_dir", "/tmp/chrome-profile"),
        headless=c.get("headless", False),
        enable_cdp=c.get("enable_cdp", True),
        remote_debugging_port=c.get("remote_debugging_port", 9222),
        netlog_capture_mode=c.get("netlog_capture_mode", "Default"),
        graceful_close_timeout=c.get("graceful_close_timeout", 20),
        disable_background_networking=c.get("disable_background_networking", False),
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
            wait_load_timeout=s.get("wait_load_timeout", 30),
        ))

    if not sites:
        raise ValueError("No sites defined in config")

    return Config(global_config=global_config, sites=sites)


def load_target_config(path: str | Path) -> TargetConfigPreview:
    """Load only safe target fields from a user-selected legacy sites YAML."""

    requested = Path(path).expanduser()
    if not requested.is_absolute():
        raise ConfigValidationError("config_path", "must be an absolute path")
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise ConfigValidationError("config_path", "file is unavailable") from exc
    if not resolved.is_file():
        raise ConfigValidationError("config_path", "must be a regular file")
    if resolved.suffix.lower() not in {".yaml", ".yml"}:
        raise ConfigValidationError("config_path", "must use a .yaml or .yml extension")
    size = resolved.stat().st_size
    if size > MAX_TARGET_CONFIG_BYTES:
        raise ConfigValidationError("config_path", "file exceeds the 1 MiB limit")
    try:
        content = resolved.read_bytes()
        raw = yaml.safe_load(content.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigValidationError("config_path", "file must be UTF-8") from exc
    except yaml.YAMLError as exc:
        raise ConfigValidationError("config_path", "file contains invalid YAML") from exc
    if not isinstance(raw, dict):
        raise ConfigValidationError("/", "configuration must be a YAML mapping")
    sites = raw.get("sites")
    if not isinstance(sites, list) or not sites:
        raise ConfigValidationError("sites", "must be a non-empty list")

    targets: list[TargetConfigEntry] = []
    warnings: list[str] = []
    for index, site in enumerate(sites):
        field = f"sites[{index}]"
        if not isinstance(site, dict):
            raise ConfigValidationError(field, "must be a mapping")
        domain = _required_string(site, "domain", field).lower().rstrip(".")
        if not _valid_domain(domain):
            raise ConfigValidationError(f"{field}.domain", "must be a valid DNS name")
        url = _required_string(site, "url", field)
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or any(character.isspace() for character in url):
            raise ConfigValidationError(f"{field}.url", "must be an absolute HTTP(S) URL")
        duration = _bounded_integer(site.get("wait", 10), f"{field}.wait", 1, 86_400)
        load_timeout = _bounded_integer(
            site.get("wait_load_timeout", 30),
            f"{field}.wait_load_timeout",
            1,
            3_600,
        )
        traffic_type = site.get("traffic_type", "all")
        if not isinstance(traffic_type, str) or not _RUN_LABEL.fullmatch(traffic_type):
            raise ConfigValidationError(
                f"{field}.traffic_type",
                "must be 1-64 safe label characters (letters, digits, '.', '_' or '-')",
            )
        network = traffic_type if traffic_type in {"tcp", "udp", "all"} else "all"
        if network != traffic_type:
            warnings.append(
                f"{field}.traffic_type={traffic_type!r} is a run label; network defaults to 'all'."
            )
        targets.append(
            TargetConfigEntry(
                index=index,
                domain=domain,
                url=url,
                duration_seconds=duration,
                network=network,
                run_label=traffic_type,
                wait_load_timeout=load_timeout,
            )
        )

    preview = TargetConfigPreview(
        config_path=str(resolved),
        sha256=hashlib.sha256(content).hexdigest(),
        targets=tuple(targets),
        warnings=tuple(warnings),
    )
    preview.to_dict()
    return preview


def _required_string(site: dict, key: str, field: str) -> str:
    value = site.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigValidationError(f"{field}.{key}", "must be a non-empty string")
    return value.strip()


def _bounded_integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigValidationError(field, f"must be an integer between {minimum} and {maximum}")
    return value


def _valid_domain(domain: str) -> bool:
    return (
        0 < len(domain) <= 253
        and all(_DOMAIN_LABEL.fullmatch(label) for label in domain.split("."))
    )

"""Resolve Mihomo controller endpoints and secrets from generated config."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

from traffictracer.config import MihomoConfig


@dataclass(frozen=True)
class ResolvedControllerConfig:
    endpoint: str
    secret: str
    generated_config: str


class ControllerConfigError(RuntimeError):
    def __init__(self, code: str, message: str, *, path: str = "") -> None:
        self.code = code
        self.path = path
        self.message = message
        location = f" ({path})" if path else ""
        super().__init__(f"{code}{location}: {message}")

    def as_dict(self) -> dict[str, str]:
        payload = {"code": self.code, "message": self.message}
        if self.path:
            payload["path"] = self.path
        return payload


def resolve_controller_config(config: MihomoConfig) -> ResolvedControllerConfig:
    generated_path = ""
    generated_endpoint = ""
    generated_secret = ""
    if config.config:
        generated_path = str(Path(config.config).expanduser().resolve(strict=False))
        generated_endpoint, generated_secret = _load_generated_config(generated_path)

    explicit_endpoint = config.api.strip()
    endpoint = (
        generated_endpoint or explicit_endpoint
        if config.managed
        else explicit_endpoint or generated_endpoint
    )
    if not endpoint:
        raise ControllerConfigError(
            "CONTROLLER_ENDPOINT_MISSING",
            "no Mihomo controller endpoint was configured",
            path=generated_path,
        )
    endpoint = normalize_controller_endpoint(endpoint, path=generated_path)
    secret = config.secret if config.secret else generated_secret
    return ResolvedControllerConfig(
        endpoint=endpoint,
        secret=secret,
        generated_config=generated_path,
    )


def normalize_controller_endpoint(value: str, *, path: str = "") -> str:
    raw = value.strip()
    if not raw:
        raise ControllerConfigError(
            "CONTROLLER_ENDPOINT_INVALID", "controller endpoint is empty", path=path
        )
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme == "unix":
        socket_path = parsed.path
        if parsed.netloc or not socket_path or not Path(socket_path).is_absolute():
            raise ControllerConfigError(
                "CONTROLLER_ENDPOINT_INVALID",
                "Unix controller must use an absolute socket path",
                path=path,
            )
        return f"unix://{socket_path}"
    if parsed.scheme not in {"http", "https"}:
        raise ControllerConfigError(
            "CONTROLLER_ENDPOINT_INVALID",
            "controller endpoint must use unix://, http://, or https://",
            path=path,
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ControllerConfigError(
            "CONTROLLER_ENDPOINT_INVALID", "controller port is invalid", path=path
        ) from exc
    if (
        not parsed.hostname
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ControllerConfigError(
            "CONTROLLER_ENDPOINT_INVALID",
            "HTTP controller must include a host and port without a path",
            path=path,
        )
    return raw.rstrip("/")


def _load_generated_config(path: str) -> tuple[str, str]:
    config_path = Path(path)
    try:
        with config_path.open(encoding="utf-8") as stream:
            payload = yaml.safe_load(stream)
    except FileNotFoundError as exc:
        raise ControllerConfigError(
            "CONTROLLER_CONFIG_NOT_FOUND", "generated config does not exist", path=path
        ) from exc
    except PermissionError as exc:
        raise ControllerConfigError(
            "CONTROLLER_CONFIG_UNREADABLE", "generated config is not readable", path=path
        ) from exc
    except OSError as exc:
        raise ControllerConfigError(
            "CONTROLLER_CONFIG_UNREADABLE", str(exc), path=path
        ) from exc
    except yaml.YAMLError as exc:
        raise ControllerConfigError(
            "CONTROLLER_CONFIG_INVALID", "generated config is invalid YAML", path=path
        ) from exc
    if not isinstance(payload, dict):
        raise ControllerConfigError(
            "CONTROLLER_CONFIG_INVALID", "generated config must be a YAML mapping", path=path
        )

    endpoint = ""
    unix_socket = payload.get("external-controller-unix")
    tcp_controller = payload.get("external-controller")
    if unix_socket:
        endpoint = f"unix://{unix_socket}"
    elif tcp_controller:
        endpoint = str(tcp_controller)
    secret_value = payload.get("secret", "")
    secret = str(secret_value) if secret_value is not None else ""
    return endpoint, secret

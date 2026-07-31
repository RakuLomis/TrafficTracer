"""Tests for structured Mihomo controller config resolution."""

from pathlib import Path

import pytest

from traffictracer.capture.controller_config import (
    ControllerConfigError,
    normalize_controller_endpoint,
    resolve_controller_config,
)
from traffictracer.config import MihomoConfig


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test" / "fixtures" / "clash_verge"


def test_installed_clash_verge_config_resolves_unix_socket_and_secret():
    resolved = resolve_controller_config(
        MihomoConfig(
            config=str(FIXTURES / "installed.yaml"),
            api="http://127.0.0.1:9090",
            managed=True,
        )
    )
    assert resolved.endpoint == "unix:///tmp/verge/verge-mihomo.sock"
    assert resolved.secret == "installed-generated-secret"
    assert resolved.generated_config == str((FIXTURES / "installed.yaml").resolve())


def test_development_config_resolves_tcp_controller():
    resolved = resolve_controller_config(
        MihomoConfig(config=str(FIXTURES / "development.yaml"), managed=True)
    )
    assert resolved.endpoint == "http://127.0.0.1:19090"
    assert resolved.secret == "development-generated-secret"


def test_external_mode_prefers_explicit_endpoint_and_secret():
    resolved = resolve_controller_config(
        MihomoConfig(
            config=str(FIXTURES / "installed.yaml"),
            api="http://127.0.0.1:29090",
            secret="explicit-secret",
            managed=False,
        )
    )
    assert resolved.endpoint == "http://127.0.0.1:29090"
    assert resolved.secret == "explicit-secret"


def test_external_mode_uses_generated_secret_when_explicit_secret_is_empty():
    resolved = resolve_controller_config(
        MihomoConfig(
            config=str(FIXTURES / "installed.yaml"),
            api="unix:///tmp/verge/verge-mihomo.sock",
            secret="",
            managed=False,
        )
    )
    assert resolved.secret == "installed-generated-secret"


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("ftp://127.0.0.1:21", "must use"),
        ("unix://relative.sock", "absolute"),
        ("http://127.0.0.1", "host and port"),
        ("http://127.0.0.1:bad", "port is invalid"),
        ("http://127.0.0.1:9090/path", "without a path"),
    ],
)
def test_invalid_endpoints_have_stable_structured_error(value, message):
    with pytest.raises(ControllerConfigError, match=message) as caught:
        normalize_controller_endpoint(value)
    assert caught.value.code == "CONTROLLER_ENDPOINT_INVALID"
    assert caught.value.as_dict()["code"] == "CONTROLLER_ENDPOINT_INVALID"


def test_missing_and_invalid_generated_configs_are_not_silently_ignored(tmp_path):
    missing = tmp_path / "missing.yaml"
    with pytest.raises(ControllerConfigError) as caught:
        resolve_controller_config(MihomoConfig(config=str(missing)))
    assert caught.value.code == "CONTROLLER_CONFIG_NOT_FOUND"

    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("external-controller: [", encoding="utf-8")
    with pytest.raises(ControllerConfigError) as caught:
        resolve_controller_config(MihomoConfig(config=str(malformed)))
    assert caught.value.code == "CONTROLLER_CONFIG_INVALID"

    non_mapping = tmp_path / "list.yaml"
    non_mapping.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(ControllerConfigError) as caught:
        resolve_controller_config(MihomoConfig(config=str(non_mapping)))
    assert caught.value.code == "CONTROLLER_CONFIG_INVALID"


def test_no_generated_config_uses_explicit_controller():
    resolved = resolve_controller_config(
        MihomoConfig(config="", api="https://controller.example:9443", secret="token")
    )
    assert resolved.endpoint == "https://controller.example:9443"
    assert resolved.generated_config == ""

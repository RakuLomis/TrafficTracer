"""Static safety and wiring tests for the privileged TUN E2E gate."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "test" / "e2e" / "tun" / "run.py"


def _driver_module():
    spec = spec_from_file_location("traffictracer_tun_e2e", DRIVER)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tun_driver_generates_isolated_non_auto_route_config(tmp_path):
    module = _driver_module()
    sandbox = module.NetworkSandbox(tmp_path)
    config = tmp_path / "config.yaml"
    module.write_core_config(config, tmp_path / "controller.sock", sandbox)
    text = config.read_text(encoding="utf-8")
    assert "tun:\n  enable: true" in text
    assert f"device: {sandbox.tun}" in text
    assert f"interface-name: {sandbox.physical}" in text
    assert "auto-route: false" in text
    assert "auto-detect-interface: false" in text


def test_privileged_gate_refuses_root_and_requires_noninteractive_sudo():
    script = (ROOT / "scripts" / "test-e2e-tun.sh").read_text(encoding="utf-8")
    assert "${EUID} -eq 0" in script
    assert "sudo -n true" in script
    assert "dumpcap -D" in script
    assert "exec \"$python_bin\"" in script


def test_privileged_workflow_is_manual_and_uses_dedicated_runner():
    workflow = (
        ROOT / ".github" / "workflows" / "privileged-tun-e2e.yml"
    ).read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "traffictracer-tun" in workflow
    assert "sudo -n true" in workflow
    assert "make test-e2e-tun" in workflow

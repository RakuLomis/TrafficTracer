"""Consistency checks for the TrafficTracer Complete component lock."""

from pathlib import Path
import subprocess

import yaml

from traffictracer import version


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "complete" / "components.lock.yaml"


def _git_output(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _load_lock() -> dict:
    with LOCK_PATH.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def test_component_lock_matches_checked_out_submodules():
    lock = _load_lock()
    for name in ("mihomo", "clash_verge_rev"):
        component = lock["components"][name]
        path = ROOT / component["path"]
        assert path.is_dir(), f"initialize the {name} submodule"
        assert _git_output("rev-parse", "HEAD", cwd=path) == component["commit"]


def test_component_lock_matches_gitlinks():
    lock = _load_lock()
    tree = {
        line.split()[3]: line.split()[2]
        for line in _git_output("ls-tree", "HEAD", "components/mihomo", "components/clash-verge-rev").splitlines()
    }
    for name in ("mihomo", "clash_verge_rev"):
        component = lock["components"][name]
        assert tree[component["path"]] == component["commit"]


def test_component_lock_matches_python_versions():
    lock = _load_lock()
    assert lock["schema_version"] == 1
    assert lock["product"]["version"] == version.COMPLETE_VERSION
    assert lock["protocols"] == {
        "worker_api": version.WORKER_API_VERSION,
        "session_manifest": version.SESSION_SCHEMA_VERSION,
        "flow_result": version.FLOW_SCHEMA_VERSION,
        "mihomo_tracing_api": version.MIHOMO_TRACING_API_VERSION,
        "mihomo_event_schema": version.MIHOMO_EVENT_SCHEMA_VERSION,
    }

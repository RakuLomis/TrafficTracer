"""Tests for build-time component version metadata."""

import json
import subprocess
import sys
from pathlib import Path

from traffictracer.build_info import component_versions_dict


ROOT = Path(__file__).resolve().parents[1]


def test_development_build_info_is_contract_shaped():
    payload = component_versions_dict()
    assert set(payload) == {
        "traffictracer", "mihomo", "clash_verge_rev", "worker_api",
    }
    assert payload["worker_api"] == 2


def test_build_info_generator_uses_locked_component_commits(tmp_path):
    output = tmp_path / "build-info.json"
    traffictracer_commit = "a" * 40
    subprocess.run([
        sys.executable,
        str(ROOT / "scripts" / "write-build-info.py"),
        "--lock", str(ROOT / "complete" / "components.lock.yaml"),
        "--output", str(output),
        "--traffictracer-commit", traffictracer_commit,
    ], check=True)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["traffictracer"]["commit"] == traffictracer_commit
    assert payload["mihomo"]["commit"] == (
        "dcf2215aa223f655c5df3d82b515ab98acc5a4bb"
    )
    assert payload["clash_verge_rev"]["commit"] == (
        "e6a8d23a59ff8a09205b840d7d39c3ea9dc51492"
    )

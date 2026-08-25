"""Functional gate for the opt-in SessionStore scaling benchmark."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "benchmark-session-store.py"


def test_session_store_benchmark_builds_all_adversarial_fixtures():
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--sessions",
            "12",
            "--repetitions",
            "1",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["schema_version"] == 1
    assert result["fixture"] == {
        "requested_sessions": 12,
        "valid_manifests": 13,
        "corrupt_manifests": 1,
        "duplicate_detected": True,
        "interrupted_session_id": result["fixture"]["interrupted_session_id"],
    }
    assert result["fixture"]["interrupted_session_id"]
    assert set(result["measurements"]) == {
        "store_construction",
        "scan",
        "scan_scope",
        "get",
        "warm_catalog_get",
        "artifact_path",
        "known_session_artifact_path",
        "scope_for_job",
        "recovery_discovery",
    }
    for measurement in result["measurements"].values():
        assert len(measurement["samples_ms"]) == 1
        assert measurement["minimum_ms"] >= 0
        assert measurement["maximum_ms"] >= measurement["minimum_ms"]

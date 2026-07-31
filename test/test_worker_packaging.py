"""Build-contract tests for the standalone Complete Worker sidecar."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "packaging" / "traffictracer-worker.spec"
BUILD = ROOT / "scripts" / "build-worker.sh"
SMOKE = ROOT / "scripts" / "smoke-worker.py"


def test_pyinstaller_spec_bundles_contracts_lock_and_tauri_sidecar_name():
    text = SPEC.read_text(encoding="utf-8")
    assert '"traffictracer-worker-x86_64-unknown-linux-gnu"' in text
    assert 'repo_root / "contracts"' in text
    assert 'repo_root / "complete" / "components.lock.yaml"' in text
    assert 'repo_root / "traffictracer_worker.py"' in text
    assert "console=True" in text
    assert "upx=False" in text


def test_worker_build_scripts_are_executable_and_shell_is_valid():
    assert BUILD.stat().st_mode & 0o111
    assert SMOKE.stat().st_mode & 0o111
    subprocess.run(["bash", "-n", str(BUILD)], check=True)
    build_text = BUILD.read_text(encoding="utf-8")
    assert "requirements-build.txt" in build_text
    assert "smoke-worker.py" in build_text
    assert "--specpath" not in build_text


def test_smoke_script_runs_source_worker_from_isolated_temp_cwd():
    completed = subprocess.run(
        [
            sys.executable,
            str(SMOKE),
            "--",
            sys.executable,
            str(ROOT / "traffictracer_worker.py"),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        cwd=ROOT,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "hello/diagnose smoke passed" in completed.stdout

"""Tests for the one-command Complete development build."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILD_UI = ROOT / "scripts" / "build-ui.sh"
TARGET = "x86_64-unknown-linux-gnu"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def fake_build(tmp_path: Path) -> dict[str, Path | dict[str, str]]:
    ui_dir = tmp_path / "ui"
    mihomo_dir = tmp_path / "mihomo"
    sidecar_dir = ui_dir / "src-tauri" / "sidecar"
    core_dist = tmp_path / "dist" / "core"
    worker_dist = tmp_path / "dist" / "worker"
    bin_dir = tmp_path / "bin"
    for directory in (sidecar_dir, mihomo_dir, bin_dir):
        directory.mkdir(parents=True)

    core_build = bin_dir / "build-core"
    _write_executable(
        core_build,
        """#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$(dirname -- "$1")"
printf 'fresh-core' >"$1"
chmod 0755 "$1"
""",
    )
    worker_build = bin_dir / "build-worker"
    _write_executable(
        worker_build,
        f"""#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$TT_WORKER_DIST_DIR"
printf 'fresh-worker' >"$TT_WORKER_DIST_DIR/traffictracer-worker-{TARGET}"
chmod 0755 "$TT_WORKER_DIST_DIR/traffictracer-worker-{TARGET}"
""",
    )
    fake_pnpm = bin_dir / "pnpm"
    _write_executable(
        fake_pnpm,
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s offline=%s\n' "$*" "${TT_PREBUILD_OFFLINE:-unset}" >>"$TT_TEST_INVOCATIONS"
case "$1" in
  prebuild)
    target="${!#}"
    mkdir -p src-tauri/sidecar
    cp "$MIHOMO_TRAFFIC_TRACER_BIN" "src-tauri/sidecar/verge-mihomo-tt-$target"
    cp "$TRAFFICTRACER_WORKER_BIN" "src-tauri/sidecar/traffictracer-worker-$target"
    chmod 0755 "src-tauri/sidecar/verge-mihomo-tt-$target"
    chmod 0755 "src-tauri/sidecar/traffictracer-worker-$target"
    ;;
  dev)
    : >"$TT_TEST_DEV_MARKER"
    ;;
  *)
    exit 64
    ;;
esac
""",
    )
    lock_check = bin_dir / "check-component-lock"
    _write_executable(
        lock_check,
        """#!/usr/bin/env bash
set -euo pipefail
test "$1" = "--core"
test "$3" = "--worker"
printf 'lock-check %s %s\n' "$2" "$4" >>"$TT_TEST_INVOCATIONS"
""",
    )

    invocations = tmp_path / "invocations"
    dev_marker = tmp_path / "dev-started"
    env = {
        **os.environ,
        "TT_UI_DIR": str(ui_dir),
        "TT_MIHOMO_DIR": str(mihomo_dir),
        "TT_CORE_DIST_DIR": str(core_dist),
        "TT_WORKER_DIST_DIR": str(worker_dist),
        "TT_BUILD_CORE_SCRIPT": str(core_build),
        "TT_BUILD_WORKER_SCRIPT": str(worker_build),
        "TT_PNPM_BIN": str(fake_pnpm),
        "TT_COMPONENT_LOCK_CHECK": str(lock_check),
        "TT_TEST_INVOCATIONS": str(invocations),
        "TT_TEST_DEV_MARKER": str(dev_marker),
    }
    return {
        "ui_dir": ui_dir,
        "sidecar_dir": sidecar_dir,
        "invocations": invocations,
        "dev_marker": dev_marker,
        "env": env,
    }


def test_prepare_dev_overwrites_stale_sidecars(fake_build) -> None:
    sidecar_dir = fake_build["sidecar_dir"]
    (sidecar_dir / f"verge-mihomo-tt-{TARGET}").write_text("stale", encoding="utf-8")
    (sidecar_dir / f"traffictracer-worker-{TARGET}").write_text(
        "stale", encoding="utf-8"
    )

    result = subprocess.run(
        ["bash", str(BUILD_UI), "--prepare-only"],
        env=fake_build["env"],
        text=True,
        capture_output=True,
        check=True,
    )

    assert (sidecar_dir / f"verge-mihomo-tt-{TARGET}").read_text() == "fresh-core"
    assert (
        sidecar_dir / f"traffictracer-worker-{TARGET}"
    ).read_text() == "fresh-worker"
    invocations = fake_build["invocations"].read_text().splitlines()
    assert invocations[0].startswith("lock-check ")
    assert invocations[1:] == [f"prebuild --force {TARGET} offline=0"]
    assert not fake_build["dev_marker"].exists()
    assert f"Injected sidecars are current for {TARGET}." in result.stdout
    assert "Artifact hashes:" in result.stdout


def test_prepare_dev_can_reuse_existing_upstream_resources(fake_build) -> None:
    env = {**fake_build["env"], "TT_PREBUILD_FORCE": "0"}

    result = subprocess.run(
        ["bash", str(BUILD_UI), "--prepare-only"],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )

    invocations = fake_build["invocations"].read_text().splitlines()
    assert invocations[0].startswith("lock-check ")
    assert invocations[1:] == [f"prebuild {TARGET} offline=1"]
    assert "Preparing UI resources with TT_PREBUILD_FORCE=0." in result.stdout


def test_prepare_dev_rejects_invalid_prebuild_force(fake_build) -> None:
    env = {**fake_build["env"], "TT_PREBUILD_FORCE": "sometimes"}
    result = subprocess.run(
        ["bash", str(BUILD_UI), "--prepare-only"],
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
    assert "TT_PREBUILD_FORCE must be 0 or 1" in result.stderr


def test_dev_starts_only_after_sidecars_are_verified(fake_build) -> None:
    subprocess.run(
        ["bash", str(BUILD_UI)],
        env=fake_build["env"],
        text=True,
        capture_output=True,
        check=True,
    )

    invocations = fake_build["invocations"].read_text().splitlines()
    assert invocations[0].startswith("lock-check ")
    assert invocations[1:] == [
        f"prebuild --force {TARGET} offline=0",
        "dev offline=unset",
    ]
    assert fake_build["dev_marker"].is_file()

"""Tests for the atomic TrafficTracer Complete Linux packaging wrapper."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "scripts" / "package-linux.sh"
TARGET = "x86_64-unknown-linux-gnu"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def fake_package(tmp_path: Path) -> dict[str, object]:
    ui_dir = tmp_path / "ui"
    sidecars = ui_dir / "src-tauri" / "sidecar"
    bin_dir = tmp_path / "bin"
    target_dir = tmp_path / "target"
    output_dir = tmp_path / "published"
    sidecars.mkdir(parents=True)
    bin_dir.mkdir()

    prepare = bin_dir / "prepare"
    _write_executable(
        prepare,
        """#!/usr/bin/env bash
set -euo pipefail
test "$1" = "--prepare-only"
printf 'prepared\n' >>"$TT_TEST_INVOCATIONS"
""",
    )

    pnpm = bin_dir / "pnpm"
    _write_executable(
        pnpm,
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$TT_TEST_INVOCATIONS"
if [[ "$1 $2" == "tauri build" ]]; then
  root="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/bundle"
  mkdir -p "$root/deb" "$root/appimage"
  printf 'deb-package' >"$root/deb/TrafficTracer.deb"
  printf 'appimage-package' >"$root/appimage/TrafficTracer.AppImage"
elif [[ "$1" == "verify:linux-bundle" ]]; then
  [[ "${TT_TEST_VERIFY_FAIL:-0}" != "1" ]]
else
  exit 64
fi
""",
    )

    invocations = tmp_path / "invocations"
    env = {
        **os.environ,
        "TT_UI_DIR": str(ui_dir),
        "TT_PREPARE_SCRIPT": str(prepare),
        "TT_PNPM_BIN": str(pnpm),
        "TT_TAURI_TARGET_DIR": str(target_dir),
        "TT_PACKAGE_OUTPUT_DIR": str(output_dir),
        "TT_TEST_INVOCATIONS": str(invocations),
    }
    return {
        "env": env,
        "output": output_dir,
        "invocations": invocations,
    }


def test_package_collects_only_verified_fresh_artifacts(fake_package) -> None:
    result = subprocess.run(
        ["bash", str(PACKAGE)],
        env=fake_package["env"],
        text=True,
        capture_output=True,
        check=True,
    )

    output = fake_package["output"]
    assert (output / "TrafficTracer.deb").read_text() == "deb-package"
    assert (output / "TrafficTracer.AppImage").read_text() == "appimage-package"
    assert (output / "SHA256SUMS").read_text().count("\n") == 2
    assert f"target={TARGET}" in (output / "COMPONENTS").read_text()
    calls = fake_package["invocations"].read_text().splitlines()
    assert calls[0] == "prepared"
    assert "tauri build --target x86_64-unknown-linux-gnu --bundles deb,appimage" in calls[1]
    assert 'createUpdaterArtifacts":false' in calls[1]
    assert calls[2].startswith("verify:linux-bundle -- --target ")
    assert "Package directory:" in result.stdout


def test_verification_failure_does_not_publish(fake_package) -> None:
    env = {**fake_package["env"], "TT_TEST_VERIFY_FAIL": "1"}
    result = subprocess.run(
        ["bash", str(PACKAGE)],
        env=env,
        text=True,
        capture_output=True,
    )

    assert result.returncode != 0
    assert not fake_package["output"].exists()


def test_existing_output_is_not_overwritten(fake_package) -> None:
    output = fake_package["output"]
    output.mkdir()
    marker = output / "keep"
    marker.write_text("user artifact", encoding="utf-8")

    result = subprocess.run(
        ["bash", str(PACKAGE)],
        env=fake_package["env"],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert marker.read_text() == "user artifact"
    assert not fake_package["invocations"].exists()

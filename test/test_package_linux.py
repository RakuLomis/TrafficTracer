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
    icons = ui_dir / "src-tauri" / "icons"
    bin_dir = tmp_path / "bin"
    resources = ui_dir / "src-tauri" / "resources"
    target_dir = tmp_path / "target"
    output_dir = tmp_path / "published"
    sidecars.mkdir(parents=True)
    icons.mkdir()
    bin_dir.mkdir()
    resources.mkdir()
    (ui_dir / "src-tauri" / "tauri.conf.json").write_text(
        '{"version":"2.5.2"}', encoding="utf-8"
    )

    icon = icons / "icon.png"
    icon.write_bytes(b"fake icon")
    icon.chmod(0o666)

    resource = resources / "Country.mmdb"
    resource.write_bytes(b"fake database")
    resource.chmod(0o666)

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
if [[ "$1 $2" == "exec node" ]]; then
  exit 0
fi
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

    cargo = bin_dir / "cargo"
    _write_executable(cargo, "#!/usr/bin/env bash\nexit 0\n")

    invocations = tmp_path / "invocations"
    env = {
        **os.environ,
        "TT_UI_DIR": str(ui_dir),
        "TT_PREPARE_SCRIPT": str(prepare),
        "TT_PNPM_BIN": str(pnpm),
        "CARGO": str(cargo),
        "TT_TAURI_TARGET_DIR": str(target_dir),
        "TT_PACKAGE_OUTPUT_DIR": str(output_dir),
        "TT_TEST_INVOCATIONS": str(invocations),
    }
    return {
        "env": env,
        "output": output_dir,
        "invocations": invocations,
        "icon": icon,
        "resource": resource,
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
    deb = output / "TrafficTracer-Complete_1.0.13_linux_x86_64.deb"
    appimage = output / "TrafficTracer-Complete_1.0.13_linux_x86_64.AppImage"
    assert deb.read_text() == "deb-package"
    assert appimage.read_text() == "appimage-package"
    assert (output / "SHA256SUMS").read_text().count("\n") == 2
    assert f"target={TARGET}" in (output / "COMPONENTS").read_text()
    assert "product_version=1.0.13" in (output / "COMPONENTS").read_text()
    assert "version=1.0.13" in (output / "VERSION").read_text()
    calls = fake_package["invocations"].read_text().splitlines()
    assert calls[0] == "prepared"
    assert "tauri build --target x86_64-unknown-linux-gnu --bundles deb,appimage" in calls[1]
    assert '"version": "2.5.2+traffictracer.1.0.13"' in calls[1]
    assert 'createUpdaterArtifacts": false' in calls[1]
    assert calls[2].startswith("verify:linux-bundle -- --target ")
    assert "Package directory:" in result.stdout
    assert fake_package["icon"].stat().st_mode & 0o777 == 0o644
    assert fake_package["resource"].stat().st_mode & 0o777 == 0o644

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


def test_release_mode_audits_stage_before_publish(fake_package, tmp_path) -> None:
    audit = tmp_path / "release-audit"
    _write_executable(
        audit,
        """#!/usr/bin/env python3
from pathlib import Path
import sys
assert sys.argv[1] == "--package-dir"
assert sys.argv[3] == "--write"
stage = Path(sys.argv[2])
assert (stage / "SHA256SUMS").is_file()
assert (stage / "COMPONENTS").is_file()
assert (stage / "VERSION").is_file()
(stage / "RELEASE-AUDIT.json").write_text('{"status":"pass"}\\n')
""",
    )
    env = {
        **fake_package["env"],
        "TT_RELEASE_AUDIT": "1",
        "TT_RELEASE_AUDIT_SCRIPT": str(audit),
    }

    subprocess.run(
        ["bash", str(PACKAGE)],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )

    assert (fake_package["output"] / "RELEASE-AUDIT.json").is_file()


def test_release_audit_failure_does_not_publish(fake_package, tmp_path) -> None:
    audit = tmp_path / "release-audit"
    _write_executable(audit, "#!/usr/bin/env python3\nraise SystemExit(42)\n")
    env = {
        **fake_package["env"],
        "TT_RELEASE_AUDIT": "1",
        "TT_RELEASE_AUDIT_SCRIPT": str(audit),
    }

    result = subprocess.run(
        ["bash", str(PACKAGE)],
        env=env,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 42
    assert not fake_package["output"].exists()

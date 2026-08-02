import hashlib
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "smoke_package_linux",
    ROOT / "scripts" / "smoke-package-linux.py",
)
assert SPEC is not None and SPEC.loader is not None
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def installed_root(tmp_path: Path) -> Path:
    root = tmp_path / "installed"
    binary_dir = root / "usr" / "bin"
    binary_dir.mkdir(parents=True)
    for name in smoke.REQUIRED:
        binary = binary_dir / name
        binary.write_bytes(b"executable")
        binary.chmod(0o755)
    application_dir = root / "usr" / "share" / "applications"
    application_dir.mkdir(parents=True)
    (application_dir / "Clash Verge.desktop").write_text(
        "[Desktop Entry]\nExec=clash-verge\n",
        encoding="utf-8",
    )
    return root


def test_assert_executables_accepts_complete_installed_layout(tmp_path):
    binaries = smoke.assert_executables(installed_root(tmp_path))

    assert tuple(binaries) == smoke.REQUIRED
    assert all(path.is_file() for path in binaries.values())


def test_assert_executables_rejects_missing_service_helper(tmp_path):
    root = installed_root(tmp_path)
    (root / "usr" / "bin" / "clash-verge-service-install").unlink()

    with pytest.raises(smoke.SmokeFailure, match="service-install"):
        smoke.assert_executables(root)


def test_verify_checksum_detects_tampered_package(tmp_path):
    artifact = tmp_path / "Complete Package.AppImage"
    artifact.write_bytes(b"published package")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (tmp_path / "SHA256SUMS").write_text(
        f"{digest}  {artifact.name}\n",
        encoding="utf-8",
    )
    smoke.verify_checksum(artifact)

    artifact.write_bytes(b"tampered package")
    with pytest.raises(smoke.SmokeFailure, match="checksum mismatch"):
        smoke.verify_checksum(artifact)


def test_clean_vm_workflow_runs_package_ui_smoke():
    workflow = (ROOT / ".github" / "workflows" / "linux-package-smoke.yml").read_text(
        encoding="utf-8"
    )
    assert "make package-linux" in workflow
    assert "TT_SMOKE_LAUNCH_UI: \"1\"" in workflow
    assert "make test-package-linux" in workflow
    assert "submodules: recursive" in workflow

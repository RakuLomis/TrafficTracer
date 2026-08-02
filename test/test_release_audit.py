import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_audit",
    ROOT / "scripts" / "release-audit.py",
)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def installed_root(tmp_path: Path) -> Path:
    root = tmp_path / "installed"
    binary_dir = root / "usr" / "bin"
    binary_dir.mkdir(parents=True)
    for directory in (root, root / "usr", binary_dir):
        directory.chmod(0o755)
    for name in audit.REQUIRED_BINARIES:
        binary = binary_dir / name
        binary.write_bytes(b"binary")
        binary.chmod(0o755)
    return root


def test_checksum_parser_preserves_package_names_with_spaces(tmp_path):
    path = tmp_path / "SHA256SUMS"
    digest = "a" * 64
    path.write_text(f"{digest}  Clash Verge Complete.deb\n", encoding="utf-8")

    assert audit.parse_checksums(path) == {"Clash Verge Complete.deb": digest}


def test_checksum_parser_rejects_duplicate_entries(tmp_path):
    path = tmp_path / "SHA256SUMS"
    path.write_text(
        f"{'a' * 64}  package.deb\n{'b' * 64}  package.deb\n",
        encoding="utf-8",
    )

    with pytest.raises(audit.AuditFailure, match="duplicate"):
        audit.parse_checksums(path)


def test_installed_layout_rejects_secret_and_unsafe_permissions(tmp_path):
    root = installed_root(tmp_path)
    assert audit.audit_installed_root(root)["files"] == len(audit.REQUIRED_BINARIES)

    secret = root / "usr" / "share" / "config.yaml"
    secret.parent.mkdir(parents=True)
    secret.write_text("secret: do-not-publish-this-token", encoding="utf-8")
    secret.chmod(0o644)
    secret.parent.chmod(0o755)
    with pytest.raises(audit.AuditFailure, match="sensitive file name"):
        audit.audit_installed_root(root)

    secret.unlink()
    binary = root / "usr" / "bin" / "clash-verge"
    binary.chmod(0o777)
    with pytest.raises(audit.AuditFailure, match="world-writable"):
        audit.audit_installed_root(root)


def test_group_writable_apprun_wrapper_is_limited_to_immutable_appimage(tmp_path):
    root = installed_root(tmp_path)
    launcher = root / "AppRun"
    launcher.write_bytes(b"launcher")
    launcher.chmod(0o755)
    wrapper = root / "AppRun.wrapped"
    wrapper.write_bytes(b"wrapped")
    wrapper.chmod(0o770)

    with pytest.raises(audit.AuditFailure, match="group/world-writable"):
        audit.audit_installed_root(root)
    assert audit.audit_installed_root(
        root, immutable_appimage=True
    )["files"] == len(audit.REQUIRED_BINARIES) + 2

    wrapper.chmod(0o777)
    with pytest.raises(audit.AuditFailure, match="group/world-writable"):
        audit.audit_installed_root(root, immutable_appimage=True)


def test_installed_layout_rejects_embedded_private_key(tmp_path):
    root = installed_root(tmp_path)
    notice = root / "usr" / "share" / "notice.txt"
    notice.parent.mkdir(parents=True)
    notice.parent.chmod(0o755)
    notice.write_text(
        "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n",
        encoding="utf-8",
    )

    notice.chmod(0o644)
    with pytest.raises(audit.AuditFailure, match="embedded secret"):
        audit.audit_installed_root(root)


def test_installed_layout_allows_only_standard_appimage_diricon(tmp_path):
    root = installed_root(tmp_path)
    icon = root / "Clash Verge.png"
    icon.write_bytes(b"png")
    icon.chmod(0o644)
    (root / ".DirIcon").symlink_to("/build/AppDir/Clash Verge.png")

    assert audit.audit_installed_root(root)["symlinks"] == 1

    escaping = root / "escape"
    escaping.symlink_to("/etc/passwd")
    with pytest.raises(audit.AuditFailure, match="escaping symlink"):
        audit.audit_installed_root(root)


def test_package_builder_uses_release_safe_umask():
    package_script = (ROOT / "scripts" / "package-linux.sh").read_text(
        encoding="utf-8"
    )

    assert "umask 022" in package_script



def test_installed_layout_scans_large_files_without_losing_root(tmp_path):
    root = installed_root(tmp_path)
    data_dir = root / "usr" / "share"
    data_dir.mkdir(parents=True)
    data_dir.chmod(0o755)
    large = data_dir / "large-resource.bin"
    large.write_bytes(b"\x00" * (2 * 1024 * 1024 + 1))
    large.chmod(0o644)

    result = audit.audit_installed_root(root)

    assert result["files"] == len(audit.REQUIRED_BINARIES) + 1


def test_large_binary_requires_complete_pem_before_reporting_secret(tmp_path):
    root = installed_root(tmp_path)
    data_dir = root / "usr" / "lib"
    data_dir.mkdir(parents=True)
    data_dir.chmod(0o755)
    binary = data_dir / "library.so"
    padding = b"\x00" * (2 * 1024 * 1024 + 1)
    binary.write_bytes(padding + b"-----BEGIN PRIVATE KEY-----")
    binary.chmod(0o644)

    audit.audit_installed_root(root)

    private_key = (
        b"-----BEGIN PRIVATE KEY-----\n"
        + b"A" * 128
        + b"\n-----END PRIVATE KEY-----"
    )
    binary.write_bytes(padding + private_key)
    with pytest.raises(audit.AuditFailure, match="embedded secret"):
        audit.audit_installed_root(root)


def test_sbom_covers_all_locked_ecosystems():
    lock = audit.load_lock(ROOT)
    revisions = {
        "traffictracer": "1" * 40,
        "mihomo": lock["components"]["mihomo"]["commit"],
        "clash_verge_rev": lock["components"]["clash_verge_rev"]["commit"],
        "clash_verge_service": lock["components"]["clash_verge_service"]["commit"],
    }

    sbom = audit.generate_sbom(ROOT, lock, revisions)

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    references = [item["bom-ref"] for item in sbom["components"]]
    assert len(references) == len(set(references))
    assert len(references) > 1000
    assert any(value.startswith("pypi:") for value in references)
    assert any(value.startswith("golang:") for value in references)
    assert any(value.startswith("cargo:") for value in references)
    assert any(value.startswith("npm:") for value in references)
    assert any("clash-verge-service-ipc@v2.6.1" in value for value in references)


def test_release_metadata_round_trip_and_tamper_detection(tmp_path):
    repo = tmp_path / "repo"
    release = tmp_path / "release"
    repo.mkdir()
    release.mkdir()
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
        (repo / name).write_text(f"{name}\n", encoding="utf-8")
    (release / "COMPONENTS").write_text("target=test\n", encoding="utf-8")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"name": f"dependency-{index}", "version": "1"}
            for index in range(100)
        ],
    }

    audit.write_release_metadata(repo, release, sbom)
    audit.verify_release_metadata(release, sbom)
    assert json.loads((release / "SBOM.cdx.json").read_text()) == sbom

    (release / "NOTICE").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(audit.AuditFailure, match="checksum failed"):
        audit.verify_release_metadata(release, sbom)

    metadata_path = release / "METADATA.sha256"
    metadata_path.write_text(
        "\n".join(
            line for line in metadata_path.read_text().splitlines() if "NOTICE" not in line
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(audit.AuditFailure, match="must cover every"):
        audit.verify_release_metadata(release, sbom)
    audit.write_release_metadata(repo, release, sbom)


def test_release_workflow_builds_and_verifies_audited_artifacts():
    workflow = (
        ROOT / ".github" / "workflows" / "linux-package-smoke.yml"
    ).read_text(encoding="utf-8")
    package_script = (ROOT / "scripts" / "package-linux.sh").read_text(
        encoding="utf-8"
    )

    assert "make release-linux" in workflow
    assert "make audit-release" in workflow
    assert "TT_RELEASE_AUDIT" in package_script
    assert "--write" in package_script

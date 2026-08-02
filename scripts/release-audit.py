#!/usr/bin/env python3
"""Generate and verify TrafficTracer Complete release audit artifacts."""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Iterable
from urllib.parse import quote
import uuid

import yaml


TARGET = "x86_64-unknown-linux-gnu"
REQUIRED_BINARIES = (
    "clash-verge",
    "clash-verge-service",
    "clash-verge-service-install",
    "clash-verge-service-uninstall",
    "verge-mihomo",
    "verge-mihomo-alpha",
    "verge-mihomo-tt",
    "traffictracer-worker",
)
FORBIDDEN_NAMES = {
    ".env",
    "config.yaml",
    "config.yml",
    "profiles.yaml",
    "profiles.yml",
    "sites.yaml",
    "session.json",
    "recovery.json",
}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"ghp_[A-Za-z0-9]{20,}"),
    re.compile(rb"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        rb"(?i)(?:password|secret|subscription|token)\s*[:=]\s*"
        rb"[\"']?[A-Za-z0-9._~+/=-]{12,}"
    ),
)
LARGE_FILE_SECRET_PATTERNS = (
    re.compile(
        rb"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]{80,}\r?\n"
        rb"-----END (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"
    ),
    *SECRET_PATTERNS[1:4],
)
# Public interoperability fixtures embedded in libgnutls; only exact PEM
# content matches are exempt, never a filename or an executable class.
KNOWN_PUBLIC_TEST_SECRET_SHA256 = frozenset(
    {
        "91ea1699ff6b1a34b4a1d500a9c75a808441e47b9ea68da6fb0195e01ce1dc61",
        "a4d138d7ef9748464117b44fb9c0a4b5b85a1599a127d02690abaa96d03c16e6",
        "d039c8119a029ab9f9c83c04d67002d887b6bc6026c4264402ab27cdf24cf138",
        "ef237ea8db4f2ae9ee100e8ced96d29b5dceb0e6a948443e6b8a00b1791f9ec9",
        "fa0b06a72461ec0a963dcfccb8d5b61bd88a6074fc7271573bff68ab86b8c1af",
    }
)

PYTHON_DISTRIBUTIONS = ("PyYAML", "websockets", "jsonschema", "PyInstaller")
RELEASE_METADATA_FILES = (
    "COMPONENTS",
    "LICENSE",
    "NOTICE",
    "SBOM.cdx.json",
    "THIRD_PARTY_NOTICES.md",
)


class AuditFailure(RuntimeError):
    pass


def run(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise AuditFailure(f"{' '.join(command)} failed: {detail}")
    return completed.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, payload: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def load_lock(repo: Path) -> dict[str, Any]:
    payload = yaml.safe_load(
        (repo / "complete" / "components.lock.yaml").read_text(encoding="utf-8")
    )
    if not isinstance(payload, dict):
        raise AuditFailure("components.lock.yaml must contain an object")
    return payload


def parse_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or not value:
            raise AuditFailure(f"invalid key/value line in {path.name}: {line!r}")
        values[key] = value
    return values


def parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            raise AuditFailure(f"invalid checksum line in {path.name}: {line!r}")
        name = fields[1].removeprefix("*").removeprefix("./")
        if not name or name in checksums:
            raise AuditFailure(f"invalid or duplicate checksum entry: {name!r}")
        checksums[name] = fields[0]
    return checksums


def verify_source(repo: Path, lock: dict[str, Any]) -> dict[str, str]:
    for name, directory in (
        ("traffictracer", repo),
        ("mihomo", repo / "components" / "mihomo"),
        ("clash_verge_rev", repo / "components" / "clash-verge-rev"),
    ):
        dirty = run(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=directory
        )
        if dirty:
            raise AuditFailure(f"{name} has tracked uncommitted changes")

    required = (
        repo / "LICENSE",
        repo / "NOTICE",
        repo / "THIRD_PARTY_NOTICES.md",
        repo / "components" / "mihomo" / "LICENSE",
        repo / "components" / "clash-verge-rev" / "LICENSE",
    )
    for path in required:
        if not path.is_file():
            raise AuditFailure(f"required license or notice is missing: {path}")
    license_text = (repo / "LICENSE").read_text(encoding="utf-8")
    if "GNU GENERAL PUBLIC LICENSE" not in license_text or "Version 3" not in license_text:
        raise AuditFailure("root LICENSE is not the expected GPL version 3 text")

    root_revision = run(["git", "rev-parse", "HEAD"], cwd=repo)
    revisions = {"traffictracer": root_revision}
    for key in ("mihomo", "clash_verge_rev"):
        component = lock["components"][key]
        component_path = repo / component["path"]
        actual = run(["git", "rev-parse", "HEAD"], cwd=component_path)
        expected = str(component["commit"])
        if actual != expected:
            raise AuditFailure(
                f"{key} revision mismatch: expected {expected}, found {actual}"
            )
        revisions[key] = actual
    return revisions


def component(
    component_type: str,
    name: str,
    version: str,
    ecosystem: str,
    source: str,
    *,
    license_id: str | None = None,
) -> dict[str, Any]:
    encoded_name = quote(name, safe="/")
    result: dict[str, Any] = {
        "type": component_type,
        "bom-ref": f"{ecosystem}:{name}@{version}",
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem}/{encoded_name}@{quote(version, safe='.+-')}",
        "properties": [{"name": "traffictracer:source", "value": source}],
    }
    if license_id:
        result["licenses"] = [{"license": {"id": license_id}}]
    return result


def python_components() -> Iterable[dict[str, Any]]:
    for distribution in PYTHON_DISTRIBUTIONS:
        try:
            info = metadata.metadata(distribution)
            version = metadata.version(distribution)
        except metadata.PackageNotFoundError as exc:
            raise AuditFailure(
                f"required Python build distribution is unavailable: {distribution}"
            ) from exc
        license_id = info.get("License-Expression")
        if not license_id:
            raw = info.get("License") or ""
            if raw in {"MIT", "BSD-3-Clause"}:
                license_id = raw
        yield component(
            "library",
            distribution,
            version,
            "pypi",
            "requirements-build.txt",
            license_id=license_id,
        )


def go_components(repo: Path) -> Iterable[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    path = repo / "components" / "mihomo" / "go.sum"
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise AuditFailure(f"invalid go.sum line: {line!r}")
        name, version = fields[:2]
        version = version.removesuffix("/go.mod")
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        yield component("library", name, version, "golang", "components/mihomo/go.sum")


def rust_components(repo: Path) -> Iterable[dict[str, Any]]:
    path = repo / "components" / "clash-verge-rev" / "Cargo.lock"
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    for package in payload.get("package", []):
        source = str(package.get("source", ""))
        if not source.startswith("registry+"):
            continue
        yield component(
            "library",
            str(package["name"]),
            str(package["version"]),
            "cargo",
            "components/clash-verge-rev/Cargo.lock",
        )


def split_npm_key(key: str) -> tuple[str, str] | None:
    if "@" not in key:
        return None
    name, version = key.rsplit("@", 1)
    if not name or not version or version.startswith(("github:", "git+")):
        return None
    return name, version


def npm_components(repo: Path) -> Iterable[dict[str, Any]]:
    path = repo / "components" / "clash-verge-rev" / "pnpm-lock.yaml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    packages = payload.get("packages", {}) if isinstance(payload, dict) else {}
    if not isinstance(packages, dict):
        raise AuditFailure("pnpm-lock.yaml packages must be an object")
    for key in packages:
        parsed = split_npm_key(str(key))
        if parsed is None:
            continue
        name, version = parsed
        yield component(
            "library",
            name,
            version,
            "npm",
            "components/clash-verge-rev/pnpm-lock.yaml",
        )


def generate_sbom(
    repo: Path,
    lock: dict[str, Any],
    revisions: dict[str, str],
) -> dict[str, Any]:
    product = lock["product"]
    components = [
        component(
            "application",
            "TrafficTracer",
            str(product["version"]),
            "generic",
            "TrafficTracer Complete",
            license_id="GPL-3.0-only",
        ),
        component(
            "application",
            "mihomo",
            revisions["mihomo"],
            "generic",
            "components/mihomo",
            license_id="GPL-3.0-only",
        ),
        component(
            "application",
            "clash-verge-rev",
            revisions["clash_verge_rev"],
            "generic",
            "components/clash-verge-rev",
            license_id="GPL-3.0-only",
        ),
        *python_components(),
        *go_components(repo),
        *rust_components(repo),
        *npm_components(repo),
    ]
    unique: dict[str, dict[str, Any]] = {}
    for item in components:
        unique[item["bom-ref"]] = item
    ordered = [unique[key] for key in sorted(unique)]
    lock_hashes = {}
    for relative in (
        "requirements-build.txt",
        "components/mihomo/go.sum",
        "components/clash-verge-rev/Cargo.lock",
        "components/clash-verge-rev/pnpm-lock.yaml",
    ):
        lock_hashes[relative] = sha256(repo / relative)
    seed = "|".join((revisions["traffictracer"], revisions["mihomo"], revisions["clash_verge_rev"]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "generic:TrafficTracer@0.1.0-dev",
                "name": str(product["name"]),
                "version": str(product["version"]),
                "licenses": [{"license": {"id": "GPL-3.0-only"}}],
            },
            "properties": [
                {"name": f"traffictracer:sha256:{path}", "value": digest}
                for path, digest in sorted(lock_hashes.items())
            ],
        },
        "components": ordered,
    }


def extract_package(artifact: Path, destination: Path) -> Path:
    destination.mkdir()
    if artifact.suffix == ".deb":
        run(["dpkg-deb", "-x", str(artifact), str(destination)])
        return destination
    if artifact.name.endswith(".AppImage"):
        completed = subprocess.run(
            [str(artifact), "--appimage-extract"],
            cwd=destination,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
        if completed.returncode:
            raise AuditFailure(
                f"AppImage extraction failed: {completed.stderr.strip()}"
            )
        return destination / "squashfs-root"
    raise AuditFailure(f"unsupported package: {artifact}")


def scan_large_file(path: Path) -> None:
    overlap = b""
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            content = overlap + chunk
            for pattern in LARGE_FILE_SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    fingerprint = hashlib.sha256(match.group(0)).hexdigest()
                    if fingerprint in KNOWN_PUBLIC_TEST_SECRET_SHA256:
                        continue
                    raise AuditFailure(
                        f"possible embedded secret in package: {path.name}"
                    )
            overlap = content[-512:]


def audit_installed_root(root: Path, immutable_appimage: bool = False) -> dict[str, int]:
    root = root.resolve()
    files = 0
    symlinks = 0
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        relative = path.relative_to(root)
        if path.is_symlink():
            symlinks += 1
            target = (path.parent / os.readlink(path)).resolve()
            if not target.is_relative_to(root):
                icon = root / Path(os.readlink(path)).name
                if (
                    relative == Path(".DirIcon")
                    and icon.suffix.lower() == ".png"
                    and icon.is_file()
                ):
                    continue
                raise AuditFailure(f"escaping symlink in package: {relative}")
            continue
        if mode & (stat.S_ISUID | stat.S_ISGID):
            raise AuditFailure(f"setuid/setgid path in package: {relative}")
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            immutable_wrapper = (
                immutable_appimage
                and relative == Path("AppRun.wrapped")
                and not mode & stat.S_IWOTH
                and (root / "AppRun").is_file()
            )
            if not immutable_wrapper:
                raise AuditFailure(
                    f"group/world-writable path in package: {relative}"
                )
        if not path.is_file():
            continue
        files += 1
        lower_name = path.name.lower()
        if lower_name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise AuditFailure(f"sensitive file name in package: {relative}")
        if path.stat().st_size > 2 * 1024 * 1024:
            scan_large_file(path)
            continue
        content = path.read_bytes()
        if b"\x00" in content:
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(content):
                raise AuditFailure(f"possible embedded secret in package: {relative}")

    binary_dir = root / "usr" / "bin"
    for name in REQUIRED_BINARIES:
        binary = binary_dir / name
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise AuditFailure(f"required executable is missing: usr/bin/{name}")
    return {"files": files, "symlinks": symlinks}


def audit_packages(package_dir: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    package_dir = package_dir.resolve()
    debs = sorted(package_dir.glob("*.deb"))
    appimages = sorted(package_dir.glob("*.AppImage"))
    if len(debs) != 1 or len(appimages) != 1:
        raise AuditFailure("release directory must contain exactly one Deb and one AppImage")
    checksum_path = package_dir / "SHA256SUMS"
    if not checksum_path.is_file():
        raise AuditFailure("SHA256SUMS is missing")
    checksums = parse_checksums(checksum_path)
    results = []
    for artifact in (*debs, *appimages):
        expected = checksums.get(artifact.name)
        if expected is None or sha256(artifact) != expected:
            raise AuditFailure(f"checksum verification failed: {artifact.name}")
        mode = artifact.stat().st_mode
        if mode & stat.S_IWOTH:
            raise AuditFailure(f"release artifact is world-writable: {artifact.name}")
        with tempfile.TemporaryDirectory(prefix="traffictracer-release-audit-") as raw:
            installed = extract_package(artifact, Path(raw) / "installed")
            layout = audit_installed_root(
                installed,
                immutable_appimage=artifact.name.endswith(".AppImage"),
            )
        results.append(
            {
                "name": artifact.name,
                "sha256": expected,
                "size": artifact.stat().st_size,
                **layout,
            }
        )
    return results, checksums


def verify_component_manifest(
    package_dir: Path,
    revisions: dict[str, str],
) -> dict[str, str]:
    path = package_dir / "COMPONENTS"
    if not path.is_file():
        raise AuditFailure("COMPONENTS is missing")
    values = parse_key_values(path)
    expected = {
        "target": TARGET,
        "traffictracer": revisions["traffictracer"],
        "mihomo": revisions["mihomo"],
        "ui": revisions["clash_verge_rev"],
    }
    if values != expected:
        raise AuditFailure(f"COMPONENTS mismatch: expected {expected}, found {values}")
    return values


def write_release_metadata(
    repo: Path,
    package_dir: Path,
    sbom: dict[str, Any],
) -> None:
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(repo / name, package_dir / name)
    atomic_json(package_dir / "SBOM.cdx.json", sbom)
    lines = [
        f"{sha256(package_dir / name)}  {name}" for name in RELEASE_METADATA_FILES
    ]
    (package_dir / "METADATA.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_release_metadata(package_dir: Path, expected_sbom: dict[str, Any]) -> None:
    required = (
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
        "SBOM.cdx.json",
        "METADATA.sha256",
    )
    for name in required:
        if not (package_dir / name).is_file():
            raise AuditFailure(f"release metadata is missing: {name}")
    actual_sbom = json.loads((package_dir / "SBOM.cdx.json").read_text(encoding="utf-8"))
    if actual_sbom != expected_sbom:
        raise AuditFailure("SBOM.cdx.json is stale or does not match dependency locks")
    if len(actual_sbom.get("components", [])) < 100:
        raise AuditFailure("SBOM dependency inventory is unexpectedly small")
    checksums = parse_checksums(package_dir / "METADATA.sha256")
    if set(checksums) != set(RELEASE_METADATA_FILES):
        raise AuditFailure(
            "METADATA.sha256 must cover every required release metadata file"
        )
    for name, expected in checksums.items():
        path = package_dir / name
        if not path.is_file() or sha256(path) != expected:
            raise AuditFailure(f"release metadata checksum failed: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--package-dir", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    repo = args.repo.resolve()
    package_dir = (
        args.package_dir
        or repo / "dist" / "packages" / TARGET
    ).resolve()
    if not package_dir.is_dir():
        parser.error(f"package directory does not exist: {package_dir}")

    lock = load_lock(repo)
    revisions = verify_source(repo, lock)
    artifacts, _ = audit_packages(package_dir)
    manifest = verify_component_manifest(package_dir, revisions)
    sbom = generate_sbom(repo, lock, revisions)
    if args.write:
        write_release_metadata(repo, package_dir, sbom)
    verify_release_metadata(package_dir, sbom)

    report = {
        "schema_version": 1,
        "status": "pass",
        "target": TARGET,
        "source": manifest,
        "checks": {
            "licenses": "pass",
            "component_lock": "pass",
            "artifact_checksums": "pass",
            "package_permissions": "pass",
            "secret_scan": "pass",
            "sbom": "pass",
        },
        "artifacts": artifacts,
        "sbom_components": len(sbom["components"]),
    }
    atomic_json(package_dir / "RELEASE-AUDIT.json", report)
    print(
        f"TrafficTracer Complete release audit passed: "
        f"{len(artifacts)} packages, {len(sbom['components'])} SBOM components"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditFailure, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"release audit failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

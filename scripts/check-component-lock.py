#!/usr/bin/env python3
"""Verify Complete source pins and packaged binary protocol handshakes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from traffictracer import version  # noqa: E402


LOCK_PATH = ROOT / "complete" / "components.lock.yaml"
TARGET = "x86_64-unknown-linux-gnu"


def _run(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return completed


def _git(*args: str, cwd: Path = ROOT) -> str:
    return _run(["git", "-C", str(cwd), *args]).stdout.strip()


def _load_lock() -> dict:
    return yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))


def _check_service_contract(lock: dict) -> None:
    ui_root = ROOT / lock["components"]["clash_verge_rev"]["path"]
    service = lock["components"]["clash_verge_service"]
    bundle_lock_path = ROOT / service["bundle_lock"]
    bundle = json.loads(bundle_lock_path.read_text(encoding="utf-8"))
    expected_bundle = {
        "source": service["repository"],
        "tag": service["tag"],
        "commit": service["commit"],
        "protocol": {
            "epoch": service["protocol"]["epoch"],
            "revision": service["protocol"]["revision"],
            "minSupportedClientRevision": service["protocol"]["min_supported_client_revision"],
            "minRequiredServiceRevision": service["protocol"]["min_required_service_revision"],
        },
        "ipcPaths": service["ipc_paths"],
    }
    for key, expected in expected_bundle.items():
        if bundle.get(key) != expected:
            raise RuntimeError(f"service bundle lock {key} does not match component lock")

    target_asset = bundle.get("assets", {}).get(TARGET)
    expected_asset = service["linux_x86_64"]
    if target_asset != {
        "file": expected_asset["asset"],
        "sha256": expected_asset["sha256"],
    }:
        raise RuntimeError("Linux x86-64 service asset does not match component lock")

    cargo_lock = tomllib.loads((ui_root / "Cargo.lock").read_text(encoding="utf-8"))
    packages = [
        package
        for package in cargo_lock.get("package", [])
        if package.get("name") == "clash_verge_service_ipc"
    ]
    expected_source = f"?rev={service['commit']}#{service['commit']}"
    if len(packages) != 1:
        raise RuntimeError("Cargo.lock must contain exactly one clash_verge_service_ipc package")
    package = packages[0]
    if package.get("version") != service["client_version"] or expected_source not in package.get("source", ""):
        raise RuntimeError("Cargo.lock service IPC client does not match component lock")


def check_sources(lock: dict) -> None:
    tree = {
        line.split()[3]: line.split()[2]
        for line in _git(
            "ls-tree", "HEAD", "components/mihomo", "components/clash-verge-rev"
        ).splitlines()
    }
    for name in ("mihomo", "clash_verge_rev"):
        component = lock["components"][name]
        path = ROOT / component["path"]
        expected = component["commit"]
        if _git("rev-parse", "HEAD", cwd=path) != expected:
            raise RuntimeError(f"{name} checkout does not match component lock")
        if tree.get(component["path"]) != expected:
            raise RuntimeError(f"{name} gitlink does not match component lock")

    expected_protocols = {
        "worker_api": version.WORKER_API_VERSION,
        "job_schema": version.JOB_SCHEMA_VERSION,
        "session_manifest": version.SESSION_SCHEMA_VERSION,
        "flow_result": version.FLOW_SCHEMA_VERSION,
        "mihomo_tracing_api": version.MIHOMO_TRACING_API_VERSION,
        "mihomo_event_schema": version.MIHOMO_EVENT_SCHEMA_VERSION,
    }
    if lock["product"]["version"] != version.COMPLETE_VERSION:
        raise RuntimeError("Complete product version does not match component lock")
    if lock["protocols"] != expected_protocols:
        raise RuntimeError("protocol versions do not match component lock")
    _check_service_contract(lock)


def check_worker(path: Path, lock: dict) -> None:
    requests = "\n".join(
        (
            json.dumps(
                {
                    "api_version": lock["protocols"]["worker_api"],
                    "type": "request",
                    "id": "hello",
                    "method": "hello",
                    "params": {},
                }
            ),
            json.dumps(
                {
                    "api_version": lock["protocols"]["worker_api"],
                    "type": "request",
                    "id": "shutdown",
                    "method": "worker.shutdown",
                    "params": {},
                }
            ),
        )
    ) + "\n"
    with tempfile.TemporaryDirectory(prefix="tt-component-lock-") as root:
        completed = _run(
            [str(path), "--output-root", str(Path(root) / "sessions")],
            input_text=requests,
        )
    messages = [json.loads(line) for line in completed.stdout.splitlines()]
    response = next(
        (
            item["result"]
            for item in messages
            if item.get("type") == "response" and item.get("id") == "hello"
        ),
        None,
    )
    expected = {
        "version": lock["product"]["version"],
        "api_version": lock["protocols"]["worker_api"],
        "job_schema_version": lock["protocols"]["job_schema"],
        "session_schema_version": lock["protocols"]["session_manifest"],
        "flow_schema_version": lock["protocols"]["flow_result"],
    }
    if response is None or any(response.get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"Worker hello does not match component lock: {response}")


def check_core(path: Path, smoke_script: Path, lock: dict) -> None:
    expected_commit = lock["components"]["mihomo"]["commit"]
    core_version = _run([str(path), "-v"])
    version_text = core_version.stdout + core_version.stderr
    if expected_commit[:12] not in version_text:
        raise RuntimeError("Mihomo binary version does not match component lock")

    smoke = _run([str(smoke_script), str(path)])
    prefix = "Capabilities: "
    payload_line = next(
        (line[len(prefix):] for line in smoke.stdout.splitlines() if line.startswith(prefix)),
        None,
    )
    if payload_line is None:
        raise RuntimeError("Mihomo smoke did not report capabilities")
    payload = json.loads(payload_line)
    if payload.get("api_version") != lock["protocols"]["mihomo_tracing_api"]:
        raise RuntimeError("Mihomo tracing API does not match component lock")
    if payload.get("event_schema_version") != lock["protocols"]["mihomo_event_schema"]:
        raise RuntimeError("Mihomo event schema does not match component lock")
    if not payload.get("supports_normalized_flow"):
        raise RuntimeError("Mihomo binary lacks normalized Flow capability")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--core",
        type=Path,
        default=ROOT / "dist" / "core" / f"verge-mihomo-tt-{TARGET}",
    )
    parser.add_argument(
        "--worker",
        type=Path,
        default=ROOT / "dist" / "worker" / f"traffictracer-worker-{TARGET}",
    )
    parser.add_argument(
        "--core-smoke",
        type=Path,
        default=ROOT / "components" / "mihomo" / "scripts" / "smoke-complete-core.sh",
    )
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()

    lock = _load_lock()
    check_sources(lock)
    if not args.source_only:
        for label, path in (("core", args.core), ("worker", args.worker)):
            if not path.is_file() or not path.stat().st_mode & 0o111:
                raise RuntimeError(f"{label} binary is missing or not executable: {path}")
        check_core(args.core.resolve(), args.core_smoke.resolve(), lock)
        check_worker(args.worker.resolve(), lock)
    print("TrafficTracer Complete component lock verified.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", flush=True)
        raise SystemExit(1) from exc

#!/usr/bin/env python3
"""Smoke installed Complete Linux roots extracted from Deb/AppImage packages."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


REQUIRED = (
    "clash-verge",
    "clash-verge-service",
    "clash-verge-service-install",
    "clash-verge-service-uninstall",
    "verge-mihomo",
    "verge-mihomo-alpha",
    "verge-mihomo-tt",
    "traffictracer-worker",
)


class SmokeFailure(RuntimeError):
    pass


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=kwargs.pop("timeout", 30),
        check=False,
        **kwargs,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SmokeFailure(f"{' '.join(command)} failed: {detail}")
    return completed


def verify_checksum(artifact: Path) -> None:
    checksum_file = artifact.parent / "SHA256SUMS"
    if not checksum_file.is_file():
        return
    expected = None
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        fields = line.split(maxsplit=1)
        filename = (
            fields[1].removeprefix("*").removeprefix("./")
            if len(fields) == 2
            else ""
        )
        if filename == artifact.name:
            expected = fields[0]
            break
    if expected is None:
        raise SmokeFailure(f"SHA256SUMS has no entry for {artifact.name}")
    hasher = hashlib.sha256()
    with artifact.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    if digest != expected:
        raise SmokeFailure(f"checksum mismatch for {artifact.name}")


def extract(artifact: Path, destination: Path) -> Path:
    destination.mkdir(parents=True)
    if artifact.suffix == ".deb":
        run(["dpkg-deb", "-x", str(artifact), str(destination)], timeout=60)
        return destination
    if artifact.name.endswith(".AppImage"):
        run([str(artifact), "--appimage-extract"], cwd=destination, timeout=90)
        return destination / "squashfs-root"
    raise SmokeFailure(f"unsupported package: {artifact}")


def assert_executables(root: Path) -> dict[str, Path]:
    binaries = {name: root / "usr" / "bin" / name for name in REQUIRED}
    for name, path in binaries.items():
        if not path.is_file() or path.stat().st_size == 0:
            raise SmokeFailure(f"installed executable is missing: {path}")
        if not os.access(path, os.X_OK):
            raise SmokeFailure(f"installed executable is not executable: {path}")
    desktop = root / "usr" / "share" / "applications" / "Clash Verge.desktop"
    if not desktop.is_file() or "Exec=clash-verge" not in desktop.read_text(encoding="utf-8"):
        raise SmokeFailure("installed desktop entry does not discover clash-verge")
    return binaries


def smoke_worker(worker: Path, root: Path) -> None:
    sessions = root / "worker-sessions"
    requests = "\n".join((
        request("hello", "hello", {}),
        request("diagnose", "environment.diagnose", {
            "tun_interface": "package-smoke-missing-tun",
            "physical_interface": "package-smoke-missing-physical",
            "chrome_binary": str(worker),
            "output_root": str(sessions),
            "min_free_bytes": 0,
        }),
        request("shutdown", "worker.shutdown", {}),
    )) + "\n"
    completed = run(
        [str(worker), "--output-root", str(sessions)],
        input=requests,
        cwd=root,
        timeout=30,
    )
    messages = [json.loads(line) for line in completed.stdout.splitlines()]
    responses = {
        item.get("id"): item for item in messages if item.get("type") == "response"
    }
    ready = next((item for item in messages if item.get("method") == "worker.ready"), None)
    hello = responses.get("hello", {}).get("result", {})
    checks = responses.get("diagnose", {}).get("result", {}).get("checks")
    if ready is None or hello.get("api_version") != 2:
        raise SmokeFailure("packaged Worker hello/ready handshake failed")
    if not isinstance(checks, list) or len(checks) != 7:
        raise SmokeFailure("packaged Worker environment diagnose failed")
    if responses.get("shutdown", {}).get("result", {}).get("shutdown") is not True:
        raise SmokeFailure("packaged Worker shutdown failed")


def request(request_id: str, method: str, params: dict[str, Any]) -> str:
    return json.dumps({
        "api_version": 2,
        "type": "request",
        "id": request_id,
        "method": method,
        "params": params,
    }, separators=(",", ":"))


def smoke_core(core: Path, root: Path) -> None:
    version = run([str(core), "-v"]).stdout
    if "traffictracer-complete-" not in version:
        raise SmokeFailure(f"packaged core is not TrafficTracer Complete: {version}")
    home = root / "core-home"
    home.mkdir()
    controller = home / "controller.sock"
    config = home / "config.yaml"
    config.write_text("\n".join((
        "mixed-port: 0",
        "allow-lan: false",
        "mode: direct",
        "log-level: warning",
        f"external-controller-unix: {controller}",
        "proxies: []",
        "proxy-groups: []",
        "rules: []",
        "",
    )), encoding="utf-8")
    run([str(core), "-t", "-d", str(home), "-f", str(config)])
    process = subprocess.Popen(
        [str(core), "-d", str(home), "-f", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15
        payload = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise SmokeFailure(f"packaged core exited: {process.stderr.read().strip()}")
            try:
                payload = unix_json(controller, "/experimental/tracing/capabilities")
                break
            except OSError:
                time.sleep(0.1)
        expected = {
            "api_version": 1,
            "event_schema_version": 1,
            "supports_normalized_flow": True,
        }
        if payload is None or any(payload.get(key) != value for key, value in expected.items()):
            raise SmokeFailure(f"packaged core capabilities mismatch: {payload}")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def unix_json(socket_path: Path, path: str) -> dict[str, Any]:
    connection = UnixHTTPConnection(socket_path, timeout=1)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
    finally:
        connection.close()
    if response.status != 200:
        raise SmokeFailure(f"packaged core HTTP failure: {response.status}")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise SmokeFailure("packaged core returned a non-object capability payload")
    return payload


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.socket_path))


def launch_ui(binary: Path, root: Path) -> None:
    xvfb = shutil.which("xvfb-run")
    if not xvfb:
        raise SmokeFailure("--launch-ui requires xvfb-run")
    home = root / "ui-home"
    home.mkdir()
    environment = {
        **os.environ,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_DATA_HOME": str(home / "data"),
    }
    command = [xvfb, "-a", str(binary)]
    dbus = shutil.which("dbus-run-session")
    if dbus:
        command = [dbus, "--", *command]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        start_new_session=True,
    )
    try:
        time.sleep(8)
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise SmokeFailure(f"packaged UI exited during startup: {stderr or stdout}")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def smoke_artifact(artifact: Path, launch: bool) -> None:
    verify_checksum(artifact)
    with tempfile.TemporaryDirectory(prefix="traffictracer-package-smoke-") as raw:
        temporary = Path(raw)
        installed = extract(artifact, temporary / "installed")
        binaries = assert_executables(installed)
        runtime = temporary / "runtime"
        runtime.mkdir()
        smoke_worker(binaries["traffictracer-worker"], runtime)
        smoke_core(binaries["verge-mihomo-tt"], runtime)
        if launch:
            launch_ui(binaries["clash-verge"], runtime)
    print(f"Package smoke passed: {artifact.name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launch-ui", action="store_true")
    parser.add_argument("artifacts", nargs="+")
    args = parser.parse_args()
    for value in args.artifacts:
        artifact = Path(value).expanduser().resolve()
        if not artifact.is_file():
            parser.error(f"package does not exist: {artifact}")
        smoke_artifact(artifact, args.launch_ui)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, SmokeFailure, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

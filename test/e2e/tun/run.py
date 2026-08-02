#!/usr/bin/env python3
"""Privileged Complete E2E using an isolated target namespace and real TUN."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Iterator
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[3]
E2E_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(E2E_ROOT))

from direct.run import (  # noqa: E402
    E2EFailure,
    WorkerClient,
    assert_real_flow,
    load_trace,
    terminate,
    wait_core,
    write_analysis_inputs,
)
from traffictracer.capture.mihomo import MihomoManager  # noqa: E402
from traffictracer.version import JOB_SCHEMA_VERSION  # noqa: E402


TARGET_PORT = 18080
PCAP_HEADER_BYTES = 24


def privileged(*command: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sudo", "-n", *command],
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=15,
    )


class NetworkSandbox:
    def __init__(self, root: Path) -> None:
        suffix = f"{os.getpid() & 0xFFFFF:05x}"
        self.namespace = f"tt-e2e-{suffix}"
        self.physical = f"ttph{suffix}"
        self.peer = f"ttns{suffix}"
        self.tun = f"ttun{suffix}"
        subnet = 20 + (os.getpid() % 200)
        self.host_ip = f"198.18.{subnet}.1"
        self.target_ip = f"198.18.{subnet}.2"
        self.fixture_dir = root / "target"
        self.server: subprocess.Popen[str] | None = None
        self._created = False

    def start(self) -> str:
        self.fixture_dir.mkdir()
        (self.fixture_dir / "fixture").write_text(
            "traffictracer-complete-tun-e2e\n", encoding="utf-8"
        )
        privileged("ip", "netns", "add", self.namespace)
        self._created = True
        privileged(
            "ip", "link", "add", self.physical, "type", "veth", "peer", "name", self.peer
        )
        privileged("ip", "link", "set", self.peer, "netns", self.namespace)
        privileged("ip", "addr", "add", f"{self.host_ip}/30", "dev", self.physical)
        privileged("ip", "link", "set", self.physical, "up")
        privileged(
            "ip", "netns", "exec", self.namespace,
            "ip", "addr", "add", f"{self.target_ip}/30", "dev", self.peer,
        )
        privileged(
            "ip", "netns", "exec", self.namespace,
            "ip", "link", "set", self.peer, "up",
        )
        privileged(
            "ip", "netns", "exec", self.namespace,
            "ip", "link", "set", "lo", "up",
        )
        self.server = subprocess.Popen(
            [
                "sudo", "-n", "ip", "netns", "exec", self.namespace,
                "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}",
                "--clear-groups", sys.executable, "-m", "http.server",
                str(TARGET_PORT), "--bind", self.target_ip,
                "--directory", str(self.fixture_dir),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._wait_server()
        return f"http://{self.target_ip}:{TARGET_PORT}/fixture"

    def route_via_tun(self) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if Path(f"/sys/class/net/{self.tun}").exists():
                privileged(
                    "ip", "route", "replace", f"{self.target_ip}/32", "dev", self.tun
                )
                return
            time.sleep(0.1)
        raise E2EFailure(f"Mihomo TUN interface was not created: {self.tun}")

    def close(self) -> None:
        if self._created:
            try:
                pids = privileged(
                    "ip", "netns", "pids", self.namespace, capture=True
                ).stdout.split()
                if pids:
                    privileged("kill", "-TERM", *pids)
            except subprocess.CalledProcessError:
                pass
        terminate(self.server)
        if self._created:
            try:
                privileged("ip", "link", "delete", self.physical)
            except subprocess.CalledProcessError:
                pass
            try:
                privileged("ip", "netns", "delete", self.namespace)
            except subprocess.CalledProcessError:
                pass
            self._created = False

    def _wait_server(self) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert self.server is not None
            if self.server.poll() is not None:
                stderr = self.server.stderr.read().strip() if self.server.stderr else ""
                raise E2EFailure(f"namespace HTTP fixture exited: {stderr}")
            probe = subprocess.run(
                [
                    "sudo", "-n", "ip", "netns", "exec", self.namespace,
                    "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}",
                    "--clear-groups", sys.executable, "-c",
                    (
                        "import socket; "
                        f"s=socket.create_connection(('{self.target_ip}',{TARGET_PORT}),1); "
                        "s.close()"
                    ),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if probe.returncode == 0:
                return
            time.sleep(0.1)
        raise E2EFailure("namespace HTTP fixture was not ready")


@contextmanager
def core_capability(core: Path) -> Iterator[None]:
    existing = subprocess.run(
        ["getcap", str(core)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()
    original = existing.split(maxsplit=1)[1] if existing else ""
    privileged("setcap", "cap_net_admin,cap_net_raw+ep", str(core))
    try:
        yield
    finally:
        if original:
            privileged("setcap", original, str(core))
        else:
            subprocess.run(
                ["sudo", "-n", "setcap", "-r", str(core)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


def write_core_config(
    path: Path, socket_path: Path, sandbox: NetworkSandbox
) -> None:
    path.write_text(
        "\n".join(
            (
                "mixed-port: 0",
                "allow-lan: false",
                "mode: direct",
                "log-level: warning",
                "ipv6: false",
                f"interface-name: {sandbox.physical}",
                f"external-controller-unix: {socket_path}",
                "tun:",
                "  enable: true",
                f"  device: {sandbox.tun}",
                "  stack: system",
                "  auto-route: false",
                "  auto-detect-interface: false",
                "  dns-hijack: []",
                "proxies: []",
                "proxy-groups: []",
                "rules: []",
                "",
            )
        ),
        encoding="utf-8",
    )


def write_fake_chrome(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import http.client
import sys
import time
from urllib.parse import urlsplit

target = next(arg for arg in reversed(sys.argv[1:]) if arg.startswith("http"))
parsed = urlsplit(target)
connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
connection.request("GET", parsed.path, headers={"Connection": "close"})
response = connection.getresponse()
body = response.read()
connection.close()
if response.status != 200 or b"traffictracer-complete-tun-e2e" not in body:
    raise SystemExit(f"unexpected fixture response: {response.status}")
time.sleep(10)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def assert_pcap(path: Path, target_ip: str) -> None:
    if not path.is_file() or path.stat().st_size <= PCAP_HEADER_BYTES:
        raise E2EFailure(f"packet capture is empty: {path}")
    completed = subprocess.run(
        [
            "tshark", "-r", str(path), "-Y", f"ip.addr == {target_ip}",
            "-T", "fields", "-e", "frame.number",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )
    if not completed.stdout.strip():
        raise E2EFailure(f"pcap has no fixture traffic for {target_ip}: {path}")


def run(core_path: Path, worker_path: Path) -> None:
    if os.geteuid() == 0:
        raise E2EFailure("Worker integration test must run as an unprivileged user")
    with tempfile.TemporaryDirectory(prefix="traffictracer-tun-e2e-") as raw_root:
        root = Path(raw_root)
        sessions = root / "sessions"
        core_home = root / "core"
        core_home.mkdir()
        socket_path = root / "controller.sock"
        config_path = core_home / "config.yaml"
        fake_chrome = root / "fake-chrome"
        write_fake_chrome(fake_chrome)
        sandbox = NetworkSandbox(root)
        core_process: subprocess.Popen[str] | None = None
        worker_process: subprocess.Popen[str] | None = None
        try:
            target_url = sandbox.start()
            write_core_config(config_path, socket_path, sandbox)
            endpoint = f"unix://{socket_path}"
            manager = MihomoManager("", "", endpoint)
            with core_capability(core_path):
                core_process = subprocess.Popen(
                    [str(core_path), "-d", str(core_home), "-f", str(config_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                wait_core(manager, core_process)
                sandbox.route_via_tun()

                baseline = {
                    "enabled": True,
                    "output": str(root / "baseline.jsonl"),
                    "session_id": "tun-e2e-baseline",
                }
                manager.patch_tracing(baseline)
                worker_process = subprocess.Popen(
                    [
                        str(worker_path), "--output-root", str(sessions),
                        "--controller-endpoint", endpoint,
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                worker = WorkerClient(worker_process)
                ready = worker.wait_ready()
                if ready["params"]["recovery"]["status"] != "ok":
                    raise E2EFailure(f"unexpected recovery failure: {ready}")

                capture_id = str(uuid4())
                domain = sandbox.target_ip
                worker.request(
                    "job.start",
                    {
                        "job": {
                            "schema_version": JOB_SCHEMA_VERSION,
                            "kind": "capture",
                            "job_id": capture_id,
                            "url": target_url,
                            "domain": domain,
                            "duration_seconds": 2,
                            "network": "tcp",
                            "interfaces": {
                                "tun": sandbox.tun,
                                "physical": sandbox.physical,
                            },
                            "output_root": str(sessions),
                            "chrome_binary": str(fake_chrome),
                            "controller": {"endpoint": endpoint},
                            "options": {
                                "capture_packets": True,
                                "collect_cdp": False,
                                "collect_netlog": False,
                                "analyze_after_capture": False,
                                "headless": False,
                            },
                        }
                    },
                )
                capture = worker.wait_job(capture_id, timeout=45)
                session_id = capture["result"]["session_id"]
                manifest = worker.request("session.get", {"session_id": session_id})
                session_dir = Path(manifest["session_dir"])
                run_dir = next((session_dir / "captures" / domain).iterdir())
                assert_pcap(run_dir / "tun.pcap", sandbox.target_ip)
                assert_pcap(run_dir / "phys.pcap", sandbox.target_ip)

                trace_path = next((session_dir / "logs").glob("mihomo_trace_*.jsonl"))
                pre_flow, post_flow = assert_real_flow(load_trace(trace_path))
                if pre_flow["dst_ip"] != sandbox.target_ip:
                    raise E2EFailure(f"unexpected pre-proxy target: {pre_flow}")
                if post_flow["dst_ip"] != sandbox.target_ip:
                    raise E2EFailure(f"unexpected post-proxy target: {post_flow}")
                restored = manager.get_tracing_status()
                if any(restored.get(key) != value for key, value in baseline.items()):
                    raise E2EFailure(f"tracing state was not restored: {restored}")

                write_analysis_inputs(
                    session_dir, domain, run_dir.name, target_url, pre_flow
                )
                analysis_id = str(uuid4())
                worker.request(
                    "analysis.start",
                    {
                        "job": {
                            "schema_version": JOB_SCHEMA_VERSION,
                            "kind": "analysis",
                            "job_id": analysis_id,
                            "session_dir": str(session_dir),
                            "output_root": str(sessions),
                            "options": {
                                "split_pcaps": False,
                                "write_flow_index": True,
                                "overwrite": True,
                            },
                        }
                    },
                )
                worker.wait_job(analysis_id, timeout=45)
                correlation = json.loads(
                    (session_dir / "results" / "correlation.json").read_text(
                        encoding="utf-8"
                    )
                )
                if not correlation.get(domain, {}).get("flows"):
                    raise E2EFailure(f"analysis produced no correlation: {correlation}")
                analyzed_manifest = worker.request(
                    "session.get", {"session_id": session_id}
                )
                artifact_paths = {
                    artifact["path"] for artifact in analyzed_manifest["artifacts"]
                }
                required_analysis = {
                    "results/correlation.json",
                    "results/flow-index.json",
                    "results/summary.json",
                }
                if not required_analysis <= artifact_paths:
                    raise E2EFailure(
                        "analysis artifacts are missing from manifest: "
                        f"{sorted(required_analysis - artifact_paths)}"
                    )
                for capture_name in ("tun.pcap", "phys.pcap"):
                    if not any(path.endswith(f"/{capture_name}") for path in artifact_paths):
                        raise E2EFailure(
                            f"capture artifact is missing from manifest: {capture_name}"
                        )
                query = worker.request(
                    "flow.query",
                    {
                        "session_id": session_id,
                        **{
                            key: pre_flow[key]
                            for key in (
                                "network", "src_ip", "src_port", "dst_ip", "dst_port"
                            )
                        },
                    },
                )
                exact = [
                    item for item in query["items"]
                    if item["match"]["status"] == "matched"
                    and item.get("post_flow") is not None
                ]
                if len(exact) != 1:
                    raise E2EFailure(f"no exact Flow with complete post_flow: {query}")

                print(
                    "TUN E2E passed: "
                    f"session={session_id} pre={pre_flow['key']} post={post_flow['key']}"
                )
                worker.request("worker.shutdown", {})
                worker_process.wait(timeout=10)
                worker_process = None
                terminate(core_process)
                core_process = None
        except Exception as exc:
            diagnostics: list[str] = []
            if worker_process is not None and worker_process.stderr is not None:
                terminate(worker_process)
                stderr = worker_process.stderr.read().strip()
                if stderr:
                    diagnostics.append(f"Worker stderr:\n{stderr}")
            if core_process is not None and core_process.stderr is not None:
                terminate(core_process)
                stderr = core_process.stderr.read().strip()
                if stderr:
                    diagnostics.append(f"Core stderr:\n{stderr}")
            if diagnostics:
                raise E2EFailure(f"{exc}\n" + "\n".join(diagnostics)) from exc
            raise
        finally:
            terminate(worker_process)
            terminate(core_process)
            sandbox.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    args = parser.parse_args()
    for name, path in (("core", args.core), ("worker", args.worker)):
        resolved = path.resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            parser.error(f"{name} is not executable: {resolved}")
        setattr(args, name, resolved)
    for tool in ("sudo", "ip", "setpriv", "setcap", "getcap", "tshark", "dumpcap"):
        if shutil.which(tool) is None:
            parser.error(f"missing prerequisite: {tool}")
    run(args.core, args.worker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

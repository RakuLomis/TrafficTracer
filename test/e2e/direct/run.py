#!/usr/bin/env python3
"""Unprivileged Complete E2E: local HTTP -> DIRECT core -> Worker analysis."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
from threading import Thread
import time
from typing import Any, Iterator
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from traffictracer.capture.mihomo import MihomoManager  # noqa: E402
from traffictracer.version import JOB_SCHEMA_VERSION, WORKER_API_VERSION  # noqa: E402


class E2EFailure(RuntimeError):
    pass


class _FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        payload = b"traffictracer-complete-direct-e2e\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


class WorkerClient:
    def __init__(self, process: subprocess.Popen[str]) -> None:
        self.process = process
        self.messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self._deferred: list[dict[str, Any]] = []
        self._request_id = 0
        self._reader = Thread(target=self._read_stdout, daemon=True)
        self._reader.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for raw in self.process.stdout:
            try:
                message = json.loads(raw)
            except json.JSONDecodeError as exc:
                self.messages.put({"reader_error": f"invalid Worker JSONL: {exc}"})
                return
            self.messages.put(message)

    def wait_ready(self, timeout: float = 15) -> dict[str, Any]:
        return self._wait_for(
            lambda item: item.get("type") == "notification"
            and item.get("method") == "worker.ready",
            timeout,
        )

    def request(
        self, method: str, params: dict[str, Any], timeout: float = 15
    ) -> dict[str, Any]:
        self._request_id += 1
        request_id = f"e2e-{self._request_id}"
        frame = {
            "api_version": WORKER_API_VERSION,
            "type": "request",
            "id": request_id,
            "method": method,
            "params": params,
        }
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(frame, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        response = self._wait_for(
            lambda item: item.get("type") == "response"
            and item.get("id") == request_id,
            timeout,
        )
        if "error" in response:
            raise E2EFailure(f"Worker {method} failed: {response['error']}")
        return response["result"]

    def wait_job(self, job_id: str, timeout: float = 30) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.request("job.status", {"job_id": job_id})
            if status["state"] in {"completed", "failed", "cancelled", "interrupted"}:
                if status["state"] != "completed":
                    raise E2EFailure(f"job {job_id} failed: {status}")
                return status
            time.sleep(0.1)
        raise E2EFailure(f"job {job_id} did not finish within {timeout}s")

    def _wait_for(self, predicate, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        for index, item in enumerate(self._deferred):
            if predicate(item):
                return self._deferred.pop(index)
        while time.monotonic() < deadline:
            if self.process.poll() is not None and self.messages.empty():
                raise E2EFailure(f"Worker exited with code {self.process.returncode}")
            try:
                item = self.messages.get(timeout=min(0.25, deadline - time.monotonic()))
            except queue.Empty:
                continue
            if "reader_error" in item:
                raise E2EFailure(item["reader_error"])
            if predicate(item):
                return item
            self._deferred.append(item)
        raise E2EFailure("timed out waiting for Worker JSONL response")


@contextmanager
def fixture_server() -> Iterator[tuple[ThreadingHTTPServer, str]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield server, f"http://{host}:{port}/fixture"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def write_core_config(path: Path, mixed_port: int, socket_path: Path) -> None:
    path.write_text(
        "\n".join(
            (
                f"mixed-port: {mixed_port}",
                "allow-lan: false",
                "mode: direct",
                "log-level: warning",
                "ipv6: false",
                f"external-controller-unix: {socket_path}",
                "external-controller-cors:",
                "  allow-private-network: true",
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
import os
import sys
import time
from urllib.parse import urlsplit

target = next(arg for arg in reversed(sys.argv[1:]) if arg.startswith("http"))
proxy = urlsplit(os.environ["TT_E2E_PROXY"])
connection = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=10)
connection.request("GET", target, headers={"Connection": "close"})
response = connection.getresponse()
body = response.read()
connection.close()
if response.status != 200 or b"traffictracer-complete-direct-e2e" not in body:
    raise SystemExit(f"unexpected fixture response: {response.status}")
time.sleep(10)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def wait_core(manager: MihomoManager, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 20
    socket_path = Path(manager.api_url.removeprefix("unix://"))
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise E2EFailure(
                f"core exited with code {process.returncode}: {stderr or stdout}"
            )
        if not socket_path.exists():
            time.sleep(0.1)
            continue
        try:
            manager._api_request("GET", "/version", timeout=0.5)
            return
        except Exception:
            time.sleep(0.1)
    raise E2EFailure("core controller Unix Socket was not ready")


def terminate(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def load_trace(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def assert_real_flow(events: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    connects = {
        event.get("conn_id"): event
        for event in events
        if event.get("type") == "tcp_connect"
        and isinstance(event.get("pre_flow"), dict)
        and event["pre_flow"].get("complete") is True
    }
    for event in events:
        post = event.get("post_flow")
        if (
            event.get("type") == "tcp_proxy_dial"
            and event.get("conn_id") in connects
            and isinstance(post, dict)
            and post.get("complete") is True
        ):
            return connects[event["conn_id"]]["pre_flow"], post
    raise E2EFailure("real trace has no paired complete pre_flow/post_flow")


def write_analysis_inputs(
    session_dir: Path, domain: str, run_tag: str, target_url: str, pre_flow: dict[str, Any]
) -> None:
    logs = session_dir / "logs"
    (logs / f"cdp_{domain}_{run_tag}.json").write_text(
        json.dumps(
            {
                "visit_url": target_url,
                "requests": [
                    {
                        "request_id": "direct-e2e-request",
                        "target_id": "direct-e2e-target",
                        "frame_id": "direct-e2e-frame",
                        "url": target_url,
                        "resource_type": "Document",
                        "timestamp": 1.0,
                        "target_type": "page",
                        "remote_ip": pre_flow["dst_ip"],
                        "remote_port": pre_flow["dst_port"],
                        "connection_reused": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (logs / f"netlog_{domain}_{run_tag}.json").write_text(
        json.dumps({"constants": {}, "events": []}), encoding="utf-8"
    )


def run(core_path: Path, worker_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="traffictracer-direct-e2e-") as raw_root:
        root = Path(raw_root)
        sessions = root / "sessions"
        core_home = root / "core"
        core_home.mkdir()
        socket_path = root / "controller.sock"
        config_path = core_home / "config.yaml"
        fake_chrome = root / "fake-chrome"
        write_fake_chrome(fake_chrome)

        core_process: subprocess.Popen[str] | None = None
        worker_process: subprocess.Popen[str] | None = None
        worker: WorkerClient | None = None
        with fixture_server() as (_, target_url):
            target_port = int(target_url.rsplit(":", 1)[1].split("/", 1)[0])
            mixed_port = _unused_port()
            write_core_config(config_path, mixed_port, socket_path)
            endpoint = f"unix://{socket_path}"
            manager = MihomoManager("", "", endpoint)
            try:
                core_process = subprocess.Popen(
                    [str(core_path), "-d", str(core_home), "-f", str(config_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                wait_core(manager, core_process)

                baseline_output = root / "baseline.jsonl"
                baseline = {
                    "enabled": True,
                    "output": str(baseline_output),
                    "session_id": "direct-e2e-baseline",
                }
                manager.patch_tracing(baseline)

                environment = os.environ.copy()
                environment["TT_E2E_PROXY"] = f"http://127.0.0.1:{mixed_port}"
                worker_process = subprocess.Popen(
                    [
                        str(worker_path),
                        "--output-root",
                        str(sessions),
                        "--controller-endpoint",
                        endpoint,
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    env=environment,
                )
                worker = WorkerClient(worker_process)
                ready = worker.wait_ready()
                if ready["params"]["recovery"]["status"] != "ok":
                    raise E2EFailure(f"unexpected recovery failure: {ready}")

                capture_id = str(uuid4())
                domain = "127.0.0.1"
                worker.request(
                    "job.start",
                    {
                        "job": {
                            "schema_version": JOB_SCHEMA_VERSION,
                            "kind": "capture",
                            "job_id": capture_id,
                            "url": target_url,
                            "domain": domain,
                            "duration_seconds": 1,
                            "network": "tcp",
                            "interfaces": {"tun": "unused-tun", "physical": "unused-physical"},
                            "output_root": str(sessions),
                            "chrome_binary": str(fake_chrome),
                            "controller": {"endpoint": endpoint},
                            "options": {
                                "capture_packets": False,
                                "collect_cdp": False,
                                "collect_netlog": False,
                                "analyze_after_capture": False,
                                "headless": False,
                            },
                        }
                    },
                )
                capture = worker.wait_job(capture_id)
                session_id = capture["result"]["session_id"]
                manifest = worker.request("session.get", {"session_id": session_id})
                if manifest["state"] != "completed":
                    raise E2EFailure(f"capture manifest is not completed: {manifest}")
                session_dir = Path(manifest["session_dir"])
                trace_path = next((session_dir / "logs").glob("mihomo_trace_*.jsonl"))
                pre_flow, post_flow = assert_real_flow(load_trace(trace_path))
                if pre_flow["dst_port"] != target_port or post_flow["dst_port"] != target_port:
                    raise E2EFailure(
                        f"captured flow does not target fixture port {target_port}: "
                        f"{pre_flow} -> {post_flow}"
                    )

                restored = manager.get_tracing_status()
                for key, expected in baseline.items():
                    if restored.get(key) != expected:
                        raise E2EFailure(f"tracing state was not restored: {restored}")

                run_dir = next((session_dir / "captures" / domain).iterdir())
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
                worker.wait_job(analysis_id)

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
                required_artifacts = {
                    "results/correlation.json",
                    "results/flow-index.json",
                    "results/summary.json",
                }
                if not required_artifacts <= artifact_paths:
                    raise E2EFailure(
                        "analysis artifacts are missing from manifest: "
                        f"{sorted(required_artifacts - artifact_paths)}"
                    )
                query = worker.request(
                    "flow.query",
                    {
                        "session_id": session_id,
                        **{
                            key: pre_flow[key]
                            for key in (
                                "network",
                                "src_ip",
                                "src_port",
                                "dst_ip",
                                "dst_port",
                            )
                        },
                    },
                )
                if query["total"] != 1:
                    raise E2EFailure(f"pre-proxy five-tuple query was not exact: {query}")
                result = query["items"][0]
                indexed_post = result["post_flow"]
                comparable_fields = (
                    "network",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                )
                if indexed_post is None or any(
                    indexed_post[field] != post_flow[field]
                    for field in comparable_fields
                ):
                    raise E2EFailure(f"queried post-proxy tuple does not match trace: {result}")

                print(
                    "DIRECT E2E passed: "
                    f"session={session_id} pre={pre_flow['key']} post={post_flow['key']}"
                )
                worker.request("worker.shutdown", {})
                worker_process.wait(timeout=5)
            except Exception as exc:
                if worker_process is not None and worker_process.stderr is not None:
                    terminate(worker_process)
                    stderr = worker_process.stderr.read().strip()
                    if stderr:
                        raise E2EFailure(f"{exc}\nWorker stderr:\n{stderr}") from exc
                raise
            finally:
                terminate(worker_process)
                terminate(core_process)


def _unused_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    args = parser.parse_args()
    for name, path in (("core", args.core), ("worker", args.worker)):
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f"{name} is not executable: {path}")
    run(args.core.resolve(), args.worker.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

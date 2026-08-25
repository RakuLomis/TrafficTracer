#!/usr/bin/env python3
"""Complete cancellation and Worker crash-recovery fault injection."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[3]
E2E_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(E2E_ROOT)]

from direct.run import E2EFailure, WorkerClient, terminate, wait_core  # noqa: E402
from traffictracer.capture.mihomo import MihomoManager  # noqa: E402
from traffictracer.version import JOB_SCHEMA_VERSION  # noqa: E402


def wait_until(predicate: Callable[[], Any], label: str, timeout: float = 15) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.03)
    raise E2EFailure(f"timed out waiting for {label}")


def wait_terminal(client: WorkerClient, job_id: str, expected: str) -> dict[str, Any]:
    def terminal():
        status = client.request("job.status", {"job_id": job_id})
        return status if status["state"] in {"completed", "cancelled", "failed"} else None

    status = wait_until(terminal, f"job {job_id} terminal state", 30)
    if status["state"] != expected:
        raise E2EFailure(f"expected {expected}, got {status}")
    return status


def write_core_config(path: Path, socket_path: Path) -> None:
    path.write_text(
        "\n".join((
            "mixed-port: 0", "allow-lan: false", "mode: direct", "log-level: warning",
            "ipv6: false", f"external-controller-unix: {socket_path}",
            "proxies: []", "proxy-groups: []", "rules: []", "",
        )),
        encoding="utf-8",
    )


def write_fakes(bin_dir: Path) -> tuple[Path, Path]:
    chrome = bin_dir / "fake-chrome"
    chrome.write_text(
        """#!/usr/bin/env python3
import json, os, pathlib, signal, sys, time
pid_dir = pathlib.Path(os.environ["TT_FAULT_PID_DIR"])
(pid_dir / f"chrome-{os.getpid()}").write_text(str(os.getpid()))
url = next((arg for arg in reversed(sys.argv[1:]) if arg.startswith("http")), "")
if "analysis.test" in url:
    root = pathlib.Path(os.environ["TT_FAULT_SESSIONS"])
    deadline = time.time() + 5
    trace = None
    while time.time() < deadline:
        matches = list(root.rglob("raw/mihomo-trace.jsonl"))
        if matches:
            trace = matches[0]
            break
        time.sleep(.02)
    if trace is None:
        raise SystemExit("analysis trace was not created")
    event = {"schema_version":1,"ts":"2026-08-02T00:00:00Z","event_seq":1,
      "type":"tcp_connect","network":"tcp","conn_id":"fault-analysis",
      "src":"10.0.0.2:50000","dst":"203.0.113.10:443",
      "pre_flow":{"network":"tcp","src_ip":"10.0.0.2","src_port":50000,
      "dst_ip":"203.0.113.10","dst_port":443,
      "key":"tcp|10.0.0.2:50000|203.0.113.10:443","complete":True,
      "source":"inbound","scope":"pre_proxy","shared":False}}
    line = json.dumps(event, separators=(",", ":")) + "\n"
    with trace.open("a", encoding="utf-8") as stream:
        for _ in range(120000):
            stream.write(line)
    netlog = trace.with_name("netlog.json")
    netlog.write_text('{"constants":{},"events":[]}', encoding="utf-8")
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(1)
""",
        encoding="utf-8",
    )
    chrome.chmod(0o755)
    tshark = bin_dir / "tshark"
    tshark.write_text(
        """#!/usr/bin/env python3
import os, pathlib, signal, struct, sys, time
args = sys.argv[1:]
output = pathlib.Path(args[args.index("-w") + 1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1))
pid_dir = pathlib.Path(os.environ["TT_FAULT_PID_DIR"])
(pid_dir / f"tshark-{os.getpid()}").write_text(str(os.getpid()))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(1)
""",
        encoding="utf-8",
    )
    tshark.chmod(0o755)
    return chrome, tshark


def start_worker(worker: Path, sessions: Path, endpoint: str, env: dict[str, str]):
    process = subprocess.Popen(
        [str(worker), "--output-root", str(sessions), "--controller-endpoint", endpoint],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1, env=env,
    )
    client = WorkerClient(process)
    ready = client.wait_ready()
    return process, client, ready


def capture_payload(
    job_id: str, sessions: Path, chrome: Path, endpoint: str, domain: str,
    *, packets: bool = False, analyze: bool = False, duration: int = 60,
) -> dict[str, Any]:
    return {
        "schema_version": JOB_SCHEMA_VERSION, "kind": "capture", "job_id": job_id,
        "url": f"http://{domain}/", "domain": domain, "duration_seconds": duration,
        "network": "tcp", "interfaces": {"tun": "fault-tun", "physical": "fault-phys"},
        "output_root": str(sessions), "chrome_binary": str(chrome),
        "controller": {"endpoint": endpoint},
        "options": {"capture_packets": packets, "collect_cdp": False,
                    "collect_netlog": False, "analyze_after_capture": analyze,
                    "headless": False},
    }


def session_for_job(client: WorkerClient, job_id: str) -> dict[str, Any] | None:
    sessions = client.request("session.list", {})["sessions"]
    return next((item for item in sessions if item["job_id"] == job_id), None)


def journal_with_roles(sessions: Path, roles: set[str]):
    for path in sessions.rglob("recovery.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        actual = {item["role"] for item in data["processes"]}
        if roles <= actual:
            return path, data
    return None


def read_pids(pid_dir: Path, prefix: str) -> set[int]:
    return {int(path.read_text()) for path in pid_dir.glob(f"{prefix}-*")}


def assert_gone(pids: set[int]) -> None:
    def active(pid: int) -> bool:
        try:
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        closing = raw.rfind(")")
        return closing < 0 or raw[closing + 2 :].split()[0] != "Z"

    def gone():
        return all(not active(pid) for pid in pids)
    wait_until(gone, f"managed PIDs to exit: {sorted(pids)}", 10)


def assert_restored(manager: MihomoManager, baseline: dict[str, Any]) -> None:
    state = manager.get_tracing_status()
    if any(state.get(key) != value for key, value in baseline.items()):
        raise E2EFailure(f"tracing was not restored: {state}")


def cancel_scenario(
    client: WorkerClient, sessions: Path, chrome: Path, endpoint: str,
    pid_dir: Path, manager: MihomoManager, baseline: dict[str, Any],
    *, domain: str, packets: bool, roles: set[str],
) -> None:
    before = read_pids(pid_dir, "tshark") | read_pids(pid_dir, "chrome")
    job_id = str(uuid4())
    client.request("job.start", {"job": capture_payload(
        job_id, sessions, chrome, endpoint, domain, packets=packets
    )})
    wait_until(lambda: journal_with_roles(sessions, roles), f"{roles} journal")
    client.request("job.cancel", {"job_id": job_id, "reason": f"cancel {domain}"})
    wait_terminal(client, job_id, "cancelled")
    manifest = wait_until(lambda: session_for_job(client, job_id), f"{domain} manifest")
    if manifest["state"] != "cancelled":
        raise E2EFailure(f"cancelled Session has wrong state: {manifest}")
    if (Path(manifest["session_dir"]) / "recovery.json").exists():
        raise E2EFailure("recovery journal survived clean cancellation")
    after = (read_pids(pid_dir, "tshark") | read_pids(pid_dir, "chrome")) - before
    assert_gone(after)
    assert_restored(manager, baseline)


def analysis_cancel(
    client: WorkerClient, sessions: Path, chrome: Path, endpoint: str,
) -> None:
    job_id = str(uuid4())
    client.request("job.start", {"job": capture_payload(
        job_id, sessions, chrome, endpoint, "analysis.test", analyze=True, duration=3
    )})

    client._wait_for(
        lambda item: item.get("type") == "notification"
        and item.get("method") == "job.progress"
        and item.get("params", {}).get("job_id") == job_id
        and item.get("params", {}).get("stage", "").startswith("analyze."),
        30,
    )
    client.request("job.cancel", {"job_id": job_id, "reason": "cancel analysis"})
    wait_terminal(client, job_id, "cancelled")
    manifest = session_for_job(client, job_id)
    if manifest is None or manifest["state"] != "cancelled":
        raise E2EFailure(f"analysis Session was not cancelled: {manifest}")


def crash_recovery(
    process: subprocess.Popen[str], client: WorkerClient, worker_path: Path,
    sessions: Path, chrome: Path, endpoint: str, pid_dir: Path,
    env: dict[str, str], manager: MihomoManager, baseline: dict[str, Any],
):
    job_id = str(uuid4())
    client.request("job.start", {"job": capture_payload(
        job_id, sessions, chrome, endpoint, "crash.test"
    )})
    _, journal = wait_until(
        lambda: journal_with_roles(sessions, {"chrome"}), "crash recovery journal"
    )
    session_id = journal["session_id"]
    chrome_profiles = [
        item.get("profile", "")
        for item in journal["processes"]
        if item.get("role") == "chrome"
    ]
    if len(chrome_profiles) != 1:
        raise E2EFailure(
            f"crash recovery journal has invalid Chrome profiles: {chrome_profiles}"
        )
    profile_parts = Path(chrome_profiles[0]).parts
    expected_profiles = {
        ("cold", "crash.test", session_id),
        ("warm", "crash.test", "capture"),
    }
    if len(profile_parts) < 3 or profile_parts[-3:] not in expected_profiles:
        raise E2EFailure(
            "crash recovery journal has unexpected Chrome profile: "
            f"profile={chrome_profiles[0]} session={session_id}"
        )
    child_pids = {item["pid"] for item in journal["processes"]}
    process.kill()
    process.wait(timeout=10)
    new_process, new_client, ready = start_worker(worker_path, sessions, endpoint, env)
    recovery = ready["params"]["recovery"]
    if session_id not in recovery["recovered_sessions"] or recovery["status"] != "ok":
        raise E2EFailure(f"Worker did not recover crashed Session: {recovery}")
    manifest = new_client.request("session.get", {"session_id": session_id})
    if manifest["state"] != "interrupted":
        raise E2EFailure(f"crashed Session was not interrupted: {manifest}")
    assert_gone(child_pids | read_pids(pid_dir, "chrome"))
    assert_restored(manager, baseline)
    return new_process, new_client


def run(core_path: Path, worker_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="traffictracer-recovery-e2e-") as raw:
        root = Path(raw); sessions = root / "sessions"; pid_dir = root / "pids"
        core_home = root / "core"; bin_dir = root / "bin"
        pid_dir.mkdir(); core_home.mkdir(); bin_dir.mkdir()
        chrome, _ = write_fakes(bin_dir)
        socket_path = root / "controller.sock"; config = core_home / "config.yaml"
        write_core_config(config, socket_path); endpoint = f"unix://{socket_path}"
        env = os.environ.copy(); env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["TT_FAULT_PID_DIR"] = str(pid_dir); env["TT_FAULT_SESSIONS"] = str(sessions)
        manager = MihomoManager("", "", endpoint)
        core = subprocess.Popen(
            [str(core_path), "-d", str(core_home), "-f", str(config)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        worker = None
        try:
            wait_core(manager, core)
            baseline = {"enabled": True, "output": str(root / "baseline.jsonl"),
                        "session_id": "recovery-e2e-baseline"}
            manager.patch_tracing(baseline)
            worker, client, ready = start_worker(worker_path, sessions, endpoint, env)
            if ready["params"]["recovery"]["status"] != "ok":
                raise E2EFailure(f"unexpected initial recovery: {ready}")
            cancel_scenario(
                client, sessions, chrome, endpoint, pid_dir, manager, baseline,
                domain="chrome.test", packets=False, roles={"chrome"},
            )
            cancel_scenario(
                client, sessions, chrome, endpoint, pid_dir, manager, baseline,
                domain="dumpcap.test", packets=True,
                roles={"tshark-tun", "tshark-physical"},
            )
            analysis_cancel(client, sessions, chrome, endpoint)
            assert_restored(manager, baseline)
            worker, client = crash_recovery(
                worker, client, worker_path, sessions, chrome, endpoint,
                pid_dir, env, manager, baseline,
            )
            print("Recovery E2E passed: chrome/tshark/analysis cancel + SIGKILL restart")
            client.request("worker.shutdown", {})
            worker.wait(timeout=10); worker = None
        finally:
            terminate(worker); terminate(core)
            leftovers = read_pids(pid_dir, "chrome") | read_pids(pid_dir, "tshark")
            for pid in leftovers:
                if Path(f"/proc/{pid}").exists():
                    try: os.kill(pid, 9)
                    except ProcessLookupError: pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    args = parser.parse_args()
    for name in ("core", "worker"):
        path = getattr(args, name).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f"{name} is not executable: {path}")
        setattr(args, name, path)
    run(args.core, args.worker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

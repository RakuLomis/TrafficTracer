"""INT-011 end-to-end gates for serial batch faults and recovery."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import subprocess
from threading import Event, Thread
from urllib.request import urlopen

from traffictracer.capture.quiescence import (
    ChromeCleanupIncomplete,
    ChromeQuiescenceReport,
)
from traffictracer.jobs.batch_models import BatchChildState, BatchState
from traffictracer.jobs.models import CaptureJobResult, JobState
from traffictracer.jobs.progress import JobStage
from traffictracer.session.store import MANIFEST_NAME
from traffictracer.worker.services import WorkerServices


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid-batch.json"


class _TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.path.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def _payload(tmp_path, port):
    config = tmp_path / "targets.yaml"
    config.write_text(
        "sites:\n  - url: ok\n  - url: residual\n  - url: analysis\n",
        encoding="utf-8",
    )
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["config_path"] = str(config)
    payload["config_sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
    payload["output_root"] = str((tmp_path / "sessions").resolve())
    base = payload["targets"][0]
    payload["targets"] = [
        {
            **base,
            "index": index,
            "url": f"http://127.0.0.1:{port}/{path}",
            "domain": "127.0.0.1",
            "run_label": path,
        }
        for index, path in ((1, "ok"), (3, "residual"), (5, "analysis"))
    ]
    return payload


def test_three_target_worker_service_fail_fast_and_resume_from_exact_child(
    tmp_path, monkeypatch
):
    """Exercise the public service layer without starting the desktop or live Chrome."""
    import traffictracer.worker.services as service_module

    server = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    unrelated_chrome = subprocess.Popen(
        ["bash", "-c", "exec -a chrome sleep 30"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    faults = {"residual": True, "analysis": True}
    starts = []
    active = 0
    maximum_active = 0

    class _FaultInjectedCapture:
        def __init__(self, spec, **kwargs):
            self.spec = spec
            self.session = kwargs["session"]
            self.progress = kwargs["progress"]

        def run(self):
            nonlocal active, maximum_active
            label = self.spec.run_label
            starts.append(self.spec.target_source.target_index)
            active += 1
            maximum_active = max(maximum_active, active)
            try:
                with urlopen(self.spec.url, timeout=2) as response:
                    assert response.status == 200
                (self.session.directory / "captures").mkdir()
                logs = self.session.directory / "logs"
                logs.mkdir()
                (logs / "capture.json").write_text("{}\n", encoding="utf-8")
                self.progress.emit(
                    JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.5
                )
                self.progress.emit(JobState.CAPTURING, JobStage.CLEANUP, 0.9)
                if label == "residual" and faults["residual"]:
                    raise ChromeCleanupIncomplete(
                        ChromeQuiescenceReport(
                            str(tmp_path / "managed-profile"), True, (4242,)
                        )
                    )
                return CaptureJobResult(
                    self.spec.job_id,
                    JobState.COMPLETED,
                    artifacts=("logs/capture.json",),
                )
            finally:
                active -= 1

    class _FaultInjectedAnalysis:
        def __init__(self, spec, **kwargs):
            self.spec = spec
            self.progress = kwargs["progress"]

        def run(self):
            manifest = json.loads(
                (Path(self.spec.session_dir) / MANIFEST_NAME).read_text(
                    encoding="utf-8"
                )
            )
            self.progress.emit(JobState.ANALYZING, JobStage.ANALYZE_WRITE, 0.95)
            if manifest["target"]["url"].endswith("/analysis") and faults["analysis"]:
                raise RuntimeError("injected analysis failure")
            return CaptureJobResult(self.spec.job_id, JobState.COMPLETED)

    monkeypatch.setattr(service_module, "CaptureJob", _FaultInjectedCapture)
    monkeypatch.setattr(service_module, "AnalysisJob", _FaultInjectedAnalysis)
    payload = _payload(tmp_path, server.server_address[1])
    services = WorkerServices(
        tmp_path / "sessions", notify=lambda _: None, shutdown_event=Event()
    )

    try:
        services.batch_start({"job": payload})
        assert services.jobs.wait(payload["job_id"], timeout=5)
        first = services.batches.get(payload["job_id"])
        assert first.state is BatchState.FAILED
        assert [child.state for child in first.children] == [
            BatchChildState.COMPLETED,
            BatchChildState.FAILED,
            BatchChildState.PENDING,
        ]
        assert first.children[1].error.code == "CHROME_CLEANUP_INCOMPLETE"
        assert first.resume.next_index == 1
        assert starts == [1, 3]
        assert unrelated_chrome.poll() is None

        faults["residual"] = False
        services.batch_resume({"batch_id": payload["job_id"]})
        assert services.jobs.wait(payload["job_id"], timeout=5)
        second = services.batches.get(payload["job_id"])
        assert second.state is BatchState.FAILED
        assert second.children[2].error.code == "BATCH_CHILD_FAILED"
        assert second.resume.next_index == 3
        assert starts == [1, 3, 3, 5]
        assert unrelated_chrome.poll() is None

        faults["analysis"] = False
        services.batch_resume({"batch_id": payload["job_id"]})
        assert services.jobs.wait(payload["job_id"], timeout=5)
        completed = services.batches.get(payload["job_id"])
        assert completed.state is BatchState.COMPLETED
        assert all(
            child.state is BatchChildState.COMPLETED
            for child in completed.children
        )
        assert completed.resume.attempt == 2
        assert starts == [1, 3, 3, 5, 5]
        assert maximum_active == 1
        assert unrelated_chrome.poll() is None
    finally:
        server.shutdown()
        server.server_close()
        unrelated_chrome.terminate()
        unrelated_chrome.wait(timeout=2)

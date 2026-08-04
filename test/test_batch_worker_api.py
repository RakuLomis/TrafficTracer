"""TT-046 Worker API, crash recovery, resume, and cancellation gates."""

import hashlib
import json
from pathlib import Path
import time
from threading import Event

from traffictracer.jobs.batch_models import (
    BatchChildState,
    BatchJobSpec,
    BatchManifest,
    BatchState,
)
from traffictracer.jobs.cancellation import CancelledError
from traffictracer.jobs.models import CaptureJobResult, JobState
from traffictracer.worker.dispatcher import Dispatcher
from traffictracer.worker.services import WorkerServices


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid-batch.json"


def _request(request_id, method, params):
    return {
        "api_version": 2,
        "type": "request",
        "id": request_id,
        "method": method,
        "params": params,
    }


def _payload(tmp_path, count=2):
    config = tmp_path / "targets.yaml"
    original = "sites:\n  - fixture: one\n  - fixture: two\n"
    config.write_text(original, encoding="utf-8")
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["config_path"] = str(config)
    payload["config_sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
    payload["output_root"] = str((tmp_path / "sessions").resolve())
    payload["targets"] = payload["targets"][:count]
    return payload, original


class _QuickCapture:
    def __init__(self, spec, **kwargs):
        self.spec = spec
        self.session = kwargs["session"]

    def run(self):
        (self.session.directory / "captures").mkdir()
        logs = self.session.directory / "logs"
        logs.mkdir()
        (logs / "capture.json").write_text("{}\n", encoding="utf-8")
        return CaptureJobResult(
            self.spec.job_id,
            JobState.COMPLETED,
            session_id=self.session.session_id,
            artifacts=("logs/capture.json",),
        )


def test_batch_jsonl_start_status_list_and_notification_order(
    tmp_path, monkeypatch
):
    import traffictracer.worker.services as module

    monkeypatch.setattr(module, "CaptureJob", _QuickCapture)
    payload, _ = _payload(tmp_path)
    notifications = []
    services = WorkerServices(
        tmp_path / "sessions",
        notify=notifications.append,
        shutdown_event=Event(),
    )
    dispatcher = Dispatcher(services.handlers())
    started = dispatcher.dispatch(_request("start", "batch.start", {"job": payload}))
    assert "result" in started
    batch_id = payload["job_id"]
    assert services.jobs.wait(batch_id, timeout=5)

    status = dispatcher.dispatch(
        _request("status", "batch.status", {"batch_id": batch_id})
    )["result"]
    listed = dispatcher.dispatch(_request("list", "batch.list", {}))["result"]
    assert status["batch"]["state"] == "completed"
    assert status["job"]["state"] == "completed"
    assert [item["batch_id"] for item in listed["batches"]] == [batch_id]
    completed_positions = [
        index for index, item in enumerate(notifications)
        if item["method"] == "job.completed"
    ]
    assert completed_positions == [len(notifications) - 1]


def test_worker_restart_marks_running_child_interrupted_and_resume_reuses_snapshot(
    tmp_path, monkeypatch
):
    import traffictracer.worker.services as module

    payload, original = _payload(tmp_path)
    first = WorkerServices(
        tmp_path / "sessions", notify=lambda _: None, shutdown_event=Event()
    )
    manifest = BatchManifest.create(BatchJobSpec.from_dict(payload)).begin().start_child(0)
    first.batches.save(manifest)

    restarted = WorkerServices(
        tmp_path / "sessions", notify=lambda _: None, shutdown_event=Event()
    )
    assert restarted.recover_batches() == (payload["job_id"],)
    interrupted = restarted.batches.get(payload["job_id"])
    assert interrupted.state is BatchState.INTERRUPTED
    assert interrupted.children[0].state is BatchChildState.INTERRUPTED
    assert interrupted.resume.next_index == 0

    Path(payload["config_path"]).write_text("sites:\n  - changed: true\n", encoding="utf-8")
    changed = Dispatcher(restarted.handlers()).dispatch(
        _request("resume-changed", "batch.resume", {"batch_id": payload["job_id"]})
    )
    assert changed["error"]["code"] == "INVALID_PARAMS"
    assert restarted.batches.get(payload["job_id"]).targets == interrupted.targets

    Path(payload["config_path"]).write_text(original, encoding="utf-8")
    monkeypatch.setattr(module, "CaptureJob", _QuickCapture)
    resumed = restarted.batch_resume({"batch_id": payload["job_id"]})
    assert resumed["job_id"] == payload["job_id"]
    assert restarted.jobs.wait(payload["job_id"], timeout=5)
    completed = restarted.batches.get(payload["job_id"])
    assert completed.state is BatchState.COMPLETED
    assert completed.resume.attempt == 1


def test_batch_cancel_is_idempotent_and_does_not_start_next_child(
    tmp_path, monkeypatch
):
    import traffictracer.worker.services as module

    payload, _ = _payload(tmp_path)
    started = Event()
    calls = []

    class _BlockingCapture:
        def __init__(self, spec, **kwargs):
            self.spec = spec
            self.session = kwargs["session"]
            self.cancellation = kwargs["cancellation"]

        def run(self):
            calls.append(self.spec.target_source.target_index)
            (self.session.directory / "captures").mkdir()
            (self.session.directory / "logs").mkdir()
            started.set()
            while True:
                self.cancellation.checkpoint()
                time.sleep(0.005)

    monkeypatch.setattr(module, "CaptureJob", _BlockingCapture)
    services = WorkerServices(
        tmp_path / "sessions", notify=lambda _: None, shutdown_event=Event()
    )
    services.batch_start({"job": payload})
    assert started.wait(2)
    first = services.batch_cancel({"batch_id": payload["job_id"], "reason": "stop"})
    second = services.batch_cancel({"batch_id": payload["job_id"], "reason": "again"})
    assert first["job"]["cancel_requested_now"] is True
    assert second["job"]["cancel_requested_now"] is False
    assert services.jobs.wait(payload["job_id"], timeout=5)
    manifest = services.batches.get(payload["job_id"])
    assert manifest.state is BatchState.CANCELLED
    assert calls == [1]

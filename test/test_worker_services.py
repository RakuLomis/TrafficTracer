"""Integration tests for concrete Session/Flow and Job Worker services."""

import json
from pathlib import Path
from threading import Event

from traffictracer.jobs.models import CaptureJobResult, JobState
from traffictracer.jobs.progress import JobStage
from traffictracer.session.atomic import write_json_atomic
from traffictracer.worker.services import WorkerServices


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid.json"


def _capture_payload(output_root):
    with CAPTURE_FIXTURE.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    payload["output_root"] = str(output_root)
    return payload


def test_capture_service_chains_analysis_and_persists_manifest_artifacts(
    tmp_path, monkeypatch
):
    import traffictracer.worker.services as module

    notifications = []
    services = WorkerServices(
        tmp_path,
        notify=notifications.append,
        shutdown_event=Event(),
    )

    class FakeCaptureJob:
        def __init__(self, spec, **kwargs):
            self.spec = spec
            self.session = kwargs["session"]
            self.progress = kwargs["progress"]

        def run(self):
            (self.session.directory / "captures").mkdir()
            logs = self.session.directory / "logs"
            logs.mkdir()
            raw = logs / "capture.json"
            raw.write_text("{}\n", encoding="utf-8")
            self.progress.emit(
                JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.4
            )
            self.progress.emit(JobState.CAPTURING, JobStage.CLEANUP, 0.9)
            return CaptureJobResult(
                self.spec.job_id,
                JobState.COMPLETED,
                session_id=self.session.session_id,
                artifacts=("logs/capture.json",),
            )

    monkeypatch.setattr(module, "CaptureJob", FakeCaptureJob)
    payload = _capture_payload(tmp_path)
    started = services.jobs.start_capture({"job": payload})
    assert services.jobs.wait(started["job_id"], timeout=3)
    status = services.jobs.status({"job_id": started["job_id"]})
    assert status["state"] == "completed"
    sessions = services.session_list({})["sessions"]
    assert len(sessions) == 1
    manifest = sessions[0]
    assert manifest["state"] == "completed"
    assert [item["path"] for item in manifest["artifacts"]] == [
        "logs/capture.json",
        "results/correlation.json",
        "results/flow-index.json",
        "results/summary.json",
    ]
    assert any(item["method"] == "job.completed" for item in notifications)


def test_session_flow_query_paginates_and_terminal_delete_is_scoped(
    tmp_path, monkeypatch
):
    import traffictracer.worker.services as module

    services = WorkerServices(
        tmp_path,
        notify=lambda message: None,
        shutdown_event=Event(),
    )

    class FakeCaptureJob:
        def __init__(self, spec, **kwargs):
            self.spec = spec
            self.session = kwargs["session"]

        def run(self):
            (self.session.directory / "captures").mkdir()
            (self.session.directory / "logs").mkdir()
            return CaptureJobResult(
                self.spec.job_id,
                JobState.COMPLETED,
                session_id=self.session.session_id,
            )

    monkeypatch.setattr(module, "CaptureJob", FakeCaptureJob)
    payload = _capture_payload(tmp_path)
    payload["options"]["analyze_after_capture"] = False
    started = services.jobs.start_capture(payload)
    assert services.jobs.wait(started["job_id"], timeout=3)
    manifest = services.session_list({})["sessions"][0]
    session_id = manifest["session_id"]
    path = services.store.artifact_path(session_id, "results/flow-index.json")
    path.parent.mkdir(exist_ok=True)
    pre = {
        "network": "tcp",
        "src_ip": "198.18.0.1",
        "src_port": 40000,
        "dst_ip": "1.1.1.1",
        "dst_port": 443,
    }
    write_json_atomic(path, {
        "items": [
            {"flow_id": "tcp:c1", "pre_flow": pre},
            {"flow_id": "tcp:c2", "pre_flow": pre},
        ]
    })
    queried = services.flow_query({
        "session_id": session_id,
        **pre,
        "offset": 1,
        "limit": 1,
    })
    assert queried["total"] == 2
    assert [item["flow_id"] for item in queried["items"]] == ["tcp:c2"]
    assert services.session_get({"session_id": session_id})["session_id"] == session_id
    assert services.session_delete({"session_id": session_id})["deleted"] is True
    assert services.session_list({})["sessions"] == []

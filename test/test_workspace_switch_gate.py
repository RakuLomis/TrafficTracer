"""INT-010 gate for isolated custom Session workspaces."""

import json
from pathlib import Path
from threading import Event

import pytest

from traffictracer.jobs.models import CaptureJobResult, JobState
from traffictracer.session.store import SessionNotFoundError
from traffictracer.worker.services import WorkerServices


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid.json"


def _capture_payload(output_root: Path, job_id: str, url: str) -> dict:
    payload = json.loads(CAPTURE_FIXTURE.read_text(encoding="utf-8"))
    payload["job_id"] = job_id
    payload["url"] = url
    payload["domain"] = "example.test"
    payload["output_root"] = str(output_root.resolve())
    payload["options"]["analyze_after_capture"] = True
    return payload


class _FixtureCaptureJob:
    """Produces the minimum immutable raw input needed by real analysis."""

    def __init__(self, spec, **kwargs):
        self.spec = spec
        self.session = kwargs["session"]

    def run(self):
        (self.session.directory / "captures").mkdir()
        logs = self.session.directory / "logs"
        logs.mkdir()
        raw = logs / "capture.json"
        raw.write_text("{}\n", encoding="utf-8")
        return CaptureJobResult(
            self.spec.job_id,
            JobState.COMPLETED,
            session_id=self.session.session_id,
            artifacts=("logs/capture.json",),
        )


def _capture_analyze_list_and_read(
    services: WorkerServices,
    root: Path,
    job_id: str,
    url: str,
) -> str:
    started = services.jobs.start_capture({
        "job": _capture_payload(root, job_id, url),
    })
    assert services.jobs.wait(started["job_id"], timeout=3)
    assert services.jobs.status({"job_id": job_id})["state"] == "completed"

    sessions = services.session_list({})["sessions"]
    assert len(sessions) == 1
    session_summary = sessions[0]
    manifest = services.session_get({
        "session_id": session_summary["session_id"],
    })
    relative_session = Path(manifest["session_dir"]).relative_to(root.resolve())
    assert len(relative_session.parts) == 3
    assert relative_session.parts[1] == "example.test"
    assert relative_session.parts[2].startswith("capture__https_")
    assert (Path(manifest["session_dir"]) / "raw").is_dir()
    assert manifest["target"]["url"] == url

    summary = next(
        artifact for artifact in manifest["artifacts"]
        if artifact["path"] == "analysis/summary.json"
    )
    opened = services.store.artifact_path(
        manifest["session_id"], summary["path"]
    )
    assert opened.is_file()
    assert isinstance(json.loads(opened.read_text(encoding="utf-8")), dict)
    return manifest["session_id"]


def test_two_custom_roots_capture_analyze_list_and_open_in_isolation(
    tmp_path,
    monkeypatch,
):
    import traffictracer.worker.services as service_module

    monkeypatch.setattr(service_module, "CaptureJob", _FixtureCaptureJob)
    first_root = tmp_path / "first user workspace"
    second_root = tmp_path / "second user workspace"
    first = WorkerServices(first_root, notify=lambda _: None, shutdown_event=Event())
    first_id = _capture_analyze_list_and_read(
        first,
        first_root,
        "11111111-1111-4111-8111-111111111111",
        "https://one.example.test/",
    )

    second = WorkerServices(
        second_root,
        notify=lambda _: None,
        shutdown_event=Event(),
    )
    assert second.session_list({})["sessions"] == []
    second_id = _capture_analyze_list_and_read(
        second,
        second_root,
        "22222222-2222-4222-8222-222222222222",
        "https://two.example.test/",
    )

    assert first_id != second_id
    assert [item["session_id"] for item in first.session_list({})["sessions"]] == [
        first_id
    ]
    assert [item["session_id"] for item in second.session_list({})["sessions"]] == [
        second_id
    ]
    with pytest.raises(SessionNotFoundError):
        first.store.get(second_id)
    with pytest.raises(SessionNotFoundError):
        second.store.get(first_id)

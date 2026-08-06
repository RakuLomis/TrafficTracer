"""Integration tests for concrete Session/Flow and Job Worker services."""

import json
from pathlib import Path
from threading import Event

import pytest

from traffictracer.jobs.models import CaptureJobResult, JobState
from traffictracer.jobs.progress import JobStage
from traffictracer.session.atomic import write_json_atomic
from traffictracer.session.manifest import (
    ComponentVersion,
    ComponentVersions,
    SessionTarget,
)
from traffictracer.worker.services import WorkerServices
from traffictracer.worker.dispatcher import WorkerMethodError


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid.json"
BATCH_FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid-batch.json"


def _capture_payload(output_root):
    with CAPTURE_FIXTURE.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    payload["output_root"] = str(output_root)
    return payload


def test_target_config_service_returns_normalized_preview(tmp_path):
    config = tmp_path / "sites.yaml"
    config.write_text(
        """global:
  mihomo:
    secret: must-not-leak
sites:
  - domain: Example.COM.
    url: https://example.com/path
    wait: 12
    traffic_type: browser
    wait_load_timeout: 45
""",
        encoding="utf-8",
    )
    services = WorkerServices(
        tmp_path / "sessions",
        notify=lambda message: None,
        shutdown_event=Event(),
    )

    preview = services.load_targets({"path": str(config)})

    assert preview["config_path"] == str(config.resolve())
    assert preview["targets"] == [{
        "index": 0,
        "domain": "example.com",
        "url": "https://example.com/path",
        "duration_seconds": 12,
        "network": "all",
        "run_label": "browser",
        "wait_load_timeout": 45,
        "page_type": "browser",
    }]
    assert preview["warnings"]
    assert "must-not-leak" not in str(preview)


def test_target_config_service_maps_validation_errors_without_values(tmp_path):
    config = tmp_path / "sites.yaml"
    config.write_text(
        "sites:\n  - domain: example.com\n    url: 'secret-value'\n",
        encoding="utf-8",
    )
    services = WorkerServices(
        tmp_path / "sessions",
        notify=lambda message: None,
        shutdown_event=Event(),
    )

    with pytest.raises(WorkerMethodError) as raised:
        services.load_targets({"path": str(config)})

    assert raised.value.code == "INVALID_PARAMS"
    assert raised.value.data == {"field": "sites[0].url"}
    assert "secret-value" not in raised.value.message


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
        "analysis/correlation.json",
        "analysis/flow-index.json",
        "analysis/summary.json",
    ]
    assert any(item["method"] == "job.completed" for item in notifications)


def test_internal_batch_orchestration_creates_three_serial_analyzed_sessions(
    tmp_path, monkeypatch
):
    import traffictracer.worker.services as module

    config = tmp_path / "three-targets.yaml"
    config.write_text(
        """sites:
  - domain: one.example.test
    url: https://one.example.test/
  - domain: two.example.test
    url: https://two.example.test/
  - domain: three.example.test
    url: https://three.example.test/
""",
        encoding="utf-8",
    )
    services = WorkerServices(
        tmp_path / "sessions",
        notify=lambda message: None,
        shutdown_event=Event(),
    )
    preview = services.load_targets({"path": str(config)})
    payload = json.loads(BATCH_FIXTURE.read_text(encoding="utf-8"))
    payload["config_path"] = preview["config_path"]
    payload["config_sha256"] = preview["sha256"]
    payload["targets"] = preview["targets"]
    payload["output_root"] = str(services.store.output_root)
    active = [0]
    maximum = [0]

    class FakeCaptureJob:
        def __init__(self, spec, **kwargs):
            self.spec = spec
            self.session = kwargs["session"]

        def run(self):
            active[0] += 1
            maximum[0] = max(maximum[0], active[0])
            try:
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
            finally:
                active[0] -= 1

    monkeypatch.setattr(module, "CaptureJob", FakeCaptureJob)
    started = services.jobs.start_batch({"job": payload})
    assert services.jobs.wait(started["job_id"], timeout=5)
    status = services.jobs.status({"job_id": started["job_id"]})
    sessions = services.session_list({})["sessions"]

    assert status["state"] == "completed"
    assert status["result"]["completed_targets"] == 3
    assert len(sessions) == 3
    assert all(session["state"] == "completed" for session in sessions)
    assert maximum == [1]


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


def test_session_cleanup_preview_is_read_only(tmp_path, monkeypatch):
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
            legacy = self.session.directory / "captures" / "d" / "r" / "flows"
            legacy.mkdir(parents=True)
            (legacy / "pre.pcap").write_bytes(b"pcap")
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
    session_id = services.session_list({})["sessions"][0]["session_id"]
    preview = services.session_cleanup_preview({"session_id": session_id})
    assert preview["candidate_count"] == 1
    assert preview["delete_supported"] is False
    assert services.store.artifact_path(
        session_id,
        preview["candidates"][0]["path"],
    ).is_file()


def test_flow_query_prefers_latest_reanalysis_generation(tmp_path, monkeypatch):
    services = WorkerServices(
        tmp_path,
        notify=lambda message: None,
        shutdown_event=Event(),
    )
    manifest = services.store.create(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=ComponentVersions(
            ComponentVersion("complete", "unknown"),
            ComponentVersion("complete", "unknown"),
            ComponentVersion("complete", "unknown"),
        ),
    )
    session = Path(manifest.session_dir)
    old = session / "results" / "flow-index.json"
    new = (
        session / "results" / "generations"
        / "11111111-1111-4111-8111-111111111111"
        / "flow-index.json"
    )
    old.parent.mkdir()
    new.parent.mkdir(parents=True)
    pre = {
        "network": "tcp", "src_ip": "198.18.0.1", "src_port": 40000,
        "dst_ip": "1.1.1.1", "dst_port": 443,
    }
    write_json_atomic(old, {"items": [{"flow_id": "old", "pre_flow": pre}]})
    write_json_atomic(new, {"items": [{"flow_id": "new", "pre_flow": pre}]})

    queried = services.flow_query({"session_id": manifest.session_id, **pre})

    assert [item["flow_id"] for item in queried["items"]] == ["new"]



def test_session_scope_resolve_and_list_are_folder_scoped(tmp_path):
    services = WorkerServices(
        tmp_path / "sessions",
        notify=lambda message: None,
        shutdown_event=Event(),
    )
    first = services.store.create(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        target=SessionTarget("https://example.com/one", "example.com"),
        component_versions=ComponentVersions(
            *(ComponentVersion("complete", "unknown") for _ in range(3))
        ),
        page_type="main-page",
        capture_group="20260805-110256-685",
    )
    services.store.create(
        job_id="c8c76aef-bbf2-45d4-96d6-9a0c52c34f91",
        target=SessionTarget("https://example.org/two", "example.org"),
        component_versions=ComponentVersions(
            *(ComponentVersion("complete", "unknown") for _ in range(3))
        ),
        page_type="video-play1",
        capture_group="20260805-110300-000",
    )

    by_path = services.session_scope_resolve(
        {"path": str(services.store.output_root / "20260805-110256-685")}
    )
    by_job = services.session_scope_resolve({"job_id": first.job_id})
    listed = services.session_scope_list({"scope_id": by_path["scope_id"]})

    assert by_job == by_path
    assert listed["scope"] == by_path
    assert [item["session_id"] for item in listed["sessions"]] == [
        first.session_id
    ]
    assert listed["corrupt"] == []


def test_session_scope_resolve_rejects_root_and_returns_none_before_job_manifest(
    tmp_path,
):
    services = WorkerServices(
        tmp_path / "sessions",
        notify=lambda message: None,
        shutdown_event=Event(),
    )

    with pytest.raises(WorkerMethodError) as raised:
        services.session_scope_resolve({"path": str(services.store.output_root)})
    assert raised.value.code == "INVALID_PARAMS"
    assert services.session_scope_resolve(
        {"job_id": "2f746e31-d62a-4e1c-a919-3f88ecde31c2"}
    ) is None



def test_session_scope_resolve_maps_batch_to_its_stable_capture_group(tmp_path):
    from datetime import datetime, timezone

    from traffictracer.jobs.batch_models import BatchJobSpec, BatchManifest

    services = WorkerServices(
        tmp_path / "sessions",
        notify=lambda message: None,
        shutdown_event=Event(),
    )
    payload = json.loads(BATCH_FIXTURE.read_text(encoding="utf-8"))
    payload["output_root"] = str(services.store.output_root)
    manifest = BatchManifest.create(
        BatchJobSpec.from_dict(payload),
        now=datetime(2026, 8, 5, 11, 2, 56, 685000, tzinfo=timezone.utc),
    )
    services.batches.save(manifest)

    scope = services.session_scope_resolve({"batch_id": manifest.batch_id})

    assert scope["scope_id"] == "20260805-110256-685"
    assert scope["kind"] == "capture_group"
    assert scope["exists"] is False
    assert services.session_scope_list({"scope_id": scope["scope_id"]})[
        "sessions"
    ] == []

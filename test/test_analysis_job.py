"""Lifecycle tests for progress-aware analysis jobs."""

from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from traffictracer.analyze.job import AnalysisJob
from traffictracer.jobs.cancellation import CancellationToken, CancelledError
from traffictracer.jobs.models import AnalysisJobOptions, AnalysisJobSpec, JobState
from traffictracer.jobs.progress import ProgressReporter
from traffictracer.session.manifest import (
    ComponentVersion,
    ComponentVersions,
    SessionTarget,
)
from traffictracer.session.store import SessionStore


SESSION_ID = UUID("5027aee9-c6e4-41de-8625-7ea0869a3307")
JOB_ID = "bc973e98-c472-40c8-bf82-e2992352ece0"


def _capturing_session(tmp_path):
    store = SessionStore(tmp_path, id_factory=lambda: SESSION_ID)
    version = ComponentVersion("complete", "unknown")
    manifest = store.create(
        job_id=JOB_ID,
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=ComponentVersions(version, version, version),
        now=datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc),
    )
    manifest = manifest.transition(JobState.PREPARING)
    manifest = manifest.transition(JobState.CAPTURING)
    store.save(manifest)
    session_dir = Path(manifest.session_dir)
    (session_dir / "captures").mkdir()
    (session_dir / "logs").mkdir()
    return store, manifest, session_dir


def _job(tmp_path, session_dir, events, token=None, **option_overrides):
    options = AnalysisJobOptions(**option_overrides)
    spec = AnalysisJobSpec(
        job_id=JOB_ID,
        session_dir=str(session_dir),
        output_root=str(tmp_path),
        options=options,
    )
    cancellation = token or CancellationToken()
    return AnalysisJob(
        spec,
        progress=ProgressReporter(JOB_ID, events.append, min_interval=0),
        cancellation=cancellation,
    )


def test_analysis_job_completes_manifest_and_returns_artifact(tmp_path):
    store, manifest, session_dir = _capturing_session(tmp_path)
    events = []
    result = _job(tmp_path, session_dir, events).run()
    assert result.state is JobState.COMPLETED
    assert result.session_id == manifest.session_id
    assert result.artifacts == (
        "results/correlation.json",
        "results/flow-index.json",
        "results/summary.json",
    )
    completed = store.get(manifest.session_id)
    assert completed.state is JobState.COMPLETED
    assert [artifact.path for artifact in completed.artifacts] == list(result.artifacts)
    assert events[-1].state is JobState.COMPLETED


def test_192_serial_analysis_jobs_release_health_threads_and_descriptors(tmp_path):
    import threading
    # Exercise actual job publication/cleanup, not a mock scheduler. Empty
    # captures deliberately isolate lifecycle resource growth from data size.
    before_fds = len(list(Path("/proc/self/fd").iterdir())) if Path("/proc/self/fd").exists() else None
    for index in range(192):
        root = tmp_path / str(index)
        _, _, session = _capturing_session(root)
        result = _job(root, session, []).run()
        assert result.state is JobState.COMPLETED
        assert not any(thread.name == "analysis-health" for thread in threading.enumerate())
    if before_fds is not None:
        assert len(list(Path("/proc/self/fd").iterdir())) <= before_fds + 2


def test_completed_session_can_be_explicitly_reanalyzed_without_duplicate_artifacts(
    tmp_path,
):
    store, manifest, session_dir = _capturing_session(tmp_path)
    _job(tmp_path, session_dir, [], overwrite=True).run()
    first = store.get(manifest.session_id)
    _job(tmp_path, session_dir, [], overwrite=True).run()
    second = store.get(manifest.session_id)
    assert second.state is JobState.COMPLETED
    assert [artifact.path for artifact in second.artifacts] == [
        artifact.path for artifact in first.artifacts
    ]


def test_completed_v1_reanalysis_writes_independent_generation(tmp_path):
    store, manifest, session_dir = _capturing_session(tmp_path)
    _job(tmp_path, session_dir, [], overwrite=True).run()
    legacy_correlation = session_dir / "results" / "correlation.json"
    legacy_correlation.write_text('{"legacy": true}\n', encoding="utf-8")
    manifest_path = session_dir / "manifest.json"
    legacy_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    legacy_manifest["schema_version"] = 1
    legacy_manifest["artifacts"] = [
        {
            "name": item["name"],
            "kind": (
                "raw" if item["phase"] == "capture"
                else "derived" if item["phase"] == "analysis"
                else "diagnostic"
            ),
            "path": item["path"],
            "media_type": item["media_type"],
            "size_bytes": item["size_bytes"],
        }
        for item in legacy_manifest["artifacts"]
    ]
    manifest_path.write_text(json.dumps(legacy_manifest), encoding="utf-8")
    manifest_before = manifest_path.read_bytes()

    result = _job(tmp_path, session_dir, [], overwrite=True).run()

    assert legacy_correlation.read_text(encoding="utf-8") == '{"legacy": true}\n'
    generation_artifacts = [
        path for path in result.artifacts if "/generations/" in f"/{path}"
    ]
    assert generation_artifacts
    generation_roots = {
        "/".join(path.split("/")[:3]) for path in generation_artifacts
    }
    assert len(generation_roots) == 1
    assert manifest_path.read_bytes() == manifest_before


def test_analysis_failure_preserves_raw_artifact_and_records_manifest_error(
    tmp_path, monkeypatch
):
    import traffictracer.analyze.job as module

    store, manifest, session_dir = _capturing_session(tmp_path)
    raw = session_dir / "logs" / "netlog_example.com_all_1.json"
    raw.write_text("original raw capture", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "run_analysis",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("bad trace")),
    )
    events = []
    with pytest.raises(RuntimeError, match="bad trace"):
        _job(tmp_path, session_dir, events).run()
    failed = store.get(manifest.session_id)
    assert failed.state is JobState.FAILED
    assert failed.error is not None
    assert failed.error.code == "ANALYSIS_FAILED"
    assert raw.read_text(encoding="utf-8") == "original raw capture"
    assert events[-1].state is JobState.FAILED


def test_failed_analysis_can_retry_in_place_without_recapturing(
    tmp_path, monkeypatch
):
    import traffictracer.analyze.job as module

    store, manifest, session_dir = _capturing_session(tmp_path)
    raw = session_dir / "logs" / "netlog_example.com_all_1.json"
    raw.write_text("original raw capture", encoding="utf-8")
    real_run_analysis = module.run_analysis
    monkeypatch.setattr(
        module,
        "run_analysis",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("invalid generated index")
        ),
    )
    with pytest.raises(RuntimeError, match="invalid generated index"):
        _job(tmp_path, session_dir, []).run()

    failed = store.get(manifest.session_id)
    assert failed.error is not None
    assert failed.error.code == "ANALYSIS_FAILED"

    monkeypatch.setattr(module, "run_analysis", real_run_analysis)
    result = _job(tmp_path, session_dir, [], overwrite=True).run()

    assert result.state is JobState.COMPLETED
    completed = store.get(manifest.session_id)
    assert completed.state is JobState.COMPLETED
    assert completed.error is None
    assert completed.session_dir == failed.session_dir
    assert raw.read_text(encoding="utf-8") == "original raw capture"


def test_analysis_failure_with_empty_exception_has_contract_safe_message(
    tmp_path, monkeypatch
):
    import traffictracer.analyze.job as module

    store, manifest, session_dir = _capturing_session(tmp_path)
    monkeypatch.setattr(
        module,
        "run_analysis",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()),
    )

    with pytest.raises(TimeoutError):
        _job(tmp_path, session_dir, []).run()

    failed = store.get(manifest.session_id)
    assert failed.state is JobState.FAILED
    assert failed.error is not None
    assert failed.error.message == "TimeoutError"
    assert failed.to_dict()["error"]["message"] == "TimeoutError"


def test_analysis_cancellation_marks_manifest_cancelled(tmp_path, monkeypatch):
    import traffictracer.analyze.job as module

    store, manifest, session_dir = _capturing_session(tmp_path)
    token = CancellationToken()

    def cancel(*args, **kwargs):
        token.cancel("user cancelled analysis")
        token.checkpoint()

    monkeypatch.setattr(module, "run_analysis", cancel)
    events = []
    with pytest.raises(CancelledError, match="user cancelled analysis"):
        _job(tmp_path, session_dir, events, token=token).run()
    assert store.get(manifest.session_id).state is JobState.CANCELLED
    assert events[-1].state is JobState.CANCELLED


def test_cancelled_v1_reanalysis_preserves_manifest_and_legacy_results(
    tmp_path,
    monkeypatch,
):
    import traffictracer.analyze.job as module

    store, manifest, session_dir = _capturing_session(tmp_path)
    _job(tmp_path, session_dir, [], overwrite=True).run()
    manifest_path = session_dir / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["schema_version"] = 1
    payload["artifacts"] = [
        {
            "name": item["name"],
            "kind": "derived",
            "path": item["path"],
            "media_type": item["media_type"],
            "size_bytes": item["size_bytes"],
        }
        for item in payload["artifacts"]
    ]
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    manifest_before = manifest_path.read_bytes()
    legacy = session_dir / "results" / "flow-index.json"
    legacy.write_bytes(b"legacy-flow-index")
    token = CancellationToken()

    def cancel_after_partial(*args, **kwargs):
        output = Path(kwargs["output_dir"])
        output.mkdir(parents=True)
        (output / ".partial.json").write_text("partial", encoding="utf-8")
        token.cancel("cancel legacy reanalysis")
        token.checkpoint()

    monkeypatch.setattr(module, "run_analysis", cancel_after_partial)
    with pytest.raises(CancelledError, match="cancel legacy reanalysis"):
        _job(
            tmp_path,
            session_dir,
            [],
            token=token,
            overwrite=True,
        ).run()

    assert manifest_path.read_bytes() == manifest_before
    assert legacy.read_bytes() == b"legacy-flow-index"


def test_analysis_consistency_failure_uses_dedicated_manifest_code(
    tmp_path, monkeypatch
):
    import traffictracer.analyze.job as module
    from traffictracer.analyze.consistency import AnalysisConsistencyError

    store, manifest, session_dir = _capturing_session(tmp_path)
    monkeypatch.setattr(
        module,
        "run_analysis",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AnalysisConsistencyError("cross-index mismatch")
        ),
    )

    with pytest.raises(AnalysisConsistencyError, match="cross-index mismatch"):
        _job(tmp_path, session_dir, []).run()

    failed = store.get(manifest.session_id)
    assert failed.state is JobState.FAILED
    assert failed.error is not None
    assert failed.error.code == "ANALYSIS_CONSISTENCY_FAILED"


def test_normalized_analysis_is_atomically_published_after_validation(
    tmp_path, monkeypatch
):
    import traffictracer.analyze.job as module

    store, manifest, session_dir = _capturing_session(tmp_path)
    (session_dir / "raw").mkdir()
    (session_dir / "analysis").mkdir()

    def write_analysis(*args, **kwargs):
        output = Path(kwargs["output_dir"])
        output.mkdir(parents=True)
        correlation = output / "correlation.json"
        correlation.write_text("{}\n", encoding="utf-8")
        pcap = output / "pcap" / "0001__https_example.com" / "pre.pcap"
        pcap.parent.mkdir(parents=True)
        pcap.write_bytes(b"pcap")
        published = Path(kwargs["published_output_dir"])
        relative_pcap = (
            published / pcap.relative_to(output)
        ).relative_to(session_dir)
        (output / "pcap-index-v1.json").write_text(json.dumps({
            "connections": [{
                "connection_id": "conn-" + "1" * 32,
                "pre_proxy": {
                    "status": "success",
                    "path": str(relative_pcap),
                },
                "post_proxy": {"status": "empty"},
            }],
        }), encoding="utf-8")
        return str(correlation)

    def write_summary(*args, **kwargs):
        output = Path(kwargs["output_dir"])
        flow_index = output / "flow-index.json"
        summary = output / "summary.json"
        flow_index.write_text("{}\n", encoding="utf-8")
        summary.write_text("{}\n", encoding="utf-8")
        return SimpleNamespace(flow_index=flow_index, summary=summary)

    monkeypatch.setattr(module, "run_analysis", write_analysis)
    monkeypatch.setattr(module, "persist_analysis_artifacts", write_summary)

    result = _job(tmp_path, session_dir, []).run()

    analysis = session_dir / "analysis"
    assert result.state is JobState.COMPLETED
    assert analysis.is_dir()
    assert not list(session_dir.glob(".analysis-staging-*"))
    pcap_index = json.loads(
        (analysis / "pcap-index-v1.json").read_text(encoding="utf-8")
    )
    assert pcap_index["connections"][0]["pre_proxy"]["path"] == (
        "analysis/pcap/0001__https_example.com/pre.pcap"
    )
    assert (analysis / "pcap/0001__https_example.com/pre.pcap").is_file()
    completed = store.get(manifest.session_id)
    assert all(
        not artifact.path.startswith(".analysis-staging-")
        for artifact in completed.artifacts
    )


def test_normalized_analysis_failure_discards_unpublished_staging(
    tmp_path, monkeypatch
):
    import traffictracer.analyze.job as module
    from traffictracer.analyze.consistency import AnalysisConsistencyError

    store, manifest, session_dir = _capturing_session(tmp_path)
    raw = session_dir / "raw"
    raw.mkdir()
    preserved = raw / "netlog.json"
    preserved.write_text("original", encoding="utf-8")

    def fail_after_partial_write(*args, **kwargs):
        output = Path(kwargs["output_dir"])
        output.mkdir(parents=True)
        (output / "partial.json").write_text("partial", encoding="utf-8")
        raise AnalysisConsistencyError("cross-index mismatch")

    monkeypatch.setattr(module, "run_analysis", fail_after_partial_write)

    with pytest.raises(AnalysisConsistencyError, match="cross-index mismatch"):
        _job(tmp_path, session_dir, []).run()

    assert not (session_dir / "analysis").exists()
    assert not list(session_dir.glob(".analysis-staging-*"))
    assert preserved.read_text(encoding="utf-8") == "original"
    failed = store.get(manifest.session_id)
    assert failed.state is JobState.FAILED
    assert failed.error is not None
    assert failed.error.code == "ANALYSIS_CONSISTENCY_FAILED"


def test_normalized_reanalysis_replaces_atomically_and_preserves_last_success(
    tmp_path, monkeypatch
):
    import traffictracer.analyze.job as module

    store, manifest, session_dir = _capturing_session(tmp_path)
    (session_dir / "raw").mkdir()
    content = {"value": "first"}

    def write_analysis(*args, **kwargs):
        output = Path(kwargs["output_dir"])
        output.mkdir(parents=True)
        correlation = output / "correlation.json"
        correlation.write_text(content["value"], encoding="utf-8")
        return str(correlation)

    def write_summary(*args, **kwargs):
        output = Path(kwargs["output_dir"])
        flow_index = output / "flow-index.json"
        summary = output / "summary.json"
        flow_index.write_text("{}\n", encoding="utf-8")
        summary.write_text("{}\n", encoding="utf-8")
        return SimpleNamespace(flow_index=flow_index, summary=summary)

    monkeypatch.setattr(module, "run_analysis", write_analysis)
    monkeypatch.setattr(module, "persist_analysis_artifacts", write_summary)

    _job(tmp_path, session_dir, [], overwrite=True).run()
    analysis = session_dir / "analysis"
    assert (analysis / "correlation.json").read_text(encoding="utf-8") == "first"

    content["value"] = "second"
    _job(tmp_path, session_dir, [], overwrite=True).run()
    assert (analysis / "correlation.json").read_text(encoding="utf-8") == "second"
    assert not list(session_dir.glob(".analysis-backup-*"))

    def fail_after_partial_write(*args, **kwargs):
        output = Path(kwargs["output_dir"])
        output.mkdir(parents=True)
        (output / "correlation.json").write_text("partial", encoding="utf-8")
        raise RuntimeError("reanalysis failed")

    monkeypatch.setattr(module, "run_analysis", fail_after_partial_write)
    with pytest.raises(RuntimeError, match="reanalysis failed"):
        _job(tmp_path, session_dir, [], overwrite=True).run()

    assert (analysis / "correlation.json").read_text(encoding="utf-8") == "second"
    assert not list(session_dir.glob(".analysis-staging-*"))
    assert store.get(manifest.session_id).state is JobState.COMPLETED


def test_manifest_completion_failure_rolls_back_published_analysis(
    tmp_path, monkeypatch
):
    import traffictracer.analyze.job as module

    store, manifest, session_dir = _capturing_session(tmp_path)
    (session_dir / "raw").mkdir()

    def write_analysis(*args, **kwargs):
        output = Path(kwargs["output_dir"])
        output.mkdir(parents=True)
        correlation = output / "correlation.json"
        correlation.write_text("validated", encoding="utf-8")
        return str(correlation)

    original_save = SessionStore.save

    def fail_completed(self, candidate):
        if candidate.state is JobState.COMPLETED:
            raise OSError("manifest fsync failed")
        return original_save(self, candidate)

    monkeypatch.setattr(module, "run_analysis", write_analysis)
    monkeypatch.setattr(SessionStore, "save", fail_completed)

    with pytest.raises(OSError, match="manifest fsync failed"):
        _job(
            tmp_path,
            session_dir,
            [],
            overwrite=True,
            write_flow_index=False,
        ).run()

    assert not (session_dir / "analysis").exists()
    failed = store.get(manifest.session_id)
    assert failed.state is JobState.FAILED
    assert all(artifact.phase != "analysis" for artifact in failed.artifacts)

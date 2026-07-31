"""Lifecycle tests for progress-aware analysis jobs."""

from datetime import datetime, timezone
from pathlib import Path
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

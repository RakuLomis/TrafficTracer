"""Tests for versioned Complete Session manifests."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from traffictracer.jobs.models import JobState
from traffictracer.session.manifest import (
    Artifact,
    ComponentVersion,
    ComponentVersions,
    SessionError,
    SessionManifest,
    SessionTarget,
    SessionTransitionError,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "session-valid.json"
BASE_TIME = datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)


def _versions():
    return ComponentVersions(
        traffictracer=ComponentVersion("0.1.0-dev", "unknown"),
        mihomo=ComponentVersion("complete", "unknown"),
        clash_verge_rev=ComponentVersion("complete", "unknown"),
    )


def _manifest():
    return SessionManifest.create(
        session_id="5027aee9-c6e4-41de-8625-7ea0869a3307",
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        session_dir="/tmp/traffictracer/sessions/20260731-example",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=_versions(),
        now=BASE_TIME,
    )


def test_golden_manifest_loads_and_round_trips():
    with FIXTURE.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    manifest = SessionManifest.from_dict(payload)
    assert manifest.to_dict() == payload
    assert SessionManifest.load(FIXTURE) == manifest


def test_capture_and_analysis_happy_path_sets_timestamps():
    created = _manifest()
    preparing = created.transition(JobState.PREPARING, now=BASE_TIME + timedelta(seconds=1))
    capturing = preparing.transition(JobState.CAPTURING, now=BASE_TIME + timedelta(seconds=2))
    analyzing = capturing.transition(JobState.ANALYZING, now=BASE_TIME + timedelta(seconds=3))
    completed = analyzing.transition(JobState.COMPLETED, now=BASE_TIME + timedelta(seconds=4))
    assert preparing.started_at == BASE_TIME + timedelta(seconds=1)
    assert completed.completed_at == BASE_TIME + timedelta(seconds=4)
    assert completed.state.terminal


def test_capture_can_complete_without_analysis():
    completed = (
        _manifest()
        .transition(JobState.PREPARING, now=BASE_TIME + timedelta(seconds=1))
        .transition(JobState.CAPTURING, now=BASE_TIME + timedelta(seconds=2))
        .transition(JobState.COMPLETED, now=BASE_TIME + timedelta(seconds=3))
    )
    assert completed.state is JobState.COMPLETED


@pytest.mark.parametrize(
    "terminal",
    [JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED, JobState.INTERRUPTED],
)
def test_terminal_sessions_cannot_reenter_capturing(terminal):
    manifest = _manifest().transition(JobState.PREPARING, now=BASE_TIME + timedelta(seconds=1))
    if terminal is JobState.COMPLETED:
        manifest = manifest.transition(JobState.CAPTURING, now=BASE_TIME + timedelta(seconds=2))
        manifest = manifest.transition(terminal, now=BASE_TIME + timedelta(seconds=3))
    elif terminal is JobState.FAILED:
        manifest = manifest.transition(
            terminal,
            error=SessionError("CAPTURE_FAILED", "fixture failure", "preparing"),
            now=BASE_TIME + timedelta(seconds=2),
        )
    else:
        manifest = manifest.transition(terminal, now=BASE_TIME + timedelta(seconds=2))
    with pytest.raises(SessionTransitionError, match="invalid Session transition"):
        manifest.transition(JobState.CAPTURING, now=BASE_TIME + timedelta(seconds=4))


def test_invalid_transitions_and_error_semantics_are_rejected():
    with pytest.raises(SessionTransitionError, match="created -> capturing"):
        _manifest().transition(JobState.CAPTURING)
    preparing = _manifest().transition(JobState.PREPARING)
    with pytest.raises(SessionTransitionError, match="requires an error"):
        preparing.transition(JobState.FAILED)
    with pytest.raises(SessionTransitionError, match="only valid"):
        preparing.transition(JobState.CANCELLED, error=SessionError("X", "bad"))


def test_artifacts_and_warnings_are_immutable_additions():
    manifest = _manifest()
    artifact = Artifact(
        name="correlation",
        kind="derived",
        phase="analysis",
        generation_id="78fdab68-4e5d-4b67-9910-33da00a2632a",
        path="analysis/correlation.json",
        media_type="application/json",
        size_bytes=42,
        sha256="a" * 64,
        created_at=BASE_TIME,
    )
    updated = manifest.with_artifact(artifact, now=BASE_TIME + timedelta(seconds=1))
    updated = updated.with_warning("partial attribution", now=BASE_TIME + timedelta(seconds=2))
    assert manifest.artifacts == ()
    assert updated.artifacts == (artifact,)
    assert updated.warnings == ("partial attribution",)
    assert updated.to_dict()["artifacts"][0]["path"] == "analysis/correlation.json"


def test_manifest_updates_cannot_move_time_backward():
    manifest = _manifest().transition(JobState.PREPARING, now=BASE_TIME + timedelta(seconds=2))
    with pytest.raises(ValueError, match="cannot move backward"):
        manifest.with_warning("late arrival", now=BASE_TIME + timedelta(seconds=1))


@pytest.mark.parametrize(
    ("path", "role"),
    [
        ("raw/capture-context.json", "capture_context"),
        ("raw/mihomo-trace.jsonl", "mihomo_trace"),
        ("raw/netlog.json", "netlog"),
        ("raw/cdp.json", "cdp_events"),
    ],
)
def test_normalized_capture_artifact_names_have_stable_roles(path, role):
    artifact = Artifact(
        name=Path(path).name,
        kind="raw",
        phase="capture",
        path=path,
        media_type="application/json",
        size_bytes=1,
    )

    assert artifact.to_dict()["role"] == role

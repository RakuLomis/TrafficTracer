"""Tests for single-active-job Worker background management."""

import json
from pathlib import Path
from threading import Event

import pytest

from traffictracer.capture.quiescence import (
    ChromeCleanupIncomplete,
    ChromeQuiescenceReport,
)
from traffictracer.contracts import validate_worker_message
from traffictracer.jobs.models import CaptureJobResult, JobState
from traffictracer.jobs.progress import JobStage
from traffictracer.worker.dispatcher import Dispatcher, WorkerMethodError
from traffictracer.worker.job_manager import JobManager


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid.json"
ANALYSIS_FIXTURE = (
    ROOT / "test" / "fixtures" / "contracts" / "job-valid-analysis.json"
)


def _payload(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


class ImmediateJob:
    def __init__(self, spec, progress, token):
        self.spec = spec
        self.progress = progress

    def run(self):
        state = JobState.CAPTURING if self.spec.kind == "capture" else JobState.ANALYZING
        stage = JobStage.CAPTURE_BROWSER if self.spec.kind == "capture" else JobStage.ANALYZE_WRITE
        self.progress.emit(state, stage, 0.5)
        return CaptureJobResult(
            job_id=self.spec.job_id,
            state=JobState.COMPLETED,
            session_id="session-1",
            artifacts=("results/correlation.json",),
        )


class BlockingJob:
    def __init__(self, spec, progress, token, started, release):
        self.spec = spec
        self.token = token
        self.started = started
        self.release = release

    def run(self):
        self.started.set()
        while not self.release.wait(0.01):
            self.token.checkpoint()
        self.token.checkpoint()
        return CaptureJobResult(self.spec.job_id, JobState.COMPLETED)


def _manager(notifications, capture_factory=None, analysis_factory=None):
    factory = lambda spec, progress, token: ImmediateJob(spec, progress, token)
    return JobManager(
        capture_factory=capture_factory or factory,
        analysis_factory=analysis_factory or factory,
        notify=notifications.append,
    )


def test_capture_and_analysis_start_status_complete_and_notify():
    notifications = []
    manager = _manager(notifications)
    capture = _payload(CAPTURE_FIXTURE)
    started = manager.start_capture({"job": capture})
    assert started["job_id"] == capture["job_id"]
    assert manager.wait(capture["job_id"], timeout=2)
    completed = manager.status({"job_id": capture["job_id"]})
    assert completed["state"] == "completed"
    assert completed["result"]["artifacts"] == ["results/correlation.json"]

    analysis = _payload(ANALYSIS_FIXTURE)
    manager.start_analysis(analysis)
    assert manager.wait(analysis["job_id"], timeout=2)
    assert manager.status({"job_id": analysis["job_id"]})["kind"] == "analysis"
    assert any(item["method"] == "job.progress" for item in notifications)
    assert sum(item["method"] == "job.completed" for item in notifications) == 2
    assert all(validate_worker_message(item) is item for item in notifications)


def test_second_job_is_rejected_with_stable_busy_error():
    notifications = []
    started = Event()
    release = Event()

    def blocking(spec, progress, token):
        return BlockingJob(spec, progress, token, started, release)

    manager = _manager(notifications, capture_factory=blocking)
    capture = _payload(CAPTURE_FIXTURE)
    manager.start_capture(capture)
    assert started.wait(1)
    with pytest.raises(WorkerMethodError) as caught:
        manager.start_analysis(_payload(ANALYSIS_FIXTURE))
    assert caught.value.code == "JOB_BUSY"
    assert caught.value.data["active_job_id"] == capture["job_id"]
    release.set()
    assert manager.wait(capture["job_id"], timeout=2)


def test_cancel_is_idempotent_and_job_becomes_cancelled():
    notifications = []
    started = Event()
    release = Event()

    def blocking(spec, progress, token):
        return BlockingJob(spec, progress, token, started, release)

    manager = _manager(notifications, capture_factory=blocking)
    capture = _payload(CAPTURE_FIXTURE)
    manager.start_capture(capture)
    assert started.wait(1)
    first = manager.cancel({"job_id": capture["job_id"], "reason": "stop now"})
    second = manager.cancel({"job_id": capture["job_id"], "reason": "again"})
    assert first["cancel_requested_now"] is True
    assert second["cancel_requested_now"] is False
    assert manager.wait(capture["job_id"], timeout=2)
    status = manager.status({"job_id": capture["job_id"]})
    assert status["state"] == "cancelled"
    assert status["error"]["code"] == "CANCELLED"


def test_generic_interrupt_is_idempotent_and_job_becomes_interrupted():
    notifications = []
    started = Event()
    release = Event()

    def blocking(spec, progress, token):
        return BlockingJob(spec, progress, token, started, release)

    manager = _manager(notifications, capture_factory=blocking)
    dispatcher = Dispatcher(manager.handlers())
    capture = _payload(CAPTURE_FIXTURE)
    manager.start_capture(capture)
    assert started.wait(1)

    first = dispatcher.dispatch({
        "api_version": 2,
        "type": "request",
        "id": "interrupt-one",
        "method": "job.interrupt",
        "params": {"job_id": capture["job_id"], "reason": "pause now"},
    })
    second = manager.interrupt({"job_id": capture["job_id"], "reason": "again"})

    assert first["result"]["interrupt_requested_now"] is True
    assert second["interrupt_requested_now"] is False
    assert manager.wait(capture["job_id"], timeout=2)
    status = manager.status({"job_id": capture["job_id"]})
    assert status["state"] == "interrupted"
    assert status["error"]["code"] == "INTERRUPTED"


def test_failed_job_is_observable_and_does_not_block_next_job():
    notifications = []

    class FailingJob:
        def run(self):
            raise RuntimeError("private failure")

    manager = _manager(
        notifications,
        capture_factory=lambda spec, progress, token: FailingJob(),
    )
    capture = _payload(CAPTURE_FIXTURE)
    manager.start_capture(capture)
    assert manager.wait(capture["job_id"], timeout=2)
    failed = manager.status({"job_id": capture["job_id"]})
    assert failed["state"] == "failed"
    assert failed["error"]["code"] == "INTERNAL_ERROR"
    assert "private failure" not in failed["error"]["message"]

    analysis = _payload(ANALYSIS_FIXTURE)
    manager.start_analysis(analysis)
    assert manager.wait(analysis["job_id"], timeout=2)


def test_chrome_cleanup_failure_keeps_its_public_error_code():
    class ResidualChromeJob:
        def run(self):
            raise ChromeCleanupIncomplete(
                ChromeQuiescenceReport("/tmp/profile", True, (321,))
            )

    manager = _manager(
        [],
        capture_factory=lambda spec, progress, token: ResidualChromeJob(),
    )
    capture = _payload(CAPTURE_FIXTURE)
    manager.start_capture(capture)
    assert manager.wait(capture["job_id"], timeout=2)

    failed = manager.status({"job_id": capture["job_id"]})
    assert failed["state"] == "failed"
    assert failed["error"]["code"] == "CHROME_CLEANUP_INCOMPLETE"


def test_terminal_state_is_not_visible_before_result_is_published():
    progress_finished = Event()
    release = Event()

    class FinishingJob:
        def __init__(self, spec, progress):
            self.spec = spec
            self.progress = progress

        def run(self):
            self.progress.finish(JobState.COMPLETED, "runner finished")
            progress_finished.set()
            assert release.wait(2)
            return CaptureJobResult(self.spec.job_id, JobState.COMPLETED)

    manager = _manager(
        [],
        capture_factory=lambda spec, progress, token: FinishingJob(spec, progress),
    )
    capture = _payload(CAPTURE_FIXTURE)
    manager.start_capture(capture)
    assert progress_finished.wait(1)
    in_flight = manager.status({"job_id": capture["job_id"]})
    assert in_flight["state"] != "completed"
    assert "result" not in in_flight
    release.set()
    assert manager.wait(capture["job_id"], timeout=2)
    completed = manager.status({"job_id": capture["job_id"]})
    assert completed["state"] == "completed"
    assert completed["result"]["state"] == "completed"


def test_dispatcher_handlers_and_unknown_job_error_are_stable():
    notifications = []
    manager = _manager(notifications)
    dispatcher = Dispatcher(manager.handlers())
    capture = _payload(CAPTURE_FIXTURE)
    response = dispatcher.dispatch({
        "api_version": 2,
        "type": "request",
        "id": "start",
        "method": "job.start",
        "params": {"job": capture},
    })
    assert "result" in response
    assert manager.wait(capture["job_id"], timeout=2)
    with pytest.raises(WorkerMethodError) as caught:
        manager.status({"job_id": "missing"})
    assert caught.value.code == "JOB_NOT_FOUND"


def test_shutdown_cancels_active_job_and_notification_failure_is_isolated():
    started = Event()
    release = Event()

    def blocking(spec, progress, token):
        return BlockingJob(spec, progress, token, started, release)

    manager = JobManager(
        capture_factory=blocking,
        analysis_factory=blocking,
        notify=lambda message: (_ for _ in ()).throw(BrokenPipeError()),
    )
    capture = _payload(CAPTURE_FIXTURE)
    manager.start_capture(capture)
    assert started.wait(1)
    assert manager.shutdown(timeout=2)
    assert manager.status({"job_id": capture["job_id"]})["state"] == "cancelled"

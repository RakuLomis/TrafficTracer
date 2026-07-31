"""Tests for structured Complete job progress reporting."""

import pytest

from traffictracer.jobs.models import JobState
from traffictracer.jobs.progress import JobStage, ProgressInvariantError, ProgressReporter


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def test_stage_transitions_and_progress_are_monotonic():
    events = []
    reporter = ProgressReporter("job-1", events.append, min_interval=0)
    reporter.emit(JobState.PREPARING, JobStage.PREPARING, 0.1)
    reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_PACKETS, 0.3)
    reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.6)
    assert [event.stage for event in events] == [
        "preparing",
        "capture.packets",
        "capture.browser",
    ]
    assert reporter.stage is JobStage.CAPTURE_BROWSER
    assert reporter.progress == 0.6


def test_stage_and_progress_regressions_are_rejected():
    reporter = ProgressReporter("job-1", lambda event: None)
    reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.6)
    with pytest.raises(ProgressInvariantError, match="stage cannot move backward"):
        reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_PACKETS, 0.7)
    with pytest.raises(ProgressInvariantError, match="progress cannot move backward"):
        reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.5)
    with pytest.raises(ProgressInvariantError, match="finite"):
        reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_BROWSER, float("nan"))


def test_high_frequency_messages_are_throttled_but_stage_changes_are_not():
    events = []
    clock = FakeClock()
    reporter = ProgressReporter("job-1", events.append, min_interval=1.0, clock=clock)
    assert reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_PACKETS, 0.1) is not None
    clock.advance(0.1)
    assert reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_PACKETS, 0.2) is None
    assert reporter.progress == 0.2
    assert reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.3) is not None
    clock.advance(1.0)
    assert reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.4) is not None
    assert [event.progress for event in events] == [0.1, 0.3, 0.4]


def test_final_event_is_forced_and_no_events_follow_it():
    events = []
    clock = FakeClock()
    reporter = ProgressReporter("job-1", events.append, min_interval=10, clock=clock)
    reporter.emit(JobState.CAPTURING, JobStage.CAPTURE_PACKETS, 0.5)
    final = reporter.finish(JobState.CANCELLED, "cancelled by user")
    assert final.stage == "finished"
    assert final.progress == 1.0
    assert final.state is JobState.CANCELLED
    assert len(events) == 2
    with pytest.raises(ProgressInvariantError, match="after the final"):
        reporter.emit(JobState.CANCELLED, JobStage.FINISHED, 1.0)


def test_finish_requires_terminal_state():
    reporter = ProgressReporter("job-1", lambda event: None)
    with pytest.raises(ProgressInvariantError, match="terminal"):
        reporter.finish(JobState.CAPTURING)

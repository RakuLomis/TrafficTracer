"""Structured, monotonic and throttled Complete job progress events."""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
import math
from threading import Lock
import time

from .models import JobState, ProgressEvent


class JobStage(str, Enum):
    CREATED = "created"
    PREPARING = "preparing"
    CORE_CONFIGURE = "core.configure"
    CAPTURE_PACKETS = "capture.packets"
    CAPTURE_BROWSER = "capture.browser"
    CLEANUP = "cleanup"
    ANALYZE_CDP = "analyze.cdp"
    ANALYZE_NETLOG = "analyze.netlog"
    ANALYZE_MIHOMO = "analyze.mihomo"
    ANALYZE_CORRELATE = "analyze.correlate"
    ANALYZE_SPLIT = "analyze.split"
    ANALYZE_WRITE = "analyze.write"
    BATCH_TARGET = "batch.target"
    FINISHED = "finished"


_STAGE_ORDER = {stage: index for index, stage in enumerate(JobStage)}


class ProgressInvariantError(ValueError):
    """Raised when a caller attempts a stage or progress regression."""


class ProgressReporter:
    """Validate and emit progress for one job through a supplied callback."""

    def __init__(
        self,
        job_id: str,
        callback: Callable[[ProgressEvent], None],
        *,
        min_interval: float = 0.1,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not job_id:
            raise ValueError("job_id must not be empty")
        if min_interval < 0:
            raise ValueError("min_interval must be non-negative")
        self._job_id = job_id
        self._callback = callback
        self._min_interval = min_interval
        self._clock = clock
        self._lock = Lock()
        self._stage: JobStage | None = None
        self._progress = 0.0
        self._last_emitted_at: float | None = None
        self._finished = False
        self._started_at = self._clock()
        self._stage_started_at: float | None = None
        self._operation = ""
        self._operation_started_at: float | None = None

    @property
    def stage(self) -> JobStage | None:
        with self._lock:
            return self._stage

    @property
    def progress(self) -> float:
        with self._lock:
            return self._progress

    def emit(
        self,
        state: JobState,
        stage: JobStage,
        progress: float,
        message: str = "",
        *,
        force: bool = False,
        operation: str = "",
    ) -> ProgressEvent | None:
        if not math.isfinite(progress) or not 0 <= progress <= 1:
            raise ProgressInvariantError("progress must be a finite number between 0 and 1")
        if not isinstance(operation, str):
            raise ProgressInvariantError("operation must be a string")
        with self._lock:
            if self._finished:
                raise ProgressInvariantError("progress cannot be emitted after the final event")
            if self._stage is not None and _STAGE_ORDER[stage] < _STAGE_ORDER[self._stage]:
                raise ProgressInvariantError(
                    f"stage cannot move backward from {self._stage.value} to {stage.value}"
                )
            if progress < self._progress:
                raise ProgressInvariantError(
                    f"progress cannot move backward from {self._progress} to {progress}"
                )

            now = self._clock()
            previous_stage = self._stage
            previous_stage_started_at = self._stage_started_at
            previous_operation = self._operation
            previous_operation_started_at = self._operation_started_at
            stage_changed = stage != self._stage
            effective_operation = operation.strip() or stage.value
            operation_changed = effective_operation != self._operation
            if stage_changed or self._stage_started_at is None:
                self._stage_started_at = now
            if operation_changed or self._operation_started_at is None:
                self._operation_started_at = now
            self._stage = stage
            self._operation = effective_operation
            self._progress = progress
            terminal = state.terminal or stage is JobStage.FINISHED or progress == 1
            throttled = (
                not force
                and not stage_changed
                and not operation_changed
                and not terminal
                and self._last_emitted_at is not None
                and now - self._last_emitted_at < self._min_interval
            )
            if throttled:
                return None
            timing = {
                "job_elapsed_ms": _duration_ms(self._started_at, now),
                "stage_elapsed_ms": _duration_ms(self._stage_started_at, now),
                "operation": effective_operation,
                "operation_elapsed_ms": _duration_ms(
                    self._operation_started_at, now
                ),
            }
            if stage_changed and previous_stage is not None:
                timing["completed_stage"] = previous_stage.value
                timing["completed_stage_duration_ms"] = _duration_ms(
                    previous_stage_started_at, now
                )
            if operation_changed and previous_operation:
                timing["completed_operation"] = previous_operation
                timing["completed_operation_duration_ms"] = _duration_ms(
                    previous_operation_started_at, now
                )
            event = ProgressEvent(
                job_id=self._job_id,
                state=state,
                stage=stage.value,
                progress=progress,
                message=message,
                timing=timing,
            )
            self._last_emitted_at = now
            if terminal:
                self._finished = True

        self._callback(event)
        return event

    def finish(self, state: JobState, message: str = "") -> ProgressEvent:
        if not state.terminal:
            raise ProgressInvariantError("final progress requires a terminal JobState")
        event = self.emit(state, JobStage.FINISHED, 1.0, message, force=True)
        assert event is not None
        return event


class ProgressWindow:
    """Map a child pipeline's 0..1 progress into a monotonic parent window."""

    def __init__(self, reporter: ProgressReporter, start: float, end: float) -> None:
        if not 0 <= start < end <= 1:
            raise ValueError("progress window requires 0 <= start < end <= 1")
        self._reporter = reporter
        self._start = start
        self._span = end - start

    @property
    def stage(self) -> JobStage | None:
        return self._reporter.stage

    @property
    def progress(self) -> float:
        return self._reporter.progress

    def emit(
        self,
        state: JobState,
        stage: JobStage,
        progress: float,
        message: str = "",
        *,
        force: bool = False,
        operation: str = "",
    ) -> ProgressEvent | None:
        if not math.isfinite(progress) or not 0 <= progress <= 1:
            raise ProgressInvariantError(
                "child progress must be a finite number between 0 and 1"
            )
        mapped = self._start + self._span * progress
        return self._reporter.emit(
            state,
            stage,
            mapped,
            message,
            force=force,
            operation=operation,
        )

    def finish(self, state: JobState, message: str = "") -> ProgressEvent:
        return self._reporter.finish(state, message)


def _duration_ms(started_at: float | None, now: float) -> int:
    if started_at is None:
        return 0
    return max(0, int(round((now - started_at) * 1000)))

"""Single-active-job background manager for capture and analysis Worker methods."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import Event, Lock, Thread
from typing import Any, Protocol

from traffictracer.capture.tshark import PacketCaptureError
from traffictracer.capture.quiescence import ChromeCleanupIncomplete
from traffictracer.contracts import validate_worker_message
from traffictracer.jobs.cancellation import (
    CancellationToken,
    CancelledError,
    InterruptedError,
)
from traffictracer.jobs.batch_models import BatchJobResult, BatchJobSpec
from traffictracer.jobs.models import (
    AnalysisJobSpec,
    CaptureJobResult,
    CaptureJobSpec,
    JobState,
    ProgressEvent,
)
from traffictracer.jobs.packet_split import (
    PacketSplitGroupResult,
    PacketSplitGroupSpec,
)
from traffictracer.jobs.progress import ProgressReporter
from traffictracer.utils import logger
from traffictracer.version import WORKER_API_VERSION

from .dispatcher import WorkerMethodError


class RunnableJob(Protocol):
    def run(self) -> CaptureJobResult | BatchJobResult | PacketSplitGroupResult: ...


JobFactory = Callable[
    [CaptureJobSpec | AnalysisJobSpec | BatchJobSpec | PacketSplitGroupSpec, ProgressReporter, CancellationToken],
    RunnableJob,
]
NotificationCallback = Callable[[dict[str, Any]], None]


@dataclass
class _ManagedJob:
    job_id: str
    kind: str
    token: CancellationToken
    state: JobState = JobState.CREATED
    stage: str = "created"
    progress: float = 0.0
    message: str = ""
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    thread: Thread | None = None
    done: Event | None = None

    def snapshot(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "job_id": self.job_id,
            "kind": self.kind,
            "state": self.state.value,
            "stage": self.stage,
            "progress": self.progress,
            "message": self.message,
            "cancel_requested": (
                self.token.cancelled and not self.token.interrupted
            ),
            "interrupt_requested": self.token.interrupted,
        }
        if self.result is not None:
            payload["result"] = dict(self.result)
        if self.error is not None:
            payload["error"] = dict(self.error)
        return payload


class JobManager:
    def __init__(
        self,
        *,
        capture_factory: JobFactory,
        analysis_factory: JobFactory,
        notify: NotificationCallback,
        batch_factory: JobFactory | None = None,
        packet_split_factory: JobFactory | None = None,
    ) -> None:
        self._capture_factory = capture_factory
        self._analysis_factory = analysis_factory
        self._batch_factory = batch_factory
        self._packet_split_factory = packet_split_factory
        self._notify = notify
        self._lock = Lock()
        self._jobs: dict[str, _ManagedJob] = {}
        self._active_job_id: str | None = None

    def handlers(self) -> dict[str, Callable[[dict[str, Any]], dict[str, Any]]]:
        return {
            "job.start": self.start_capture,
            "analysis.start": self.start_analysis,
            "packet_split.start": self.start_packet_split,
            "job.cancel": self.cancel,
            "job.status": self.status,
        }

    def start_capture(self, params: dict[str, Any]) -> dict[str, Any]:
        payload = _job_payload(params)
        return self._start(CaptureJobSpec.from_dict(payload), self._capture_factory)

    def start_analysis(self, params: dict[str, Any]) -> dict[str, Any]:
        payload = _job_payload(params)
        return self._start(AnalysisJobSpec.from_dict(payload), self._analysis_factory)

    def start_packet_split(
        self, params: dict[str, Any], *, resume: bool = False
    ) -> dict[str, Any]:
        if self._packet_split_factory is None:
            raise WorkerMethodError(
                "METHOD_NOT_FOUND", "Packet split group Jobs are unavailable."
            )
        spec = PacketSplitGroupSpec.from_dict(_job_payload(params))
        return self._start(
            spec,
            self._packet_split_factory,
            allow_terminal_reuse=resume,
        )

    def start_batch(
        self,
        params: dict[str, Any],
        *,
        resume: bool = False,
        prepare: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if self._batch_factory is None:
            raise WorkerMethodError("METHOD_NOT_FOUND", "Batch Jobs are unavailable.")
        payload = _job_payload(params)
        spec = BatchJobSpec.from_dict(payload)
        factory = self._batch_factory
        if resume:
            factory = lambda item, progress, token: self._batch_factory(
                item, progress, token, resume=True
            )
        return self._start(
            spec,
            factory,
            allow_terminal_reuse=resume,
            prepare=prepare,
        )

    def maybe_status(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            managed = self._jobs.get(job_id)
            return managed.snapshot() if managed is not None else None

    def status(self, params: dict[str, Any]) -> dict[str, Any]:
        job_id = _required_job_id(params)
        with self._lock:
            managed = self._jobs.get(job_id)
            if managed is None:
                raise WorkerMethodError(
                    "JOB_NOT_FOUND", "The requested Job does not exist."
                )
            return managed.snapshot()

    def cancel(self, params: dict[str, Any]) -> dict[str, Any]:
        job_id = _required_job_id(params)
        reason = params.get("reason", "Cancelled by user.")
        if not isinstance(reason, str):
            raise WorkerMethodError("INVALID_PARAMS", "reason must be a string.")
        with self._lock:
            managed = self._jobs.get(job_id)
            if managed is None:
                raise WorkerMethodError(
                    "JOB_NOT_FOUND", "The requested Job does not exist."
                )
            requested = False
            if not managed.state.terminal:
                requested = managed.token.cancel(reason)
            snapshot = managed.snapshot()
            snapshot["cancel_requested_now"] = requested
            return snapshot

    def interrupt(self, params: dict[str, Any]) -> dict[str, Any]:
        job_id = _required_job_id(params)
        reason = params.get("reason", "Interrupted by user.")
        if not isinstance(reason, str):
            raise WorkerMethodError("INVALID_PARAMS", "reason must be a string.")
        with self._lock:
            managed = self._jobs.get(job_id)
            if managed is None:
                raise WorkerMethodError(
                    "JOB_NOT_FOUND", "The requested Job does not exist."
                )
            requested = False
            if not managed.state.terminal:
                requested = managed.token.interrupt(reason)
            snapshot = managed.snapshot()
            snapshot["interrupt_requested_now"] = requested
            return snapshot

    def wait(self, job_id: str, timeout: float | None = None) -> bool:
        with self._lock:
            managed = self._jobs.get(job_id)
            if managed is None:
                raise WorkerMethodError(
                    "JOB_NOT_FOUND", "The requested Job does not exist."
                )
            done = managed.done
        assert done is not None
        return done.wait(timeout)

    def shutdown(self, timeout: float = 5.0) -> bool:
        with self._lock:
            active = self._jobs.get(self._active_job_id or "")
            if active is None:
                return True
            active.token.cancel("Worker shutdown.")
            done = active.done
        assert done is not None
        return done.wait(timeout)

    def _start(
        self,
        spec: CaptureJobSpec | AnalysisJobSpec | BatchJobSpec | PacketSplitGroupSpec,
        factory: JobFactory,
        *,
        allow_terminal_reuse: bool = False,
        prepare: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        token = CancellationToken()
        done = Event()
        managed = _ManagedJob(spec.job_id, spec.kind, token, done=done)
        with self._lock:
            if self._active_job_id is not None:
                active = self._jobs[self._active_job_id]
                if not active.state.terminal:
                    raise WorkerMethodError(
                        "JOB_BUSY",
                        "Another capture or analysis Job is already active.",
                        {"active_job_id": active.job_id},
                    )
            if spec.job_id in self._jobs:
                previous = self._jobs[spec.job_id]
                if not allow_terminal_reuse or not previous.state.terminal:
                    raise WorkerMethodError(
                        "INVALID_PARAMS", "job_id has already been used."
                    )
            # Batch callers use this hook to persist their initial manifest
            # while the manager lock still prevents another Job from being
            # accepted. The returned snapshot is immediately queryable.
            if prepare is not None:
                prepare()

            thread = Thread(
                target=self._run_job,
                args=(managed, spec, factory),
                name=f"traffictracer-{spec.kind}-{spec.job_id}",
                daemon=True,
            )
            managed.thread = thread
            self._jobs[spec.job_id] = managed
            self._active_job_id = spec.job_id
            snapshot = managed.snapshot()
        self._emit("job.state_changed", snapshot)
        thread.start()
        return snapshot

    def _run_job(
        self,
        managed: _ManagedJob,
        spec: CaptureJobSpec | AnalysisJobSpec,
        factory: JobFactory,
    ) -> None:
        reporter = ProgressReporter(
            managed.job_id,
            lambda event: self._on_progress(managed.job_id, event),
            min_interval=0.1,
        )
        try:
            runnable = factory(spec, reporter, managed.token)
            result = runnable.run()
        except InterruptedError as exc:
            self._finish_job(
                managed.job_id,
                JobState.INTERRUPTED,
                message=str(exc) or "Job interrupted.",
                error={
                    "code": "INTERRUPTED",
                    "message": str(exc) or "Job interrupted.",
                },
            )
        except CancelledError as exc:
            self._finish_job(
                managed.job_id,
                JobState.CANCELLED,
                message=str(exc) or "Job cancelled.",
                error={"code": "CANCELLED", "message": str(exc) or "Job cancelled."},
            )
        except PacketCaptureError as exc:
            code = (
                "CAPTURE_PERMISSION_DENIED"
                if exc.code == "CAPTURE_PERMISSION_DENIED"
                else "INTERNAL_ERROR"
            )
            self._finish_job(
                managed.job_id,
                JobState.FAILED,
                message="Packet capture failed.",
                error={"code": code, "message": exc.message},
            )
        except ChromeCleanupIncomplete as exc:
            self._finish_job(
                managed.job_id,
                JobState.FAILED,
                message="Chrome cleanup did not reach quiescence.",
                error={"code": exc.code, "message": str(exc)},
            )
        except Exception:
            self._finish_job(
                managed.job_id,
                JobState.FAILED,
                message="Job execution failed.",
                error={
                    "code": "INTERNAL_ERROR",
                    "message": "The Worker could not complete the Job.",
                },
            )
        else:
            self._finish_job(
                managed.job_id,
                result.state,
                message="Job complete.",
                result=result.to_dict(),
            )

    def _on_progress(self, job_id: str, event: ProgressEvent) -> None:
        with self._lock:
            managed = self._jobs.get(job_id)
            if managed is None:
                return
            # A runner can emit its final progress before returning its result.
            # Publish terminal state only in _finish_job so status never exposes
            # "completed" without the corresponding result (or failure error).
            if not event.state.terminal:
                managed.state = event.state
            managed.stage = event.stage
            managed.progress = event.progress
            managed.message = event.message
        self._emit("job.progress", event.to_dict())

    def _finish_job(
        self,
        job_id: str,
        state: JobState,
        *,
        message: str,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        if not state.terminal:
            state = JobState.FAILED
            result = None
            error = {
                "code": "INTERNAL_ERROR",
                "message": "Job runner returned a non-terminal state.",
            }
        with self._lock:
            managed = self._jobs[job_id]
            managed.state = state
            managed.stage = "finished"
            managed.progress = 1.0
            managed.message = message
            managed.result = result
            managed.error = error
            if self._active_job_id == job_id:
                self._active_job_id = None
            snapshot = managed.snapshot()
            done = managed.done
        self._emit("job.state_changed", snapshot)
        self._emit("job.completed", snapshot)
        assert done is not None
        done.set()

    def _emit(self, method: str, params: dict[str, Any]) -> None:
        notification = {
            "api_version": WORKER_API_VERSION,
            "type": "notification",
            "method": method,
            "params": params,
        }
        validate_worker_message(notification)
        try:
            self._notify(notification)
        except Exception as exc:
            logger.error("Worker notification delivery failed: %s", exc)


def _job_payload(params: dict[str, Any]) -> Mapping[str, Any]:
    payload = params.get("job", params)
    if not isinstance(payload, Mapping):
        raise WorkerMethodError("INVALID_PARAMS", "job must be an object.")
    return payload


def _required_job_id(params: dict[str, Any]) -> str:
    job_id = params.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        raise WorkerMethodError(
            "INVALID_PARAMS", "job_id must be a non-empty string."
        )
    return job_id

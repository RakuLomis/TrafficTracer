"""Strictly serial capture -> quiescence -> analysis batch execution."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Protocol
from uuid import UUID, uuid5

from traffictracer.layout import group_directory_name


from .batch_models import (
    BATCH_MANIFEST_NAME,
    BatchChildState,
    BatchError,
    BatchJobResult,
    BatchJobSpec,
    BatchManifest,
    BatchStage,
    BatchState,
    BatchTarget,
)
from .cancellation import CancellationToken, CancelledError, InterruptedError
from .errors import exception_message
from .models import CaptureJobResult, CaptureJobSpec, JobState, TargetSource
from .progress import JobStage, ProgressEvent, ProgressReporter


class ChildRunnable(Protocol):
    def run(self) -> CaptureJobResult: ...


ChildFactory = Callable[
    [CaptureJobSpec, ProgressReporter, CancellationToken],
    ChildRunnable,
]
SessionResolver = Callable[[str], str | None]


class SerialBatchJob:
    """Runs one child at a time and checkpoints before creating the next."""

    def __init__(
        self,
        spec: BatchJobSpec,
        *,
        child_factory: ChildFactory,
        progress: ProgressReporter,
        cancellation: CancellationToken,
        session_for_job: SessionResolver | None = None,
        resume: bool = False,
    ) -> None:
        self.spec = spec
        self.child_factory = child_factory
        self.progress = progress
        self.cancellation = cancellation
        self.session_for_job = session_for_job or (lambda job_id: None)
        self.resume = resume
        self.batch_dir = (
            Path(spec.output_root).resolve() / ".batches" / spec.job_id
        )
        self.manifest_path = self.batch_dir / BATCH_MANIFEST_NAME
        self.manifest: BatchManifest | None = None

    def run(self) -> BatchJobResult:
        self.spec.verify_config_sha256()
        manifest = self._load_or_create()
        if manifest.state is BatchState.CREATED:
            manifest = manifest.begin()
        elif manifest.state in {BatchState.FAILED, BatchState.INTERRUPTED}:
            if not self.resume:
                raise ValueError("batch resume must be explicitly requested")
            manifest = manifest.with_resume_policy(
                fail_fast=self.spec.fail_fast,
            ).begin()
        elif manifest.state is BatchState.COMPLETED:
            return self._result(manifest)
        else:
            raise ValueError(f"batch cannot run from {manifest.state.value}")
        self._save(manifest)

        try:
            while manifest.state is BatchState.RUNNING:
                manifest = manifest.skip_completed()
                self._save(manifest)
                if manifest.resume.next_index >= len(manifest.targets):
                    break
                self.cancellation.checkpoint()
                position = manifest.resume.next_index
                manifest = manifest.start_child(position)
                self._save(manifest)
                target = manifest.targets[position]
                child_spec = self._child_spec(
                    target,
                    position,
                    manifest.resume.attempt,
                    group_directory_name(manifest.created_at),
                )
                child_progress = _ChildProgress(
                    self.progress,
                    position,
                    len(manifest.targets),
                    self._record_child_stage,
                )
                try:
                    runnable = self.child_factory(
                        child_spec,
                        child_progress,
                        self.cancellation,
                    )
                    session_id = self.session_for_job(child_spec.job_id)
                    if session_id:
                        manifest = (self.manifest or manifest).attach_child_session(
                            session_id
                        )
                        self._save(manifest)
                    result = runnable.run()
                    if result.state is not JobState.COMPLETED:
                        raise RuntimeError(
                            f"child returned non-completed state {result.state.value}"
                        )
                except InterruptedError:
                    manifest = self.manifest or manifest
                    manifest = manifest.finish_child(
                        BatchChildState.INTERRUPTED,
                        session_id=self.session_for_job(child_spec.job_id),
                        error=BatchError(
                            "INTERRUPTED", self.cancellation.reason
                        ),
                    )
                    self._save(manifest)
                    raise
                except CancelledError:
                    manifest = self.manifest or manifest
                    manifest = manifest.request_cancel().finish_child(
                        BatchChildState.CANCELLED,
                        session_id=self.session_for_job(child_spec.job_id),
                        error=BatchError("CANCELLED", self.cancellation.reason),
                    )
                    self._save(manifest)
                    raise
                except Exception as exc:
                    manifest = self.manifest or manifest
                    code = getattr(exc, "code", "BATCH_CHILD_FAILED")
                    manifest = manifest.finish_child(
                        BatchChildState.FAILED,
                        session_id=self.session_for_job(child_spec.job_id),
                        error=BatchError(
                            str(code),
                            exception_message(exc, "batch child failed"),
                        ),
                    )
                    self._save(manifest)
                    if (
                        str(code) == "PROXY_PROTOCOL_INVARIANT_FAILED"
                        and manifest.state is BatchState.RUNNING
                    ):
                        manifest = manifest.stop(BatchState.FAILED)
                        self._save(manifest)
                    if manifest.state is BatchState.FAILED:
                        return self._result(manifest)
                    continue

                manifest = self.manifest or manifest
                manifest = manifest.set_stage(BatchStage.CHECKPOINT)
                self._save(manifest)
                manifest = manifest.finish_child(
                    BatchChildState.COMPLETED,
                    session_id=result.session_id or self.session_for_job(child_spec.job_id),
                )
                self._save(manifest)
        except InterruptedError:
            manifest = self.manifest or manifest
            if (
                manifest.state is BatchState.RUNNING
                and manifest.current_index is None
            ):
                self._save(manifest.stop(BatchState.INTERRUPTED))
            raise
        except CancelledError:
            manifest = self.manifest or manifest
            if manifest.state is BatchState.RUNNING and manifest.current_index is None:
                self._save(
                    manifest.request_cancel().stop(BatchState.CANCELLED)
                )
            raise
        except Exception:
            manifest = self.manifest or manifest
            if manifest.current_index is None and manifest.state is BatchState.RUNNING:
                self._save(manifest.stop(BatchState.INTERRUPTED))
            raise
        return self._result(self.manifest or manifest)

    def _load_or_create(self) -> BatchManifest:
        if self.manifest_path.exists():
            manifest = BatchManifest.load(self.manifest_path)
            if (
                manifest.batch_id != self.spec.job_id
                or manifest.config_path != self.spec.config_path
                or manifest.config_sha256 != self.spec.config_sha256
                or manifest.targets != self.spec.targets
            ):
                raise ValueError("persisted batch snapshot does not match Job specification")
            return manifest
        manifest = BatchManifest.create(self.spec)
        self._save(manifest)
        return manifest

    def _save(self, manifest: BatchManifest) -> None:
        manifest.persist(self.batch_dir)
        self.manifest = manifest

    def _record_child_stage(self, stage: BatchStage) -> None:
        manifest = self.manifest
        if (
            manifest is not None
            and manifest.state is BatchState.RUNNING
            and manifest.current_index is not None
            and manifest.stage is not stage
        ):
            self._save(manifest.set_stage(stage))

    def _child_spec(
        self,
        target: BatchTarget,
        position: int,
        attempt: int,
        capture_group: str,
    ) -> CaptureJobSpec:
        child_id = str(
            uuid5(UUID(self.spec.job_id), f"target:{position}:attempt:{attempt}")
        )
        return CaptureJobSpec(
            job_id=child_id,
            url=target.url,
            domain=target.domain,
            duration_seconds=target.duration_seconds,
            network=target.network,
            interfaces=self.spec.interfaces,
            output_root=self.spec.output_root,
            chrome_binary=self.spec.chrome_binary,
            controller=self.spec.controller,
            options=self.spec.options,
            wait_load_timeout=target.wait_load_timeout,
            run_label=target.run_label,
            page_type=target.page_type,
            playback=target.playback,
            capture_group=capture_group,
            target_source=TargetSource(
                mode="config",
                config_path=self.spec.config_path,
                config_sha256=self.spec.config_sha256,
                target_index=target.index,
            ),
        )

    def _result(self, manifest: BatchManifest) -> BatchJobResult:
        state = {
            BatchState.COMPLETED: JobState.COMPLETED,
            BatchState.FAILED: JobState.FAILED,
            BatchState.CANCELLED: JobState.CANCELLED,
            BatchState.INTERRUPTED: JobState.INTERRUPTED,
        }.get(manifest.state, JobState.FAILED)
        session_ids = tuple(
            child.session_id for child in manifest.children if child.session_id
        )
        return BatchJobResult(
            job_id=self.spec.job_id,
            state=state,
            manifest_path=str(self.manifest_path),
            session_ids=session_ids,
            completed_targets=sum(
                child.state is BatchChildState.COMPLETED
                for child in manifest.children
            ),
            total_targets=len(manifest.targets),
        )


class _ChildProgress:
    """Maps repeated child stages into one monotonic parent progress stage."""

    def __init__(
        self,
        parent: ProgressReporter,
        position: int,
        total: int,
        stage_callback: Callable[[BatchStage], None],
    ) -> None:
        self.parent = parent
        self.position = position
        self.total = total
        self.stage_callback = stage_callback
        self._progress = 0.0

    @property
    def stage(self):
        return JobStage.BATCH_TARGET

    @property
    def progress(self) -> float:
        return self._progress

    def emit(
        self,
        state: JobState,
        stage: JobStage,
        progress: float,
        message: str = "",
        *,
        force: bool = False,
    ) -> ProgressEvent | None:
        self._progress = progress
        batch_stage = (
            BatchStage.ANALYSIS
            if stage.value.startswith("analyze.")
            else BatchStage.QUIESCENCE
            if stage is JobStage.CLEANUP
            else BatchStage.CAPTURE
        )
        if stage is not JobStage.FINISHED:
            self.stage_callback(batch_stage)
        mapped = (self.position + min(max(progress, 0.0), 1.0)) / self.total
        return self.parent.emit(
            JobState.CAPTURING,
            JobStage.BATCH_TARGET,
            mapped,
            f"target {self.position + 1}/{self.total}: {stage.value} {message}".strip(),
            force=force,
        )

    def finish(self, state: JobState, message: str = "") -> ProgressEvent:
        event = self.emit(
            JobState.CAPTURING,
            JobStage.FINISHED,
            1.0,
            message,
            force=True,
        )
        assert event is not None
        return event

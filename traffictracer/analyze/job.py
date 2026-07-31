"""Progress-aware, cancellable analysis job lifecycle."""

from __future__ import annotations

from pathlib import Path

from traffictracer.jobs.cancellation import CancellationToken, CancelledError
from traffictracer.jobs.models import (
    AnalysisJobSpec,
    CaptureJobResult,
    JobState,
)
from traffictracer.jobs.progress import ProgressReporter
from traffictracer.session.manifest import Artifact, SessionError, SessionManifest
from traffictracer.session.store import MANIFEST_NAME, SessionStore

from .pipeline import run_analysis
from .artifacts import persist_analysis_artifacts


class AnalysisJob:
    def __init__(
        self,
        spec: AnalysisJobSpec,
        *,
        progress: ProgressReporter,
        cancellation: CancellationToken,
    ) -> None:
        spec.to_dict()
        self.spec = spec
        self.progress = progress
        self.cancellation = cancellation
        self._store: SessionStore | None = None
        self._manifest: SessionManifest | None = None

    def run(self) -> CaptureJobResult:
        try:
            self.cancellation.checkpoint()
            self._begin_manifest()
            correlation_path = run_analysis(
                self.spec.session_dir,
                progress=self.progress,
                cancellation=self.cancellation,
                split_pcaps=self.spec.options.split_pcaps,
                overwrite=self.spec.options.overwrite,
            )
            artifact_paths = [Path(correlation_path)]
            if self.spec.options.write_flow_index:
                self.cancellation.checkpoint()
                generated = persist_analysis_artifacts(
                    self.spec.session_dir,
                    self._manifest.session_id if self._manifest is not None else "",
                )
                artifact_paths.extend([generated.flow_index, generated.summary])
                self.cancellation.checkpoint()
            self._record_artifacts(artifact_paths)
        except CancelledError:
            self._finish_manifest(JobState.CANCELLED)
            self.progress.finish(JobState.CANCELLED, self.cancellation.reason)
            raise
        except Exception as exc:
            stage = self.progress.stage.value if self.progress.stage is not None else None
            self._finish_manifest(
                JobState.FAILED,
                SessionError("ANALYSIS_FAILED", str(exc), stage),
            )
            self.progress.finish(JobState.FAILED, "analysis failed")
            raise

        self._finish_manifest(JobState.COMPLETED)
        self.progress.finish(JobState.COMPLETED, "analysis complete")
        artifacts = tuple(
            _relative_artifact(self.spec.session_dir, str(path))
            for path in artifact_paths
        )
        return CaptureJobResult(
            job_id=self.spec.job_id,
            state=JobState.COMPLETED,
            session_id=self._manifest.session_id if self._manifest is not None else "",
            artifacts=artifacts,
        )

    def _begin_manifest(self) -> None:
        manifest_path = Path(self.spec.session_dir) / MANIFEST_NAME
        if not manifest_path.is_file():
            return
        manifest = SessionManifest.load(manifest_path)
        store = SessionStore(self.spec.output_root)
        if manifest.state is JobState.CAPTURING:
            manifest = manifest.transition(JobState.ANALYZING)
            store.save(manifest)
        elif manifest.state is not JobState.ANALYZING:
            raise ValueError(
                f"Session is not ready for analysis: {manifest.state.value}"
            )
        self._store = store
        self._manifest = manifest

    def _finish_manifest(
        self,
        state: JobState,
        error: SessionError | None = None,
    ) -> None:
        if self._store is None or self._manifest is None:
            return
        self._manifest = self._manifest.transition(state, error=error)
        self._store.save(self._manifest)

    def _record_artifacts(self, paths: list[Path]) -> None:
        if self._store is None or self._manifest is None:
            return
        for path in paths:
            relative = _relative_artifact(self.spec.session_dir, str(path))
            self._manifest = self._manifest.with_artifact(
                Artifact(
                    name=path.name,
                    kind="derived",
                    path=relative,
                    media_type="application/json",
                    size_bytes=path.stat().st_size,
                )
            )
        self._store.save(self._manifest)


def _relative_artifact(session_dir: str, artifact_path: str) -> str:
    try:
        return str(Path(artifact_path).relative_to(Path(session_dir)))
    except ValueError:
        return artifact_path

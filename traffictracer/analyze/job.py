"""Progress-aware, cancellable analysis job lifecycle."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5

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
        session_uri = Path(spec.session_dir).resolve().as_uri()
        self._analysis_generation_id: str | None = str(
            uuid5(NAMESPACE_URL, f"{session_uri}#analysis-v2")
        )
        self._results_dir = Path(spec.session_dir) / "results"
        self._session_id = str(uuid5(NAMESPACE_URL, session_uri))

    def run(self) -> CaptureJobResult:
        try:
            self.cancellation.checkpoint()
            self._begin_manifest()
            correlation_path = run_analysis(
                self.spec.session_dir,
                progress=self.progress,
                cancellation=self.cancellation,
                split_pcaps=self.spec.options.split_pcaps,
                pcap_split_mode=self.spec.options.pcap_split_mode,
                overwrite=self.spec.options.overwrite,
                output_dir=self._results_dir,
                analysis_generation_id=self._analysis_generation_id,
            )
            artifact_paths = [Path(correlation_path)]
            if self.spec.options.write_flow_index:
                self.cancellation.checkpoint()
                generated = persist_analysis_artifacts(
                    self.spec.session_dir,
                    self._session_id,
                    output_dir=self._results_dir,
                )
                artifact_paths.extend([generated.flow_index, generated.summary])
                self.cancellation.checkpoint()
            for name in (
                "connection-index-v2.json",
                "request-index-v2.json",
                "pcap-index-v1.json",
            ):
                candidate = self._results_dir / name
                if candidate.is_file():
                    artifact_paths.append(candidate)
                    if name == "pcap-index-v1.json":
                        artifact_paths.extend(
                            _pcap_artifact_paths(
                                Path(self.spec.session_dir),
                                candidate,
                            )
                        )
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
            session_id=self._session_id,
            artifacts=artifacts,
        )

    def _begin_manifest(self) -> None:
        manifest_path = Path(self.spec.session_dir) / MANIFEST_NAME
        if not manifest_path.is_file():
            return
        manifest = SessionManifest.load(manifest_path)
        store = SessionStore(self.spec.output_root)
        self._session_id = manifest.session_id
        if (
            manifest.schema_version == 1
            and manifest.state is JobState.COMPLETED
            and self.spec.options.overwrite
        ):
            self._analysis_generation_id = str(uuid4())
            self._results_dir = (
                Path(self.spec.session_dir)
                / "results"
                / "generations"
                / self._analysis_generation_id
            )
            return
        if manifest.state is JobState.CAPTURING:
            manifest = manifest.transition(JobState.ANALYZING)
            store.save(manifest)
        elif manifest.state is JobState.COMPLETED and self.spec.options.overwrite:
            pass
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
        if self._manifest.state.terminal:
            return
        self._manifest = self._manifest.transition(state, error=error)
        self._store.save(self._manifest)

    def _record_artifacts(self, paths: list[Path]) -> None:
        if self._store is None or self._manifest is None:
            return
        existing = {artifact.path for artifact in self._manifest.artifacts}
        for path in paths:
            relative = _relative_artifact(self.spec.session_dir, str(path))
            if relative in existing:
                continue
            self._manifest = self._manifest.with_artifact(
                Artifact(
                    name=path.name,
                    kind="derived",
                    phase="analysis",
                    generation_id=self._analysis_generation_id,
                    path=relative,
                    media_type=(
                        "application/vnd.tcpdump.pcap"
                        if path.suffix == ".pcap"
                        else "application/json"
                    ),
                    size_bytes=path.stat().st_size,
                )
            )
            existing.add(relative)
        self._store.save(self._manifest)


def _relative_artifact(session_dir: str, artifact_path: str) -> str:
    try:
        return str(Path(artifact_path).relative_to(Path(session_dir)))
    except ValueError:
        return artifact_path


def _pcap_artifact_paths(session: Path, index_path: Path) -> list[Path]:
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    paths: list[Path] = []
    for connection in payload.get("connections", []):
        for side_name in ("pre_proxy", "post_proxy"):
            side = connection.get(side_name, {})
            if side.get("status") != "success" or not side.get("path"):
                continue
            candidate = session / side["path"]
            if candidate.is_file():
                paths.append(candidate)
    return paths

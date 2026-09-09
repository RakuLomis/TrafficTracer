"""Progress-aware, cancellable analysis job lifecycle."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
from uuid import NAMESPACE_URL, uuid4, uuid5

from traffictracer.jobs.cancellation import (
    CancellationToken,
    CancelledError,
    InterruptedError,
)
from traffictracer.jobs.models import (
    AnalysisJobSpec,
    CaptureJobResult,
    JobState,
)
from traffictracer.jobs.errors import exception_message
from traffictracer.jobs.progress import ProgressReporter
from traffictracer.session.manifest import Artifact, SessionError, SessionManifest
from traffictracer.session.store import MANIFEST_NAME, SessionStore
from traffictracer.utils import logger

from .pipeline import run_analysis
from .artifacts import persist_analysis_artifacts
from .consistency import AnalysisConsistencyError
from .health import analysis_health
from .process import analysis_process_scope


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
        session = Path(spec.session_dir)
        self._results_dir = (
            session / "analysis" if (session / "raw").is_dir() else session / "results"
        )
        self._published_results_dir = self._results_dir
        self._staging_results_dir: Path | None = None
        self._backup_results_dir: Path | None = None
        self._published_this_run = False
        self._session_id = str(uuid5(NAMESPACE_URL, session_uri))

    def run(self) -> CaptureJobResult:
        with analysis_health(self.spec.session_dir, self.spec.job_id, self.progress) as health, analysis_process_scope(self.cancellation):
            result = self._run()
            health["state"] = result.state.value
            return result

    def _run(self) -> CaptureJobResult:
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
                published_output_dir=self._published_results_dir,
                analysis_generation_id=self._analysis_generation_id,
            )
            artifact_names = [
                Path(correlation_path).relative_to(self._results_dir)
            ]
            if self.spec.options.write_flow_index:
                self.cancellation.checkpoint()
                generated = persist_analysis_artifacts(
                    self.spec.session_dir,
                    self._session_id,
                    output_dir=self._results_dir,
                )
                artifact_names.extend([
                    generated.flow_index.relative_to(self._results_dir),
                    generated.summary.relative_to(self._results_dir),
                ])
                self.cancellation.checkpoint()
            self._publish_staged_results()
            artifact_paths = [
                self._results_dir / name for name in artifact_names
            ]
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
            updated_manifest = self._record_artifacts(artifact_paths)
            self._finish_manifest(
                JobState.COMPLETED,
                manifest=updated_manifest,
            )
            self._commit_staged_results()
        except InterruptedError:
            self._discard_staged_results()
            self._finish_manifest(JobState.INTERRUPTED)
            self.progress.finish(JobState.INTERRUPTED, self.cancellation.reason)
            raise
        except CancelledError:
            self._discard_staged_results()
            self._finish_manifest(JobState.CANCELLED)
            self.progress.finish(JobState.CANCELLED, self.cancellation.reason)
            raise
        except Exception as exc:
            self._discard_staged_results()
            stage = self.progress.stage.value if self.progress.stage is not None else None
            error_code = (
                "ANALYSIS_CONSISTENCY_FAILED"
                if isinstance(exc, AnalysisConsistencyError)
                else "ANALYSIS_FAILED"
            )
            self._finish_manifest(
                JobState.FAILED,
                SessionError(error_code, exception_message(exc, "analysis failed"), stage),
            )
            self.progress.finish(JobState.FAILED, "analysis failed")
            raise

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
        elif manifest.state is JobState.FAILED and self.spec.options.overwrite:
            manifest = manifest.begin_analysis_retry()
            store.save(manifest)
        elif manifest.state is JobState.COMPLETED and self.spec.options.overwrite:
            pass
        elif manifest.state is not JobState.ANALYZING:
            raise ValueError(
                f"Session is not ready for analysis: {manifest.state.value}"
            )
        self._store = store
        self._manifest = manifest
        if self._published_results_dir == Path(self.spec.session_dir) / "analysis":
            self._prepare_staged_results()

    def _prepare_staged_results(self) -> None:
        session = Path(self.spec.session_dir)
        if self._store is not None:
            self._store.set_analysis_recovery(self._session_id, True)
        staging = session / f".analysis-staging-{uuid4()}"
        self._staging_results_dir = staging
        self._results_dir = staging

    def _publish_staged_results(self) -> None:
        staging = self._staging_results_dir
        if staging is None:
            return
        destination = self._published_results_dir
        backup: Path | None = None
        if destination.exists():
            try:
                # Session initialization may reserve an empty analysis/
                # directory before the Job starts.
                destination.rmdir()
            except OSError:
                if not self.spec.options.overwrite:
                    raise FileExistsError(
                        f"Analysis destination already exists: {destination}"
                    )
                backup = destination.with_name(f".analysis-backup-{uuid4()}")
                os.replace(destination, backup)
        try:
            os.replace(staging, destination)
        except Exception:
            if backup is not None and not destination.exists():
                os.replace(backup, destination)
            raise
        self._backup_results_dir = backup
        self._published_this_run = True
        self._results_dir = destination
        self._staging_results_dir = None

    def _commit_staged_results(self) -> None:
        backup = self._backup_results_dir
        if backup is not None:
            try:
                shutil.rmtree(backup)
            except OSError as exc:
                logger.warning(
                    "Failed to remove analysis backup %s: %s", backup, exc
                )
        self._backup_results_dir = None
        self._published_this_run = False
        self._clear_analysis_recovery_if_clean()

    def _discard_staged_results(self) -> None:
        destination = self._published_results_dir
        backup = self._backup_results_dir
        if self._published_this_run:
            try:
                if destination.exists():
                    shutil.rmtree(destination)
                if backup is not None and backup.exists():
                    os.replace(backup, destination)
            except OSError as exc:
                logger.warning(
                    "Failed to roll back analysis publication %s: %s",
                    destination,
                    exc,
                )
            self._published_this_run = False
            self._backup_results_dir = None

        staging = self._staging_results_dir
        if staging is not None:
            session = Path(self.spec.session_dir).resolve()
            resolved = staging.resolve(strict=False)
            if (
                resolved.parent == session
                and resolved.name.startswith(".analysis-staging-")
            ):
                try:
                    shutil.rmtree(resolved)
                except OSError as exc:
                    logger.warning(
                        "Failed to remove analysis staging %s: %s", resolved, exc
                    )
        self._staging_results_dir = None
        self._results_dir = self._published_results_dir
        self._clear_analysis_recovery_if_clean()

    def _clear_analysis_recovery_if_clean(self) -> None:
        if self._store is not None:
            self._store.clear_analysis_recovery_if_clean(self._session_id)

    def _finish_manifest(
        self,
        state: JobState,
        error: SessionError | None = None,
        *,
        manifest: SessionManifest | None = None,
    ) -> None:
        if self._store is None or self._manifest is None:
            return
        if self._manifest.state.terminal:
            if state is JobState.COMPLETED and manifest is not None:
                self._store.save(manifest)
                self._manifest = manifest
            return
        source = manifest if manifest is not None else self._manifest
        updated = source.transition(state, error=error)
        self._store.save(updated)
        self._manifest = updated

    def _record_artifacts(self, paths: list[Path]) -> SessionManifest | None:
        if self._store is None or self._manifest is None:
            return None
        updated = replace(
            self._manifest,
            artifacts=tuple(
                artifact
                for artifact in self._manifest.artifacts
                if artifact.phase != "analysis"
            ),
        )
        existing = {artifact.path for artifact in updated.artifacts}
        for path in paths:
            relative = _relative_artifact(self.spec.session_dir, str(path))
            if relative in existing:
                continue
            updated = updated.with_artifact(
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
        return updated


def _relative_artifact(session_dir: str, artifact_path: str) -> str:
    try:
        return str(
            Path(artifact_path).resolve().relative_to(Path(session_dir).resolve())
        )
    except ValueError as exc:
        raise ValueError(
            f"artifact is outside Session directory: {artifact_path}"
        ) from exc


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

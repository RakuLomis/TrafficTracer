"""Concrete Worker method services joining Jobs, Sessions, diagnostics and Flows."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from threading import Event
from typing import Any

from traffictracer.analyze.flow_index import flow_key
from traffictracer.analyze.job import AnalysisJob
from traffictracer.capture.job import CaptureJob, CaptureRuntime, CaptureSessionContext
from traffictracer.capture.mihomo import MihomoManager
from traffictracer.config import ConfigValidationError, load_target_config
from traffictracer.diagnostics import EnvironmentSpec, diagnose_environment
from traffictracer.jobs.cancellation import CancellationToken, CancelledError
from traffictracer.jobs.batch import SerialBatchJob
from traffictracer.jobs.batch_models import BatchJobSpec
from traffictracer.jobs.models import (
    AnalysisJobOptions,
    AnalysisJobSpec,
    CaptureJobResult,
    CaptureJobSpec,
    JobState,
)
from traffictracer.jobs.process_registry import ProcessRegistry
from traffictracer.jobs.progress import ProgressReporter, ProgressWindow
from traffictracer.session.manifest import (
    Artifact,
    ComponentVersion,
    ComponentVersions,
    SessionError,
    SessionManifest,
    SessionTarget,
)
from traffictracer.session.store import MANIFEST_NAME, SessionStore
from traffictracer.version import COMPLETE_VERSION

from .dispatcher import WorkerMethodError
from .job_manager import JobManager


class WorkerServices:
    def __init__(
        self,
        output_root: str | Path,
        *,
        notify,
        shutdown_event: Event,
        controller_endpoint: str = "",
        controller_secret: str = "",
    ) -> None:
        self.store = SessionStore(Path(output_root).expanduser().resolve())
        self.notify = notify
        self.shutdown_event = shutdown_event
        self.controller_endpoint = controller_endpoint
        self.controller_secret = controller_secret
        self.jobs = JobManager(
            capture_factory=self._capture_factory,
            analysis_factory=self._analysis_factory,
            batch_factory=self._batch_factory,
            notify=notify,
        )

    def handlers(self):
        handlers = self.jobs.handlers()
        handlers.update({
            "environment.diagnose": self.diagnose,
            "config.targets.load": self.load_targets,
            "session.list": self.session_list,
            "session.get": self.session_get,
            "session.delete": self.session_delete,
            "session.cleanup.preview": self.session_cleanup_preview,
            "flow.query": self.flow_query,
            "worker.shutdown": self.shutdown,
        })
        return handlers

    def load_targets(self, params: dict[str, Any]) -> dict[str, Any]:
        if set(params) != {"path"} or not isinstance(params.get("path"), str):
            raise WorkerMethodError(
                "INVALID_PARAMS", "config.targets.load requires one string path."
            )
        try:
            return load_target_config(params["path"]).to_dict()
        except ConfigValidationError as exc:
            raise WorkerMethodError(
                "INVALID_PARAMS",
                exc.message,
                {"field": exc.field_path},
            ) from exc

    def diagnose(self, params: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "controller_endpoint",
            "controller_secret",
            "tun_interface",
            "physical_interface",
            "chrome_binary",
            "output_root",
            "min_free_bytes",
        }
        unknown = set(params) - allowed
        if unknown:
            raise WorkerMethodError(
                "INVALID_PARAMS", f"Unknown diagnose parameter: {sorted(unknown)[0]}"
            )
        spec = EnvironmentSpec(
            controller_endpoint=params.get(
                "controller_endpoint", self.controller_endpoint
            ),
            controller_secret=params.get(
                "controller_secret", self.controller_secret
            ),
            tun_interface=params.get("tun_interface", ""),
            physical_interface=params.get("physical_interface", ""),
            chrome_binary=params.get("chrome_binary", "google-chrome"),
            output_root=params.get("output_root", str(self.store.output_root)),
            min_free_bytes=params.get("min_free_bytes", 1024 * 1024 * 1024),
        )
        return diagnose_environment(spec).to_dict()

    def session_list(self, params: dict[str, Any]) -> dict[str, Any]:
        if params:
            raise WorkerMethodError(
                "INVALID_PARAMS", "session.list does not accept parameters."
            )
        scan = self.store.scan()
        return {
            "sessions": [manifest.to_dict() for manifest in scan.sessions],
            "corrupt": [
                {"session_dir": item.session_dir, "message": item.message}
                for item in scan.corrupt
            ],
        }

    def session_get(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._manifest(params).to_dict()

    def session_delete(self, params: dict[str, Any]) -> dict[str, Any]:
        manifest = self._manifest(params)
        if not manifest.state.terminal:
            raise WorkerMethodError(
                "INVALID_PARAMS", "An active or interrupted Session cannot be deleted."
            )
        self.store.delete(manifest.session_id)
        return {"session_id": manifest.session_id, "deleted": True}

    def session_cleanup_preview(self, params: dict[str, Any]) -> dict[str, Any]:
        if set(params) != {"session_id"}:
            raise WorkerMethodError(
                "INVALID_PARAMS",
                "session.cleanup.preview requires only session_id.",
            )
        try:
            return self.store.preview_derived_cleanup(params["session_id"])
        except (TypeError, ValueError) as exc:
            raise WorkerMethodError("INVALID_PARAMS", str(exc)) from exc

    def flow_query(self, params: dict[str, Any]) -> dict[str, Any]:
        manifest = self._manifest(params)
        required = ("network", "src_ip", "src_port", "dst_ip", "dst_port")
        if any(name not in params for name in required):
            raise WorkerMethodError(
                "INVALID_PARAMS", "flow.query requires a normalized five-tuple."
            )
        try:
            expected = flow_key(*(params[name] for name in required))
        except (TypeError, ValueError) as exc:
            raise WorkerMethodError("INVALID_PARAMS", str(exc)) from exc
        offset = params.get("offset", 0)
        limit = params.get("limit", 100)
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 1000
        ):
            raise WorkerMethodError(
                "INVALID_PARAMS", "offset must be non-negative and limit must be 1..1000."
            )
        path = self._flow_index_path(manifest)
        try:
            with path.open(encoding="utf-8") as stream:
                payload = json.load(stream)
        except FileNotFoundError as exc:
            raise WorkerMethodError(
                "INVALID_PARAMS", "Session has no persisted Flow index; run analysis first."
            ) from exc
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise WorkerMethodError("INTERNAL_ERROR", "Persisted Flow index is invalid.")
        matches = [item for item in items if _item_flow_key(item) == expected]
        return {
            "session_id": manifest.session_id,
            "offset": offset,
            "limit": limit,
            "total": len(matches),
            "items": matches[offset : offset + limit],
        }

    def _flow_index_path(self, manifest: SessionManifest) -> Path:
        session = Path(manifest.session_dir)
        generation_root = session / "results" / "generations"
        generated = (
            sorted(
                generation_root.glob("*/flow-index.json"),
                key=lambda path: (path.stat().st_mtime_ns, str(path)),
                reverse=True,
            )
            if generation_root.is_dir()
            else []
        )
        if generated:
            relative = generated[0].relative_to(session)
            return self.store.artifact_path(manifest.session_id, relative)
        indexed = [
            artifact.path
            for artifact in manifest.artifacts
            if getattr(artifact, "role", "") == "flow_index"
        ]
        return self.store.artifact_path(
            manifest.session_id,
            indexed[-1] if indexed else "results/flow-index.json",
        )

    def shutdown(self, params: dict[str, Any]) -> dict[str, Any]:
        if params:
            raise WorkerMethodError(
                "INVALID_PARAMS", "worker.shutdown does not accept parameters."
            )
        clean = self.jobs.shutdown(timeout=5)
        self.shutdown_event.set()
        return {"shutdown": True, "jobs_stopped": clean}

    def restore_tracing(self, state: dict[str, object]) -> Any:
        if not self.controller_endpoint:
            raise RuntimeError("controller endpoint is not configured")
        return MihomoManager(
            "", "", self.controller_endpoint, self.controller_secret
        ).restore_tracing(state)

    def _manifest(self, params: dict[str, Any]) -> SessionManifest:
        session_id = params.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise WorkerMethodError(
                "INVALID_PARAMS", "session_id must be a non-empty string."
            )
        try:
            return self.store.get(session_id)
        except Exception as exc:
            raise WorkerMethodError(
                "SESSION_NOT_FOUND", "The requested Session does not exist."
            ) from exc

    def _capture_factory(
        self,
        spec: CaptureJobSpec | AnalysisJobSpec,
        progress: ProgressReporter,
        cancellation: CancellationToken,
    ):
        assert isinstance(spec, CaptureJobSpec)
        self._require_output_root(spec.output_root)
        traffictracer_version = ComponentVersion(COMPLETE_VERSION, "unknown")
        component_version = ComponentVersion("unknown", "unknown")
        manifest = self.store.create(
            job_id=spec.job_id,
            target=SessionTarget(spec.url, spec.domain, spec.target_source.to_dict()),
            component_versions=ComponentVersions(
                traffictracer_version,
                component_version,
                component_version,
            ),
        )
        manifest = manifest.transition(JobState.PREPARING)
        manifest = manifest.transition(JobState.CAPTURING)
        self.store.save(manifest)
        mihomo = MihomoManager(
            "",
            spec.controller.generated_config or "",
            spec.controller.endpoint,
            spec.controller.secret or "",
        )
        capture = CaptureJob(
            spec,
            runtime=CaptureRuntime(
                user_data_dir=str(self.store.output_root / ".chrome-profiles"),
                enable_cdp=spec.options.collect_cdp,
                wait_load_timeout=spec.wait_load_timeout,
                run_label=spec.run_label,
            ),
            mihomo=mihomo,
            session=CaptureSessionContext(
                manifest.session_id, Path(manifest.session_dir), self.store
            ),
            registry=ProcessRegistry(),
            progress=progress,
            cancellation=cancellation,
            finalize_progress=not spec.options.analyze_after_capture,
        )
        return _PersistentCaptureRunner(
            capture,
            spec,
            manifest.session_id,
            self.store,
            progress,
            cancellation,
        )

    def _analysis_factory(
        self,
        spec: CaptureJobSpec | AnalysisJobSpec,
        progress: ProgressReporter,
        cancellation: CancellationToken,
    ):
        assert isinstance(spec, AnalysisJobSpec)
        self._require_output_root(spec.output_root)
        manifest_path = Path(spec.session_dir) / MANIFEST_NAME
        try:
            manifest = SessionManifest.load(manifest_path)
            managed = self.store.get(manifest.session_id)
        except Exception as exc:
            raise WorkerMethodError(
                "SESSION_NOT_FOUND", "Analysis Session is not managed by this Worker."
            ) from exc
        if Path(managed.session_dir) != Path(spec.session_dir).resolve():
            raise WorkerMethodError(
                "SESSION_NOT_FOUND", "Analysis Session path does not match its manifest."
            )
        return AnalysisJob(spec, progress=progress, cancellation=cancellation)

    def _batch_factory(
        self,
        spec,
        progress: ProgressReporter,
        cancellation: CancellationToken,
        *,
        resume: bool = False,
    ):
        assert isinstance(spec, BatchJobSpec)
        self._require_output_root(spec.output_root)
        return SerialBatchJob(
            spec,
            child_factory=self._capture_factory,
            progress=progress,
            cancellation=cancellation,
            session_for_job=self._session_for_job,
            resume=resume,
        )

    def _session_for_job(self, job_id: str) -> str | None:
        return next(
            (
                manifest.session_id
                for manifest in self.store.scan().sessions
                if manifest.job_id == job_id
            ),
            None,
        )

    def _require_output_root(self, value: str) -> None:
        if Path(value).resolve() != self.store.output_root:
            raise WorkerMethodError(
                "INVALID_PARAMS", "Job output_root must match the Worker Session root."
            )


class _PersistentCaptureRunner:
    def __init__(
        self,
        capture: CaptureJob,
        spec: CaptureJobSpec,
        session_id: str,
        store: SessionStore,
        progress: ProgressReporter,
        cancellation: CancellationToken,
    ) -> None:
        self.capture = capture
        self.spec = spec
        self.session_id = session_id
        self.store = store
        self.progress = progress
        self.cancellation = cancellation

    def run(self) -> CaptureJobResult:
        try:
            captured = self.capture.run()
            self._record_paths(captured.artifacts, kind="raw")
            if self.spec.options.analyze_after_capture:
                manifest = self.store.get(self.session_id)
                analysis_spec = AnalysisJobSpec(
                    job_id=self.spec.job_id,
                    session_dir=manifest.session_dir,
                    output_root=str(self.store.output_root),
                    options=AnalysisJobOptions(overwrite=False),
                )
                analyzed = AnalysisJob(
                    analysis_spec,
                    progress=ProgressWindow(self.progress, 0.9, 0.99),
                    cancellation=self.cancellation,
                ).run()
                return replace(
                    analyzed,
                    artifacts=(*captured.artifacts, *analyzed.artifacts),
                )
            self._transition(JobState.COMPLETED)
            return captured
        except CancelledError:
            self._transition(JobState.CANCELLED)
            raise
        except Exception as exc:
            code = getattr(exc, "code", "CAPTURE_FAILED")
            self._transition(
                JobState.FAILED,
                SessionError(code, str(exc), "capture"),
            )
            raise

    def _record_paths(self, paths: tuple[str, ...], *, kind: str) -> None:
        manifest = self.store.get(self.session_id)
        existing = {artifact.path for artifact in manifest.artifacts}
        for relative in paths:
            path = Path(manifest.session_dir) / relative
            if relative in existing or not path.is_file():
                continue
            manifest = manifest.with_artifact(Artifact(
                name=path.name,
                kind=kind,
                path=relative,
                media_type=_media_type(path),
                size_bytes=path.stat().st_size,
            ))
            existing.add(relative)
        self.store.save(manifest)

    def _transition(
        self,
        state: JobState,
        error: SessionError | None = None,
    ) -> None:
        manifest = self.store.get(self.session_id)
        if manifest.state.terminal:
            return
        self.store.save(manifest.transition(state, error=error))


def _item_flow_key(item: object) -> str:
    if not isinstance(item, dict) or not isinstance(item.get("pre_flow"), dict):
        return ""
    pre = item["pre_flow"]
    try:
        return flow_key(
            pre["network"],
            pre["src_ip"],
            pre["src_port"],
            pre["dst_ip"],
            pre["dst_port"],
        )
    except (KeyError, TypeError, ValueError):
        return ""


def _media_type(path: Path) -> str:
    if path.suffix == ".pcap":
        return "application/vnd.tcpdump.pcap"
    if path.suffix == ".jsonl":
        return "application/x-ndjson"
    return "application/json"

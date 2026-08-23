"""Concrete Worker method services joining Jobs, Sessions, diagnostics and Flows."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from threading import Event
from typing import Any

from traffictracer.analyze.flow_index import flow_key
from traffictracer.analyze.job import AnalysisJob
from traffictracer.analyze.packet_split_status import inspect_packet_split
from traffictracer.capture.job import CaptureJob, CaptureRuntime, CaptureSessionContext
from traffictracer.capture.mihomo import MihomoManager
from traffictracer.config import ConfigValidationError, load_target_config
from traffictracer.diagnostics import EnvironmentSpec, diagnose_environment
from traffictracer.jobs.cancellation import (
    CancellationToken,
    CancelledError,
    InterruptedError,
)
from traffictracer.jobs.batch import SerialBatchJob
from traffictracer.jobs.batch_models import (
    BatchJobSpec,
    BatchState,
    BatchStore,
)
from traffictracer.jobs.models import (
    AnalysisJobOptions,
    AnalysisJobSpec,
    CaptureJobResult,
    CaptureJobSpec,
    JobState,
)
from traffictracer.jobs.errors import exception_message
from traffictracer.jobs.packet_split import (
    PacketSplitGroupSpec,
    SerialPacketSplitJob,
)
from traffictracer.jobs.process_registry import ProcessRegistry
from traffictracer.jobs.progress import ProgressReporter, ProgressWindow
from traffictracer.layout import group_directory_name
from traffictracer.build_info import component_versions_dict
from traffictracer.session.manifest import (
    Artifact,
    ComponentVersion,
    ComponentVersions,
    SessionError,
    SessionManifest,
    SessionTarget,
)
from traffictracer.session.store import MANIFEST_NAME, SessionStore, SessionStoreError

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
        self.batches = BatchStore(self.store.output_root)
        self.notify = notify
        self.shutdown_event = shutdown_event
        self.controller_endpoint = controller_endpoint
        self.controller_secret = controller_secret
        self.jobs = JobManager(
            capture_factory=self._capture_factory,
            analysis_factory=self._analysis_factory,
            batch_factory=self._batch_factory,
            packet_split_factory=self._packet_split_factory,
            notify=notify,
        )

    def handlers(self):
        handlers = self.jobs.handlers()
        handlers.update({
            "environment.diagnose": self.diagnose,
            "config.targets.load": self.load_targets,
            "session.list": self.session_list,
            "session.scope.resolve": self.session_scope_resolve,
            "session.scope.list": self.session_scope_list,
            "session.scope.packet_split.preview": self.session_scope_packet_split_preview,
            "session.get": self.session_get,
            "session.delete": self.session_delete,
            "session.cleanup.preview": self.session_cleanup_preview,
            "flow.query": self.flow_query,
            "batch.start": self.batch_start,
            "batch.status": self.batch_status,
            "batch.interrupt": self.batch_interrupt,
            "batch.cancel": self.batch_cancel,
            "batch.list": self.batch_list,
            "batch.resume": self.batch_resume,
            "packet_split.resume": self.packet_split_resume,
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
        offset, limit = _pagination(params)
        scan = self.store.scan()
        return _session_page(scan, offset=offset, limit=limit)

    def session_scope_resolve(self, params: dict[str, Any]) -> dict[str, Any] | None:
        selectors = {"path", "job_id", "batch_id"} & set(params)
        if len(selectors) != 1 or set(params) != selectors:
            raise WorkerMethodError(
                "INVALID_PARAMS",
                "session.scope.resolve requires exactly one of path, job_id or batch_id.",
            )
        selector = selectors.pop()
        value = params.get(selector)
        if not isinstance(value, str) or not value:
            raise WorkerMethodError(
                "INVALID_PARAMS", f"{selector} must be a non-empty string."
            )
        try:
            if selector == "path":
                scope = self.store.resolve_scope_path(value)
            elif selector == "job_id":
                scope = self.store.scope_for_job(value)
                if scope is None:
                    return None
            else:
                batch = self._batch_manifest(value)
                scope = self.store.resolve_scope_id(
                    group_directory_name(batch.created_at),
                    allow_missing_capture_group=True,
                )
        except WorkerMethodError:
            raise
        except (OSError, TypeError, ValueError, SessionStoreError) as exc:
            raise WorkerMethodError("INVALID_PARAMS", str(exc)) from exc
        return scope.to_dict()

    def session_scope_list(self, params: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(params.get("scope_id"), str):
            raise WorkerMethodError(
                "INVALID_PARAMS", "session.scope.list requires a string scope_id."
            )
        offset, limit = _pagination(params, required={"scope_id"})
        try:
            scope = self.store.resolve_scope_id(
                params["scope_id"], allow_missing_capture_group=True
            )
            scan = self.store.scan_scope(scope.scope_id)
        except (OSError, TypeError, ValueError, SessionStoreError) as exc:
            raise WorkerMethodError("INVALID_PARAMS", str(exc)) from exc
        return {
            "scope": scope.to_dict(),
            **_session_page(scan, offset=offset, limit=limit),
        }

    def session_scope_packet_split_preview(self, params: dict[str, Any]) -> dict[str, Any]:
        if set(params) != {"scope_id"} or not isinstance(params.get("scope_id"), str):
            raise WorkerMethodError(
                "INVALID_PARAMS",
                "packet split preview requires only a string scope_id.",
            )
        try:
            scope = self.store.resolve_scope_id(params["scope_id"])
            if scope.kind != "capture_group":
                raise ValueError("packet splitting requires a timestamp capture group")
            scan = self.store.scan_scope(scope.scope_id)
        except (OSError, TypeError, ValueError, SessionStoreError) as exc:
            raise WorkerMethodError("INVALID_PARAMS", str(exc)) from exc
        sessions = []
        counts: dict[str, int] = {}
        for manifest in scan.sessions:
            inspection = inspect_packet_split(manifest)
            counts[inspection.status.value] = counts.get(inspection.status.value, 0) + 1
            sessions.append({
                "session_id": manifest.session_id,
                "url": manifest.target.url,
                **inspection.to_dict(),
            })
        return {
            "scope": scope.to_dict(),
            "total": len(sessions),
            "counts": counts,
            "missing_only": sum(item["runnable_missing"] for item in sessions),
            "repair_incomplete": sum(item["runnable_repair"] for item in sessions),
            "sessions": sessions,
            "corrupt": [
                {"session_dir": item.session_dir, "message": item.message}
                for item in scan.corrupt
            ],
        }

    def packet_split_resume(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.jobs.start_packet_split(params, resume=True)

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
        result_root = session / ("analysis" if (session / "raw").is_dir() else "results")
        generation_root = result_root / "generations"
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
        if indexed:
            relative = indexed[-1]
        else:
            preferred = result_root / "flow-index.json"
            legacy = session / "results" / "flow-index.json"
            relative = str(
                (legacy if legacy.is_file() else preferred).relative_to(session)
            )
        return self.store.artifact_path(manifest.session_id, relative)

    def shutdown(self, params: dict[str, Any]) -> dict[str, Any]:
        if params:
            raise WorkerMethodError(
                "INVALID_PARAMS", "worker.shutdown does not accept parameters."
            )
        clean = self.jobs.shutdown(timeout=5)
        self.shutdown_event.set()
        return {"shutdown": True, "jobs_stopped": clean}

    def recover_batches(self) -> tuple[str, ...]:
        return self.batches.recover_running()

    def batch_start(self, params: dict[str, Any]) -> dict[str, Any]:
        payload = params.get("job") if set(params) == {"job"} else params
        if not isinstance(payload, dict):
            raise WorkerMethodError("INVALID_PARAMS", "batch.start requires a Job object.")
        spec = BatchJobSpec.from_dict(payload)
        self._require_output_root(spec.output_root)
        spec.verify_config_sha256()
        return self.jobs.start_batch({"job": spec.to_dict()})

    def batch_status(self, params: dict[str, Any]) -> dict[str, Any]:
        batch_id = _batch_id(params)
        manifest = self._batch_manifest(batch_id)
        return {
            "batch": manifest.to_dict(),
            "job": self.jobs.maybe_status(batch_id),
        }

    def batch_list(self, params: dict[str, Any]) -> dict[str, Any]:
        if params:
            raise WorkerMethodError("INVALID_PARAMS", "batch.list does not accept parameters.")
        scan = self.batches.scan()
        return {
            "batches": [manifest.to_dict() for manifest in scan.batches],
            "corrupt": [
                {"path": item.path, "message": item.message}
                for item in scan.corrupt
            ],
        }

    def batch_cancel(self, params: dict[str, Any]) -> dict[str, Any]:
        batch_id = _batch_id(params, allow_reason=True)
        manifest = self._batch_manifest(batch_id)
        job = self.jobs.maybe_status(batch_id)
        if job is not None and not JobState(job["state"]).terminal:
            cancelled = self.jobs.cancel({
                "job_id": batch_id,
                "reason": params.get("reason", "Batch cancelled by user."),
            })
            return {"batch": manifest.to_dict(), "job": cancelled}
        if manifest.state is BatchState.COMPLETED:
            return {"batch": manifest.to_dict(), "job": job}
        if manifest.state is not BatchState.CANCELLED:
            manifest = manifest.cancel_inactive()
            self.batches.save(manifest)
        return {"batch": manifest.to_dict(), "job": job}

    def batch_interrupt(self, params: dict[str, Any]) -> dict[str, Any]:
        batch_id = _batch_id(params, allow_reason=True)
        manifest = self._batch_manifest(batch_id)
        job = self.jobs.maybe_status(batch_id)
        if job is not None and not JobState(job["state"]).terminal:
            interrupted = self.jobs.interrupt({
                "job_id": batch_id,
                "reason": params.get(
                    "reason", "Batch interrupted by user."
                ),
            })
            return {"batch": manifest.to_dict(), "job": interrupted}
        return {"batch": manifest.to_dict(), "job": job}

    def batch_resume(self, params: dict[str, Any]) -> dict[str, Any]:
        batch_id = _batch_id(params)
        manifest = self._batch_manifest(batch_id)
        if manifest.state not in {BatchState.FAILED, BatchState.INTERRUPTED}:
            raise WorkerMethodError(
                "INVALID_PARAMS", "Only failed or interrupted batches can resume."
            )
        spec = replace(
            manifest.to_job_spec(
                controller_secret=self.controller_secret or None
            ),
            fail_fast=False,
        )
        # Resume never reloads target definitions. The source file is checked
        # only as an immutable provenance guard against silent YAML changes.
        spec.verify_config_sha256()
        return self.jobs.start_batch({"job": spec.to_dict()}, resume=True)

    def _batch_manifest(self, batch_id: str):
        try:
            return self.batches.get(batch_id)
        except (OSError, ValueError) as exc:
            raise WorkerMethodError(
                "JOB_NOT_FOUND", "The requested batch does not exist."
            ) from exc

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
        versions = component_versions_dict()
        manifest = self.store.create(
            job_id=spec.job_id,
            target=SessionTarget(spec.url, spec.domain, spec.target_source.to_dict()),
            component_versions=ComponentVersions(
                traffictracer=ComponentVersion(**versions["traffictracer"]),
                mihomo=ComponentVersion(**versions["mihomo"]),
                clash_verge_rev=ComponentVersion(
                    **versions["clash_verge_rev"]
                ),
                worker_api=versions["worker_api"],
            ),
            page_type=spec.page_type,
            capture_group=spec.capture_group,
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

    def _packet_split_factory(
        self,
        spec,
        progress: ProgressReporter,
        cancellation: CancellationToken,
    ):
        assert isinstance(spec, PacketSplitGroupSpec)
        self._require_output_root(spec.output_root)
        return SerialPacketSplitJob(
            spec,
            store=self.store,
            analysis_factory=self._analysis_factory,
            progress=progress,
            cancellation=cancellation,
        )

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
        spec = self._freeze_batch_proxy_protocol(spec)
        return SerialBatchJob(
            spec,
            child_factory=self._capture_factory,
            progress=progress,
            cancellation=cancellation,
            session_for_job=self._session_for_job,
            resume=resume,
        )

    @staticmethod
    def _freeze_batch_proxy_protocol(spec: BatchJobSpec) -> BatchJobSpec:
        options = spec.options
        if (
            options.proxy_protocol_mode != "strict_single"
            or options.expected_proxy_protocol
        ):
            return spec
        manager = MihomoManager(
            "",
            spec.controller.generated_config or "",
            spec.controller.endpoint,
            spec.controller.secret or "",
        )
        snapshot = manager.get_proxy_protocol_snapshot()
        protocols = list(snapshot.get("protocols", []))
        if len(protocols) > 1:
            raise RuntimeError(
                "Proxy protocol invariant failed at capture-group creation: "
                + ", ".join(sorted(protocols))
            )
        if len(protocols) != 1:
            return spec
        return replace(
            spec,
            options=replace(
                options, expected_proxy_protocol=str(protocols[0]),
            ),
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
                    options=AnalysisJobOptions(
                        split_pcaps=(
                            self.spec.options.capture_packets
                            and self.spec.options.pcap_split_mode
                            == "unique_connections"
                        ),
                        pcap_split_mode=(
                            self.spec.options.pcap_split_mode
                            if self.spec.options.capture_packets
                            else "none"
                        ),
                        overwrite=False,
                    ),
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
        except InterruptedError:
            self._transition(JobState.INTERRUPTED)
            raise
        except CancelledError:
            self._transition(JobState.CANCELLED)
            raise
        except Exception as exc:
            partial_artifacts = getattr(self.capture, "artifacts", ())
            if isinstance(partial_artifacts, tuple):
                self._record_paths(partial_artifacts, kind="raw")
            code = getattr(exc, "code", "CAPTURE_FAILED")
            self._transition(
                JobState.FAILED,
                SessionError(
                    code,
                    exception_message(exc, "capture failed"),
                    "capture",
                ),
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


def _batch_id(params: dict[str, Any], *, allow_reason: bool = False) -> str:
    allowed = {"batch_id", "reason"} if allow_reason else {"batch_id"}
    if set(params) - allowed:
        raise WorkerMethodError("INVALID_PARAMS", "Unknown batch parameter.")
    batch_id = params.get("batch_id")
    if not isinstance(batch_id, str) or not batch_id:
        raise WorkerMethodError("INVALID_PARAMS", "batch_id must be a UUID string.")
    return batch_id


def _media_type(path: Path) -> str:
    if path.suffix == ".pcap":
        return "application/vnd.tcpdump.pcap"
    if path.suffix == ".jsonl":
        return "application/x-ndjson"
    return "application/json"

def _pagination(
    params: dict[str, Any],
    *,
    required: set[str] | None = None,
) -> tuple[int, int]:
    required = required or set()
    allowed = required | {"offset", "limit"}
    if set(params) - allowed or not required.issubset(params):
        raise WorkerMethodError(
            "INVALID_PARAMS",
            "Session pagination accepts only offset and limit.",
        )
    offset = params.get("offset", 0)
    limit = params.get("limit", 20)
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= 100
    ):
        raise WorkerMethodError(
            "INVALID_PARAMS",
            "offset must be non-negative and limit must be between 1 and 100.",
        )
    return offset, limit


def _session_page(scan, *, offset: int, limit: int) -> dict[str, Any]:
    total = len(scan.sessions)
    page = scan.sessions[offset:offset + limit]
    return {
        "sessions": [_session_summary(manifest) for manifest in page],
        "offset": offset,
        "limit": limit,
        "total": total,
        "has_more": offset + len(page) < total,
        "corrupt": [
            {"session_dir": item.session_dir, "message": item.message}
            for item in scan.corrupt
        ],
    }


def _session_summary(manifest: SessionManifest) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": manifest.schema_version,
        "session_id": manifest.session_id,
        "job_id": manifest.job_id,
        "state": manifest.state.value,
        "created_at": manifest.created_at.isoformat().replace("+00:00", "Z"),
        "updated_at": manifest.updated_at.isoformat().replace("+00:00", "Z"),
        "session_dir": manifest.session_dir,
        "target": manifest.target.to_dict(),
        "artifact_count": len(manifest.artifacts),
        "warning_count": len(manifest.warnings),
        "quality_state": None,
        "capture_global_quality_state": None,
        "analysis_integrity_state": None,
        "network_outcome_state": None,
        "scenario_outcome_state": None,
        "coverage": None,
        "packet_split": inspect_packet_split(manifest).to_dict(),
    }
    if manifest.started_at is not None:
        payload["started_at"] = (
            manifest.started_at.isoformat().replace("+00:00", "Z")
        )
    if manifest.completed_at is not None:
        payload["completed_at"] = (
            manifest.completed_at.isoformat().replace("+00:00", "Z")
        )
    if manifest.error is not None:
        payload["error"] = manifest.error.to_dict()

    summary_artifact = next(
        (
            artifact for artifact in manifest.artifacts
            if artifact.role == "coverage_summary"
            or artifact.path == "analysis/summary.json"
        ),
        None,
    )
    if summary_artifact is not None:
        try:
            session_dir = Path(manifest.session_dir).resolve(strict=True)
            summary_path = (
                session_dir / summary_artifact.path
            ).resolve(strict=True)
            summary_path.relative_to(session_dir)
            with summary_path.open(encoding="utf-8") as stream:
                summary = json.load(stream)
            if isinstance(summary, dict):
                payload["quality_state"] = summary.get("quality_state")
                payload["capture_global_quality_state"] = summary.get(
                    "capture_global_quality_state"
                )
                integrity = summary.get("analysis_integrity", {})
                if isinstance(integrity, dict):
                    page_integrity = integrity.get("page_attributed", {})
                    if isinstance(page_integrity, dict):
                        payload["analysis_integrity_state"] = page_integrity.get("state")
                network = summary.get("network_outcome", {})
                if isinstance(network, dict):
                    page_network = network.get("page_attributed", {})
                    if isinstance(page_network, dict):
                        payload["network_outcome_state"] = page_network.get("state")
                scenario = summary.get("scenario_outcome", {})
                if isinstance(scenario, dict):
                    payload["scenario_outcome_state"] = scenario.get("state")
                coverage = summary.get("coverage")
                if isinstance(coverage, dict):
                    page = coverage.get("page_attributed")
                    if isinstance(page, dict):
                        payload["coverage"] = page
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    return payload

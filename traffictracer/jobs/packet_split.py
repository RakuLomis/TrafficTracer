"""Durable, strictly serial splitting of every eligible Session in one capture group."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID, uuid5

from traffictracer.contracts import validate_job, validate_packet_split_manifest
from traffictracer.analyze.packet_split_status import (
    PacketSplitStatus,
    inspect_packet_split,
)
from traffictracer.jobs.cancellation import CancellationToken, CancelledError
from traffictracer.jobs.errors import exception_message
from traffictracer.jobs.models import (
    AnalysisJobOptions,
    AnalysisJobSpec,
    CaptureJobResult,
    JobState,
    ProgressEvent,
)
from traffictracer.jobs.progress import JobStage, ProgressReporter
from traffictracer.session.atomic import write_json_atomic
from traffictracer.session.store import SessionStore
from traffictracer.version import JOB_SCHEMA_VERSION


PACKET_SPLIT_MANIFEST_NAME = "packet-split-manifest.json"


class PacketSplitPolicy(str, Enum):
    MISSING_ONLY = "missing_only"
    REPAIR_INCOMPLETE = "repair_incomplete"


@dataclass(frozen=True)
class PacketSplitGroupSpec:
    job_id: str
    scope_id: str
    output_root: str
    policy: PacketSplitPolicy = PacketSplitPolicy.MISSING_ONLY
    schema_version: int = JOB_SCHEMA_VERSION
    kind: str = "packet_split_group"

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PacketSplitGroupSpec":
        data = dict(payload)
        validate_job(data)
        if data.get("schema_version") != JOB_SCHEMA_VERSION:
            raise ValueError("unsupported packet split Job schema_version")
        if data.get("kind") != "packet_split_group":
            raise ValueError("packet split Job requires kind='packet_split_group'")
        UUID(str(data.get("job_id", "")))
        scope_id = data.get("scope_id")
        output_root = data.get("output_root")
        if not isinstance(scope_id, str) or not scope_id:
            raise ValueError("scope_id must be a non-empty string")
        if not isinstance(output_root, str) or not Path(output_root).is_absolute():
            raise ValueError("output_root must be an absolute path")
        return cls(
            job_id=data["job_id"],
            scope_id=scope_id,
            output_root=output_root,
            policy=PacketSplitPolicy(data.get("policy", "missing_only")),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "job_id": self.job_id,
            "scope_id": self.scope_id,
            "output_root": self.output_root,
            "policy": self.policy.value,
        }
        validate_job(payload)
        return payload


@dataclass(frozen=True)
class PacketSplitGroupResult:
    job_id: str
    state: JobState
    manifest_path: str
    total_sessions: int
    processed_sessions: int
    completed_sessions: int
    failed_sessions: int
    skipped_sessions: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state.value,
            "manifest_path": self.manifest_path,
            "total_sessions": self.total_sessions,
            "processed_sessions": self.processed_sessions,
            "completed_sessions": self.completed_sessions,
            "failed_sessions": self.failed_sessions,
            "skipped_sessions": self.skipped_sessions,
        }


class SerialPacketSplitJob:
    def __init__(
        self,
        spec: PacketSplitGroupSpec,
        *,
        store: SessionStore,
        analysis_factory,
        progress: ProgressReporter,
        cancellation: CancellationToken,
    ) -> None:
        self.spec = spec
        self.store = store
        self.analysis_factory = analysis_factory
        self.progress = progress
        self.cancellation = cancellation
        scope = store.resolve_scope_id(spec.scope_id)
        if scope.kind != "capture_group" or not scope.exists:
            raise ValueError("packet splitting requires an existing timestamp capture group")
        self.scope_dir = Path(scope.directory)
        self.manifest_path = self.scope_dir / PACKET_SPLIT_MANIFEST_NAME

    def run(self) -> PacketSplitGroupResult:
        scan = self.store.scan_scope(self.spec.scope_id)
        self.corrupt = [
            {"session_dir": item.session_dir, "message": item.message}
            for item in scan.corrupt
        ]
        entries = []
        candidates = []
        for manifest in scan.sessions:
            inspection = inspect_packet_split(manifest)
            selected = (
                inspection.runnable_missing
                if self.spec.policy is PacketSplitPolicy.MISSING_ONLY
                else inspection.runnable_repair
            )
            entry = {
                "session_id": manifest.session_id,
                "session_dir": manifest.session_dir,
                "url": manifest.target.url,
                "initial_status": inspection.status.value,
                "state": "pending" if selected else "skipped",
                "final_status": inspection.status.value if not selected else None,
                "error": None,
            }
            entries.append(entry)
            if selected:
                candidates.append((manifest, entry))

        document = self._document("running", entries)
        self._save(document)
        total = len(candidates)
        completed = 0
        failed = 0
        try:
            for position, (manifest, entry) in enumerate(candidates):
                self.cancellation.checkpoint()
                # Re-scan immediately before mutation so resume and external repair
                # cannot duplicate a valid split.
                current = self.store.get(manifest.session_id)
                inspection = inspect_packet_split(current)
                selected = (
                    inspection.runnable_missing
                    if self.spec.policy is PacketSplitPolicy.MISSING_ONLY
                    else inspection.runnable_repair
                )
                if not selected:
                    entry.update(state="skipped", final_status=inspection.status.value)
                    self._save(self._document("running", entries))
                    continue
                entry["state"] = "running"
                self._save(self._document("running", entries))
                child_id = str(uuid5(UUID(self.spec.job_id), f"session:{manifest.session_id}"))
                child_spec = AnalysisJobSpec(
                    job_id=child_id,
                    session_dir=manifest.session_dir,
                    output_root=self.spec.output_root,
                    options=AnalysisJobOptions(
                        split_pcaps=True,
                        pcap_split_mode="unique_connections",
                        write_flow_index=True,
                        overwrite=True,
                    ),
                )
                try:
                    child = self.analysis_factory(
                        child_spec,
                        _SplitChildProgress(self.progress, position, max(total, 1)),
                        self.cancellation,
                    )
                    child.run()
                    final = inspect_packet_split(self.store.get(manifest.session_id))
                    if final.status not in {
                        PacketSplitStatus.COMPLETE,
                        PacketSplitStatus.COMPLETE_EMPTY,
                    }:
                        raise RuntimeError(
                            f"split verification ended as {final.status.value}: {final.reason}"
                        )
                    entry.update(state="completed", final_status=final.status.value)
                    completed += 1
                except CancelledError:
                    entry.update(
                        state="cancelled",
                        final_status=inspect_packet_split(
                            self.store.get(manifest.session_id)
                        ).status.value,
                        error={"code": "CANCELLED", "message": self.cancellation.reason},
                    )
                    self._save(self._document("cancelled", entries))
                    raise
                except Exception as exc:
                    final = inspect_packet_split(self.store.get(manifest.session_id))
                    entry.update(
                        state="failed",
                        final_status=final.status.value,
                        error={
                            "code": str(getattr(exc, "code", "PACKET_SPLIT_FAILED")),
                            "message": exception_message(exc, "packet split failed"),
                        },
                    )
                    failed += 1
                self._save(self._document("running", entries))
        except CancelledError:
            self._save(self._document("cancelled", entries))
            raise
        except Exception:
            self._save(self._document("interrupted", entries))
            raise

        state = JobState.FAILED if failed else JobState.COMPLETED
        self._save(self._document(state.value, entries))
        self.progress.finish(state, "packet split group complete")
        processed = completed + failed
        return PacketSplitGroupResult(
            job_id=self.spec.job_id,
            state=state,
            manifest_path=str(self.manifest_path),
            total_sessions=len(entries),
            processed_sessions=processed,
            completed_sessions=completed,
            failed_sessions=failed,
            skipped_sessions=len(entries) - processed,
        )

    def _document(self, state: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        created = now
        if self.manifest_path.is_file():
            try:
                existing = json.loads(self.manifest_path.read_text(encoding="utf-8"))
                if existing.get("job_id") == self.spec.job_id:
                    created = existing.get("created_at", now)
            except (OSError, ValueError):
                pass
        return {
            "schema_version": 1,
            "job_id": self.spec.job_id,
            "scope_id": self.spec.scope_id,
            "policy": self.spec.policy.value,
            "state": state,
            "created_at": created,
            "updated_at": now,
            "sessions": entries,
            "corrupt": self.corrupt,
        }

    def _save(self, payload: dict[str, Any]) -> None:
        validate_packet_split_manifest(payload)
        write_json_atomic(self.manifest_path, payload)


class _SplitChildProgress:
    def __init__(self, parent: ProgressReporter, position: int, total: int) -> None:
        self.parent = parent
        self.position = position
        self.total = total

    @property
    def stage(self):
        return JobStage.BATCH_TARGET

    @property
    def progress(self) -> float:
        return self.parent.progress

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
        mapped = (self.position + progress) / self.total
        return self.parent.emit(
            JobState.ANALYZING,
            JobStage.BATCH_TARGET,
            mapped,
            message,
            force=force,
            operation=(operation.strip() or stage.value),
        )

    def finish(self, state: JobState, message: str = "") -> None:
        # Child completion is checkpointed by the parent; it must not finish the
        # parent reporter or prevent subsequent children from emitting progress.
        return None

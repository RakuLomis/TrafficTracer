"""Immutable specifications and durable state for serial capture batches."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID

from traffictracer.config import TargetConfigPreview
from traffictracer.contracts import validate_batch_manifest, validate_job
from traffictracer.session.atomic import write_json_atomic
from traffictracer.version import BATCH_MANIFEST_SCHEMA_VERSION, JOB_SCHEMA_VERSION

from .models import CaptureInterfaces, CaptureJobOptions, ControllerSpec, JobState


BATCH_MANIFEST_NAME = "batch-manifest.json"


class BatchState(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.FAILED, self.CANCELLED}


class BatchStage(str, Enum):
    QUEUED = "queued"
    CAPTURE = "capture"
    QUIESCENCE = "quiescence"
    ANALYSIS = "analysis"
    CHECKPOINT = "checkpoint"
    FINISHED = "finished"


class BatchChildState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class BatchTarget:
    index: int
    url: str
    domain: str
    duration_seconds: int
    network: str
    run_label: str
    wait_load_timeout: int
    page_type: str = "capture"

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "url": self.url,
            "domain": self.domain,
            "duration_seconds": self.duration_seconds,
            "network": self.network,
            "run_label": self.run_label,
            "wait_load_timeout": self.wait_load_timeout,
            "page_type": self.page_type,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BatchTarget":
        return cls(
            index=payload["index"],
            url=payload["url"],
            domain=payload["domain"],
            duration_seconds=payload["duration_seconds"],
            network=payload["network"],
            run_label=payload["run_label"],
            wait_load_timeout=payload["wait_load_timeout"],
            page_type=payload.get("page_type", payload["run_label"].lower().replace("_", "-")),
        )


@dataclass(frozen=True)
class BatchJobSpec:
    job_id: str
    config_path: str
    config_sha256: str
    targets: tuple[BatchTarget, ...]
    interfaces: CaptureInterfaces
    output_root: str
    chrome_binary: str
    controller: ControllerSpec
    options: CaptureJobOptions = field(default_factory=CaptureJobOptions)
    fail_fast: bool = True
    schema_version: int = field(default=JOB_SCHEMA_VERSION, init=False)
    kind: str = field(default="batch", init=False)

    def __post_init__(self) -> None:
        if not self.targets:
            raise ValueError("capture group targets must not be empty")
        indices = [target.index for target in self.targets]
        if len(indices) != len(set(indices)):
            raise ValueError("batch target indexes must be unique")
        identities = [
            (
                target.url,
                target.domain,
                target.duration_seconds,
                target.network,
                target.run_label,
                target.wait_load_timeout,
                target.page_type,
            )
            for target in self.targets
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("capture group targets must not contain duplicates")
        if not self.options.analyze_after_capture:
            raise ValueError("capture group requires analyze_after_capture")

    @classmethod
    def from_preview(
        cls,
        preview: TargetConfigPreview,
        **kwargs,
    ) -> "BatchJobSpec":
        return cls(
            config_path=preview.config_path,
            config_sha256=preview.sha256,
            targets=tuple(BatchTarget.from_dict(item.to_dict()) for item in preview.targets),
            **kwargs,
        )

    def verify_config_sha256(self) -> None:
        try:
            path = Path(self.config_path).resolve(strict=True)
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise ValueError("batch target configuration is unavailable") from exc
        if actual != self.config_sha256:
            raise ValueError("batch target configuration SHA-256 no longer matches")

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "job_id": self.job_id,
            "config_path": self.config_path,
            "config_sha256": self.config_sha256,
            "targets": [target.to_dict() for target in self.targets],
            "interfaces": self.interfaces.to_dict(),
            "output_root": self.output_root,
            "chrome_binary": self.chrome_binary,
            "controller": self.controller.to_dict(),
            "options": self.options.to_dict(),
            "fail_fast": self.fail_fast,
        }
        if validate:
            validate_job(payload)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BatchJobSpec":
        data = dict(payload)
        validate_job(data)
        if data["kind"] != "batch":
            raise ValueError("BatchJobSpec requires kind='batch'")
        options = data["options"]
        controller = data["controller"]
        return cls(
            job_id=data["job_id"],
            config_path=data["config_path"],
            config_sha256=data["config_sha256"],
            targets=tuple(BatchTarget.from_dict(item) for item in data["targets"]),
            interfaces=CaptureInterfaces(**data["interfaces"]),
            output_root=data["output_root"],
            chrome_binary=data["chrome_binary"],
            controller=ControllerSpec(
                endpoint=controller["endpoint"],
                secret=controller.get("secret"),
                generated_config=controller.get("generated_config"),
            ),
            options=CaptureJobOptions(**options),
            fail_fast=data["fail_fast"],
        )


@dataclass(frozen=True)
class BatchError:
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class BatchChild:
    target_index: int
    state: BatchChildState = BatchChildState.PENDING
    session_id: str | None = None
    error: BatchError | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_index": self.target_index,
            "state": self.state.value,
            "session_id": self.session_id,
            "error": self.error.to_dict() if self.error else None,
        }


@dataclass(frozen=True)
class BatchResume:
    attempt: int = 0
    next_index: int = 0
    resumed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "next_index": self.next_index,
            "resumed_at": _format_time(self.resumed_at) if self.resumed_at else None,
        }


@dataclass(frozen=True)
class BatchManifest:
    batch_id: str
    state: BatchState
    stage: BatchStage
    created_at: datetime
    updated_at: datetime
    output_root: str
    config_path: str
    config_sha256: str
    interfaces: CaptureInterfaces
    chrome_binary: str
    controller_endpoint: str
    controller_generated_config: str | None
    options: CaptureJobOptions
    targets: tuple[BatchTarget, ...]
    current_index: int | None
    children: tuple[BatchChild, ...]
    fail_fast: bool
    cancel_requested: bool = False
    resume: BatchResume = field(default_factory=BatchResume)
    schema_version: int = BATCH_MANIFEST_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        spec: BatchJobSpec,
        *,
        now: datetime | None = None,
    ) -> "BatchManifest":
        timestamp = _utc(now)
        manifest = cls(
            batch_id=spec.job_id,
            state=BatchState.CREATED,
            stage=BatchStage.QUEUED,
            created_at=timestamp,
            updated_at=timestamp,
            output_root=spec.output_root,
            config_path=spec.config_path,
            config_sha256=spec.config_sha256,
            interfaces=spec.interfaces,
            chrome_binary=spec.chrome_binary,
            controller_endpoint=spec.controller.endpoint,
            controller_generated_config=spec.controller.generated_config,
            options=spec.options,
            targets=spec.targets,
            current_index=None,
            children=tuple(BatchChild(target.index) for target in spec.targets),
            fail_fast=spec.fail_fast,
        )
        manifest.to_dict()
        return manifest

    def begin(self, *, now: datetime | None = None) -> "BatchManifest":
        if self.state not in {
            BatchState.CREATED,
            BatchState.INTERRUPTED,
            BatchState.FAILED,
        }:
            raise ValueError(f"cannot begin batch from {self.state.value}")
        timestamp = _utc(now)
        resume = self.resume
        children = self.children
        if self.state in {BatchState.INTERRUPTED, BatchState.FAILED}:
            resume = replace(
                resume,
                attempt=resume.attempt + 1,
                resumed_at=timestamp,
            )
        if self.state is BatchState.FAILED and resume.next_index < len(children):
            mutable = list(children)
            mutable[resume.next_index] = replace(
                mutable[resume.next_index],
                state=BatchChildState.INTERRUPTED,
            )
            children = tuple(mutable)
        return replace(
            self,
            state=BatchState.RUNNING,
            stage=BatchStage.CAPTURE,
            updated_at=timestamp,
            resume=resume,
            children=children,
        )

    def start_child(self, target_index: int, *, now: datetime | None = None) -> "BatchManifest":
        if self.state is not BatchState.RUNNING or self.current_index is not None:
            raise ValueError("batch must be idle and running before a child starts")
        if target_index != self.resume.next_index:
            raise ValueError("batch child must start in snapshot order")
        position = target_index
        if position >= len(self.children):
            raise ValueError("batch target index is outside the snapshot")
        child = self.children[position]
        if child.state not in {BatchChildState.PENDING, BatchChildState.INTERRUPTED}:
            raise ValueError("batch child cannot be started from its current state")
        children = list(self.children)
        children[position] = replace(child, state=BatchChildState.RUNNING, error=None)
        return replace(
            self,
            current_index=target_index,
            stage=BatchStage.CAPTURE,
            children=tuple(children),
            updated_at=_utc(now),
        )

    def set_stage(self, stage: BatchStage, *, now: datetime | None = None) -> "BatchManifest":
        if self.state is not BatchState.RUNNING or self.current_index is None:
            raise ValueError("batch stage requires a running child")
        if stage not in {
            BatchStage.CAPTURE,
            BatchStage.QUIESCENCE,
            BatchStage.ANALYSIS,
            BatchStage.CHECKPOINT,
        }:
            raise ValueError("invalid active batch stage")
        return replace(self, stage=stage, updated_at=_utc(now))

    def attach_child_session(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> "BatchManifest":
        if self.state is not BatchState.RUNNING or self.current_index is None:
            raise ValueError("batch has no running child for Session attachment")
        position = self.current_index
        child = self.children[position]
        if child.state is not BatchChildState.RUNNING:
            raise ValueError("batch child is not running")
        children = list(self.children)
        children[position] = replace(child, session_id=session_id)
        return replace(self, children=tuple(children), updated_at=_utc(now))

    def finish_child(
        self,
        state: BatchChildState,
        *,
        session_id: str | None = None,
        error: BatchError | None = None,
        now: datetime | None = None,
    ) -> "BatchManifest":
        if self.state is not BatchState.RUNNING or self.current_index is None:
            raise ValueError("batch has no running child")
        if state not in {
            BatchChildState.COMPLETED,
            BatchChildState.FAILED,
            BatchChildState.CANCELLED,
            BatchChildState.INTERRUPTED,
        }:
            raise ValueError("batch child requires a terminal checkpoint state")
        position = self.current_index
        if self.children[position].state is not BatchChildState.RUNNING:
            raise ValueError("batch child state is not running")
        children = list(self.children)
        children[position] = BatchChild(
            self.children[position].target_index,
            state,
            session_id,
            error,
        )
        retry_current = (
            state in {BatchChildState.CANCELLED, BatchChildState.INTERRUPTED}
            or (state is BatchChildState.FAILED and self.fail_fast)
        )
        next_index = position if retry_current else position + 1
        batch_state = BatchState.RUNNING
        stage = BatchStage.CHECKPOINT
        if state is BatchChildState.CANCELLED or self.cancel_requested:
            batch_state, stage = BatchState.CANCELLED, BatchStage.FINISHED
        elif state is BatchChildState.INTERRUPTED:
            batch_state, stage = BatchState.INTERRUPTED, BatchStage.FINISHED
        elif state is BatchChildState.FAILED and self.fail_fast:
            batch_state, stage = BatchState.FAILED, BatchStage.FINISHED
        elif next_index == len(self.children):
            batch_state, stage = (
                (BatchState.FAILED, BatchStage.FINISHED)
                if any(item.state is BatchChildState.FAILED for item in children)
                else (BatchState.COMPLETED, BatchStage.FINISHED)
            )
        return replace(
            self,
            state=batch_state,
            stage=stage,
            current_index=None,
            children=tuple(children),
            resume=replace(self.resume, next_index=next_index),
            updated_at=_utc(now),
        )

    def request_cancel(self, *, now: datetime | None = None) -> "BatchManifest":
        if self.state.terminal:
            return self
        return replace(self, cancel_requested=True, updated_at=_utc(now))

    def stop(
        self,
        state: BatchState,
        *,
        now: datetime | None = None,
    ) -> "BatchManifest":
        if self.state is not BatchState.RUNNING or self.current_index is not None:
            raise ValueError("only an idle running batch can stop directly")
        if state not in {
            BatchState.FAILED,
            BatchState.CANCELLED,
            BatchState.INTERRUPTED,
        }:
            raise ValueError("invalid direct batch stop state")
        return replace(
            self,
            state=state,
            stage=BatchStage.FINISHED,
            updated_at=_utc(now),
        )

    def cancel_inactive(self, *, now: datetime | None = None) -> "BatchManifest":
        if self.state is BatchState.CANCELLED:
            return self
        if self.state not in {
            BatchState.CREATED,
            BatchState.FAILED,
            BatchState.INTERRUPTED,
        }:
            raise ValueError("active or completed batch cannot be cancelled as inactive")
        return replace(
            self,
            state=BatchState.CANCELLED,
            stage=BatchStage.FINISHED,
            cancel_requested=True,
            current_index=None,
            updated_at=_utc(now),
        )

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "batch_id": self.batch_id,
            "state": self.state.value,
            "stage": self.stage.value,
            "created_at": _format_time(self.created_at),
            "updated_at": _format_time(self.updated_at),
            "output_root": self.output_root,
            "config": {"path": self.config_path, "sha256": self.config_sha256},
            "execution": {
                "interfaces": self.interfaces.to_dict(),
                "chrome_binary": self.chrome_binary,
                "controller_endpoint": self.controller_endpoint,
                "controller_generated_config": self.controller_generated_config,
                "options": self.options.to_dict(),
            },
            "targets": [target.to_dict() for target in self.targets],
            "current_index": self.current_index,
            "children": [child.to_dict() for child in self.children],
            "fail_fast": self.fail_fast,
            "cancel_requested": self.cancel_requested,
            "resume": self.resume.to_dict(),
        }
        if validate:
            validate_batch_manifest(payload)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BatchManifest":
        data = dict(payload)
        validate_batch_manifest(data)
        config = data["config"]
        execution = data["execution"]
        children = tuple(
            BatchChild(
                target_index=item["target_index"],
                state=BatchChildState(item["state"]),
                session_id=item["session_id"],
                error=BatchError(**item["error"]) if item["error"] else None,
            )
            for item in data["children"]
        )
        manifest = cls(
            batch_id=data["batch_id"],
            state=BatchState(data["state"]),
            stage=BatchStage(data["stage"]),
            created_at=_parse_time(data["created_at"]),
            updated_at=_parse_time(data["updated_at"]),
            output_root=data["output_root"],
            config_path=config["path"],
            config_sha256=config["sha256"],
            interfaces=CaptureInterfaces(**execution["interfaces"]),
            chrome_binary=execution["chrome_binary"],
            controller_endpoint=execution["controller_endpoint"],
            controller_generated_config=execution["controller_generated_config"],
            options=CaptureJobOptions(**execution["options"]),
            targets=tuple(BatchTarget.from_dict(item) for item in data["targets"]),
            current_index=data["current_index"],
            children=children,
            fail_fast=data["fail_fast"],
            cancel_requested=data["cancel_requested"],
            resume=BatchResume(
                attempt=data["resume"]["attempt"],
                next_index=data["resume"]["next_index"],
                resumed_at=(
                    _parse_time(data["resume"]["resumed_at"])
                    if data["resume"]["resumed_at"] else None
                ),
            ),
            schema_version=data["schema_version"],
        )
        manifest._validate_consistency()
        return manifest

    def to_job_spec(self, *, controller_secret: str | None = None) -> BatchJobSpec:
        return BatchJobSpec(
            job_id=self.batch_id,
            config_path=self.config_path,
            config_sha256=self.config_sha256,
            targets=self.targets,
            interfaces=self.interfaces,
            output_root=self.output_root,
            chrome_binary=self.chrome_binary,
            controller=ControllerSpec(
                endpoint=self.controller_endpoint,
                secret=controller_secret,
                generated_config=self.controller_generated_config,
            ),
            options=self.options,
            fail_fast=self.fail_fast,
        )

    def persist(self, directory: str | Path) -> Path:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = root / BATCH_MANIFEST_NAME
        write_json_atomic(path, self.to_dict())
        return path

    @classmethod
    def load(cls, path: str | Path) -> "BatchManifest":
        import json

        with Path(path).open(encoding="utf-8") as stream:
            return cls.from_dict(json.load(stream))

    def _child_position(self, target_index: int) -> int:
        for position, child in enumerate(self.children):
            if child.target_index == target_index:
                return position
        raise ValueError("batch target index is not in the snapshot")

    def _validate_consistency(self) -> None:
        target_indices = [target.index for target in self.targets]
        child_indices = [child.target_index for child in self.children]
        if not target_indices or target_indices != child_indices:
            raise ValueError("batch children must exactly match target snapshot order")
        if self.resume.next_index > len(self.targets):
            raise ValueError("batch resume index exceeds target snapshot")
        running = [
            position
            for position, child in enumerate(self.children)
            if child.state is BatchChildState.RUNNING
        ]
        if running != ([] if self.current_index is None else [self.current_index]):
            raise ValueError("batch current index does not match running child")


def _utc(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("batch timestamp must be timezone-aware")
    return timestamp.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


@dataclass(frozen=True)
class BatchJobResult:
    job_id: str
    state: JobState
    manifest_path: str
    session_ids: tuple[str, ...]
    completed_targets: int
    total_targets: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state.value,
            "manifest_path": self.manifest_path,
            "session_ids": list(self.session_ids),
            "completed_targets": self.completed_targets,
            "total_targets": self.total_targets,
        }


@dataclass(frozen=True)
class BatchScanError:
    path: str
    message: str


@dataclass(frozen=True)
class BatchScan:
    batches: tuple[BatchManifest, ...]
    corrupt: tuple[BatchScanError, ...]


class BatchStore:
    """Path-safe access and startup recovery for persisted batch manifests."""

    def __init__(self, output_root: str | Path) -> None:
        self.root = Path(output_root).resolve() / ".batches"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def path(self, batch_id: str) -> Path:
        canonical = str(UUID(batch_id))
        candidate = self.root / canonical
        if candidate.is_symlink():
            raise ValueError("batch directory must not be a symlink")
        return candidate / BATCH_MANIFEST_NAME

    def get(self, batch_id: str) -> BatchManifest:
        path = self.path(batch_id)
        if not path.is_file():
            raise FileNotFoundError("batch manifest does not exist")
        manifest = BatchManifest.load(path)
        if manifest.batch_id != str(UUID(batch_id)):
            raise ValueError("batch manifest ID does not match directory")
        return manifest

    def save(self, manifest: BatchManifest) -> Path:
        return manifest.persist(self.path(manifest.batch_id).parent)

    def scan(self) -> BatchScan:
        batches = []
        corrupt = []
        for directory in self.root.iterdir():
            if not directory.is_dir() or directory.is_symlink():
                continue
            path = directory / BATCH_MANIFEST_NAME
            if not path.is_file():
                continue
            try:
                manifest = BatchManifest.load(path)
                if directory.name != str(UUID(manifest.batch_id)):
                    raise ValueError("batch directory does not match manifest ID")
                batches.append(manifest)
            except (OSError, ValueError) as exc:
                corrupt.append(BatchScanError(str(path), str(exc)))
        batches.sort(key=lambda item: (item.updated_at, item.batch_id), reverse=True)
        corrupt.sort(key=lambda item: item.path)
        return BatchScan(tuple(batches), tuple(corrupt))

    def recover_running(self) -> tuple[str, ...]:
        recovered = []
        for manifest in self.scan().batches:
            if manifest.state is not BatchState.RUNNING:
                continue
            if manifest.current_index is None:
                interrupted = manifest.stop(BatchState.INTERRUPTED)
            else:
                interrupted = manifest.finish_child(
                    BatchChildState.INTERRUPTED,
                    session_id=manifest.children[manifest.current_index].session_id,
                    error=BatchError(
                        "WORKER_RESTARTED",
                        "Worker restarted before the child checkpoint completed.",
                    ),
                )
            self.save(interrupted)
            recovered.append(manifest.batch_id)
        return tuple(recovered)

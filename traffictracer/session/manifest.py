"""Versioned, immutable TrafficTracer Complete Session manifests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping

from traffictracer.contracts import validate_session, validate_session_v2
from traffictracer.jobs.models import JobState
from traffictracer.version import SESSION_SCHEMA_VERSION, WORKER_API_VERSION


_TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.CREATED: frozenset(
        {JobState.PREPARING, JobState.CANCELLED, JobState.FAILED, JobState.INTERRUPTED}
    ),
    JobState.PREPARING: frozenset(
        {JobState.CAPTURING, JobState.CANCELLED, JobState.FAILED, JobState.INTERRUPTED}
    ),
    JobState.CAPTURING: frozenset(
        {
            JobState.ANALYZING,
            JobState.COMPLETED,
            JobState.CANCELLED,
            JobState.FAILED,
            JobState.INTERRUPTED,
        }
    ),
    JobState.ANALYZING: frozenset(
        {JobState.COMPLETED, JobState.CANCELLED, JobState.FAILED, JobState.INTERRUPTED}
    ),
    JobState.COMPLETED: frozenset(),
    JobState.FAILED: frozenset(),
    JobState.CANCELLED: frozenset(),
    JobState.INTERRUPTED: frozenset(),
}


class SessionTransitionError(ValueError):
    """Raised when a Session state transition violates the lifecycle."""


@dataclass(frozen=True)
class SessionTarget:
    url: str
    domain: str
    source: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"url": self.url, "domain": self.domain}
        if self.source is not None:
            payload["source"] = dict(self.source)
        return payload


@dataclass(frozen=True)
class ComponentVersion:
    version: str
    commit: str

    def to_dict(self) -> dict[str, str]:
        return {"version": self.version, "commit": self.commit}


@dataclass(frozen=True)
class ComponentVersions:
    traffictracer: ComponentVersion
    mihomo: ComponentVersion
    clash_verge_rev: ComponentVersion
    worker_api: int = WORKER_API_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "traffictracer": self.traffictracer.to_dict(),
            "mihomo": self.mihomo.to_dict(),
            "clash_verge_rev": self.clash_verge_rev.to_dict(),
            "worker_api": self.worker_api,
        }


@dataclass(frozen=True)
class Artifact:
    name: str
    path: str
    media_type: str
    size_bytes: int
    kind: str = ""
    artifact_id: str = ""
    phase: str = ""
    role: str = ""
    generation_id: str | None = None
    sha256: str | None = None
    created_at: datetime | None = None

    def to_dict(self, *, schema_version: int = SESSION_SCHEMA_VERSION) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "path": self.path,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
        }
        if schema_version == 1:
            payload["kind"] = self.kind or _legacy_kind(self.phase)
        else:
            payload.update({
                "artifact_id": self.artifact_id or _artifact_id(self.path),
                "phase": self.phase or _phase(self.kind),
                "role": self.role or _role(self.path),
            })
            if self.generation_id is not None:
                payload["generation_id"] = self.generation_id
        if self.sha256 is not None:
            payload["sha256"] = self.sha256
        if self.created_at is not None:
            payload["created_at"] = _format_time(self.created_at)
        return payload


@dataclass(frozen=True)
class SessionError:
    code: str
    message: str
    stage: str | None = None

    def to_dict(self) -> dict[str, str]:
        payload = {"code": self.code, "message": self.message}
        if self.stage is not None:
            payload["stage"] = self.stage
        return payload


@dataclass(frozen=True)
class SessionManifest:
    session_id: str
    job_id: str
    state: JobState
    created_at: datetime
    updated_at: datetime
    session_dir: str
    target: SessionTarget
    component_versions: ComponentVersions
    started_at: datetime | None = None
    completed_at: datetime | None = None
    artifacts: tuple[Artifact, ...] = ()
    warnings: tuple[str, ...] = ()
    error: SessionError | None = None
    schema_version: int = SESSION_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        job_id: str,
        session_dir: str,
        target: SessionTarget,
        component_versions: ComponentVersions,
        now: datetime | None = None,
    ) -> SessionManifest:
        timestamp = _utc(now)
        manifest = cls(
            session_id=session_id,
            job_id=job_id,
            state=JobState.CREATED,
            created_at=timestamp,
            updated_at=timestamp,
            session_dir=session_dir,
            target=target,
            component_versions=component_versions,
            schema_version=SESSION_SCHEMA_VERSION,
        )
        manifest.validate()
        return manifest

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SessionManifest:
        data = dict(payload)
        schema_version = data.get("schema_version")
        if schema_version == 1:
            validate_session(data)
        elif schema_version == 2:
            validate_session_v2(data)
        else:
            raise ValueError(f"unsupported Session schema_version: {schema_version}")
        versions = data["component_versions"]
        error = data.get("error")
        manifest = cls(
            session_id=data["session_id"],
            job_id=data["job_id"],
            state=JobState(data["state"]),
            created_at=_parse_time(data["created_at"]),
            updated_at=_parse_time(data["updated_at"]),
            started_at=_parse_optional_time(data.get("started_at")),
            completed_at=_parse_optional_time(data.get("completed_at")),
            session_dir=data["session_dir"],
            target=SessionTarget(**data["target"]),
            component_versions=ComponentVersions(
                traffictracer=ComponentVersion(**versions["traffictracer"]),
                mihomo=ComponentVersion(**versions["mihomo"]),
                clash_verge_rev=ComponentVersion(**versions["clash_verge_rev"]),
                worker_api=versions["worker_api"],
            ),
            artifacts=tuple(
                _artifact_from_dict(item, schema_version)
                for item in data["artifacts"]
            ),
            warnings=tuple(data["warnings"]),
            error=SessionError(**error) if error is not None else None,
            schema_version=schema_version,
        )
        manifest.validate()
        return manifest

    @classmethod
    def load(cls, path: str | Path) -> SessionManifest:
        with Path(path).open(encoding="utf-8") as stream:
            payload = json.load(stream)
        if not isinstance(payload, dict):
            raise ValueError("Session manifest must contain a JSON object")
        return cls.from_dict(payload)

    def transition(
        self,
        new_state: JobState,
        *,
        error: SessionError | None = None,
        now: datetime | None = None,
    ) -> SessionManifest:
        self._require_writable()
        if new_state not in _TRANSITIONS[self.state]:
            raise SessionTransitionError(
                f"invalid Session transition: {self.state.value} -> {new_state.value}"
            )
        if new_state is JobState.FAILED and error is None:
            raise SessionTransitionError("failed Session transition requires an error")
        if new_state is not JobState.FAILED and error is not None:
            raise SessionTransitionError("error details are only valid for failed Sessions")

        timestamp = self._updated_time(now)
        started_at = self.started_at
        if started_at is None and new_state is JobState.PREPARING:
            started_at = timestamp
        completed_at = timestamp if new_state.terminal else None
        result = replace(
            self,
            state=new_state,
            updated_at=timestamp,
            started_at=started_at,
            completed_at=completed_at,
            error=error,
        )
        result.validate()
        return result

    def begin_analysis_retry(
        self,
        *,
        now: datetime | None = None,
    ) -> SessionManifest:
        """Reopen only a failed v2 analysis while preserving captured evidence."""
        self._require_writable()
        if self.state is not JobState.FAILED or self.error is None:
            raise SessionTransitionError(
                "analysis retry requires a failed Session"
            )
        if self.error.code not in {
            "ANALYSIS_FAILED",
            "ANALYSIS_CONSISTENCY_FAILED",
        }:
            raise SessionTransitionError(
                "only an analysis failure can be retried"
            )
        result = replace(
            self,
            state=JobState.ANALYZING,
            updated_at=self._updated_time(now),
            completed_at=None,
            error=None,
        )
        result.validate()
        return result

    def with_artifact(self, artifact: Artifact, *, now: datetime | None = None) -> SessionManifest:
        self._require_writable()
        result = replace(
            self,
            artifacts=(*self.artifacts, artifact),
            updated_at=self._updated_time(now),
        )
        result.validate()
        return result

    def with_warning(self, warning: str, *, now: datetime | None = None) -> SessionManifest:
        self._require_writable()
        normalized = warning.strip()
        if not normalized:
            raise ValueError("warning must not be empty")
        result = replace(
            self,
            warnings=(*self.warnings, normalized),
            updated_at=self._updated_time(now),
        )
        result.validate()
        return result

    def _updated_time(self, value: datetime | None) -> datetime:
        timestamp = _utc(value)
        if timestamp < self.updated_at:
            raise ValueError("Session update timestamp cannot move backward")
        return timestamp

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "job_id": self.job_id,
            "state": self.state.value,
            "created_at": _format_time(self.created_at),
            "updated_at": _format_time(self.updated_at),
            "session_dir": self.session_dir,
            "target": self.target.to_dict(),
            "component_versions": self.component_versions.to_dict(),
            "artifacts": [
                artifact.to_dict(schema_version=self.schema_version)
                for artifact in self.artifacts
            ],
            "warnings": list(self.warnings),
        }
        if self.started_at is not None:
            payload["started_at"] = _format_time(self.started_at)
        if self.completed_at is not None:
            payload["completed_at"] = _format_time(self.completed_at)
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        if validate:
            self._validate_contract(payload)
        return payload

    def validate(self) -> None:
        self._validate_contract(self.to_dict(validate=False))
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.started_at is not None and self.started_at < self.created_at:
            raise ValueError("started_at cannot precede created_at")
        if self.completed_at is not None and not self.state.terminal:
            raise ValueError("completed_at is only valid for terminal Sessions")
        if self.state.terminal and self.completed_at is None:
            raise ValueError("terminal Sessions require completed_at")
        if self.completed_at is not None and self.completed_at > self.updated_at:
            raise ValueError("completed_at cannot follow updated_at")
        if self.state is JobState.COMPLETED and self.started_at is None:
            raise ValueError("completed Sessions require started_at")
        if self.state is JobState.FAILED and self.error is None:
            raise ValueError("failed Sessions require error details")
        if self.state is not JobState.FAILED and self.error is not None:
            raise ValueError("error details are only valid for failed Sessions")

    @property
    def read_only(self) -> bool:
        return self.schema_version == 1

    def _require_writable(self) -> None:
        if self.read_only:
            raise ValueError("Session v1 manifest is read-only")

    def _validate_contract(self, payload: dict[str, Any]) -> None:
        if self.schema_version == 1:
            validate_session(payload)
        else:
            validate_session_v2(payload)


def _artifact_from_dict(data: Mapping[str, Any], schema_version: int) -> Artifact:
    phase = data.get("phase", "")
    return Artifact(
        name=data["name"],
        path=data["path"],
        media_type=data["media_type"],
        size_bytes=data["size_bytes"],
        kind=data.get("kind", _legacy_kind(phase)),
        artifact_id=data.get("artifact_id", ""),
        phase=phase,
        role=data.get("role", ""),
        generation_id=data.get("generation_id"),
        sha256=data.get("sha256"),
        created_at=_parse_optional_time(data.get("created_at")),
    )


def _phase(kind: str) -> str:
    return {
        "raw": "capture",
        "derived": "analysis",
        "diagnostic": "diagnostic",
    }.get(kind, "diagnostic")


def _legacy_kind(phase: str) -> str:
    return {
        "capture": "raw",
        "analysis": "derived",
        "diagnostic": "diagnostic",
    }.get(phase, "diagnostic")


def _artifact_id(path: str) -> str:
    import hashlib
    import re

    stem = re.sub(r"[^a-z0-9_-]+", "-", Path(path).stem.lower()).strip("-")
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:12]
    return f"artifact-{(stem or 'file')[:37]}-{digest}"


def _role(path: str) -> str:
    name = Path(path).name
    exact = {
        "tun.pcap": "tun_pcap",
        "phys.pcap": "physical_pcap",
        "capture_context.json": "capture_context",
        "capture-context.json": "capture_context",
        "mihomo-trace.jsonl": "mihomo_trace",
        "netlog.json": "netlog",
        "cdp.json": "cdp_events",
        "connection-index-v2.json": "connection_index",
        "request-index-v2.json": "request_index",
        "flow-index.json": "flow_index",
        "pcap-index-v1.json": "pcap_index",
        "summary.json": "coverage_summary",
    }
    if name in exact:
        return exact[name]
    if name.endswith(".pcap"):
        return "derived_pcap"
    if name.startswith("mihomo_trace_"):
        return "mihomo_trace"
    if name.startswith("netlog_"):
        return "netlog"
    if name.startswith("cdp_"):
        return "cdp_events"
    return "other"


def _utc(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("Session timestamps must be timezone-aware")
    return timestamp.astimezone(timezone.utc)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _parse_optional_time(value: str | None) -> datetime | None:
    return _parse_time(value) if value is not None else None


def _format_time(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")

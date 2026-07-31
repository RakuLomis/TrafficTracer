"""Typed, YAML-independent models for Complete capture jobs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from traffictracer.contracts import validate_job
from traffictracer.version import JOB_SCHEMA_VERSION


class JobState(str, Enum):
    CREATED = "created"
    PREPARING = "preparing"
    CAPTURING = "capturing"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"

    @property
    def terminal(self) -> bool:
        return self in {
            JobState.COMPLETED,
            JobState.FAILED,
            JobState.CANCELLED,
            JobState.INTERRUPTED,
        }


@dataclass(frozen=True)
class CaptureInterfaces:
    tun: str
    physical: str

    def to_dict(self) -> dict[str, str]:
        return {"tun": self.tun, "physical": self.physical}


@dataclass(frozen=True)
class ControllerSpec:
    endpoint: str
    secret: str | None = None
    generated_config: str | None = None

    def to_dict(self) -> dict[str, str]:
        payload = {"endpoint": self.endpoint}
        if self.secret is not None:
            payload["secret"] = self.secret
        if self.generated_config is not None:
            payload["generated_config"] = self.generated_config
        return payload


@dataclass(frozen=True)
class CaptureJobOptions:
    capture_packets: bool = True
    collect_cdp: bool = True
    collect_netlog: bool = True
    analyze_after_capture: bool = True
    headless: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "capture_packets": self.capture_packets,
            "collect_cdp": self.collect_cdp,
            "collect_netlog": self.collect_netlog,
            "analyze_after_capture": self.analyze_after_capture,
            "headless": self.headless,
        }


@dataclass(frozen=True)
class CaptureJobSpec:
    job_id: str
    url: str
    domain: str
    duration_seconds: int
    network: str
    interfaces: CaptureInterfaces
    output_root: str
    chrome_binary: str
    controller: ControllerSpec
    options: CaptureJobOptions = field(default_factory=CaptureJobOptions)

    schema_version: int = field(default=JOB_SCHEMA_VERSION, init=False)
    kind: str = field(default="capture", init=False)

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "job_id": self.job_id,
            "url": self.url,
            "domain": self.domain,
            "duration_seconds": self.duration_seconds,
            "network": self.network,
            "interfaces": self.interfaces.to_dict(),
            "output_root": self.output_root,
            "chrome_binary": self.chrome_binary,
            "controller": self.controller.to_dict(),
            "options": self.options.to_dict(),
        }
        if validate:
            validate_job(payload)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CaptureJobSpec:
        data = dict(payload)
        validate_job(data)
        if data["kind"] != "capture":
            raise ValueError("CaptureJobSpec requires kind='capture'")
        interfaces = data["interfaces"]
        controller = data["controller"]
        options = data.get("options", {})
        return cls(
            job_id=data["job_id"],
            url=data["url"],
            domain=data["domain"],
            duration_seconds=data["duration_seconds"],
            network=data["network"],
            interfaces=CaptureInterfaces(
                tun=interfaces["tun"],
                physical=interfaces["physical"],
            ),
            output_root=data["output_root"],
            chrome_binary=data["chrome_binary"],
            controller=ControllerSpec(
                endpoint=controller["endpoint"],
                secret=controller.get("secret"),
                generated_config=controller.get("generated_config"),
            ),
            options=CaptureJobOptions(
                capture_packets=options.get("capture_packets", True),
                collect_cdp=options.get("collect_cdp", True),
                collect_netlog=options.get("collect_netlog", True),
                analyze_after_capture=options.get("analyze_after_capture", True),
                headless=options.get("headless", False),
            ),
        )


@dataclass(frozen=True)
class ProgressEvent:
    job_id: str
    state: JobState
    stage: str
    progress: float
    message: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state.value,
            "stage": self.stage,
            "progress": self.progress,
            "message": self.message,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
        }


@dataclass(frozen=True)
class CaptureJobResult:
    job_id: str
    state: JobState
    session_id: str = ""
    artifacts: tuple[str, ...] = ()
    error_code: str = ""
    error_message: str = ""

    def __post_init__(self) -> None:
        if not self.state.terminal:
            raise ValueError("CaptureJobResult requires a terminal JobState")

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state.value,
            "session_id": self.session_id,
            "artifacts": list(self.artifacts),
            "error_code": self.error_code,
            "error_message": self.error_message,
        }

"""Typed, YAML-independent models for Complete capture jobs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from traffictracer.contracts import validate_job
from traffictracer.playback import PlaybackPolicy
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
    pcap_split_mode: str = "unique_connections"
    cache_mode: str = "cold"
    proxy_protocol_mode: str = "strict_single"
    expected_proxy_protocol: str = ""

    def __post_init__(self) -> None:
        if self.pcap_split_mode not in {"none", "unique_connections"}:
            raise ValueError(
                "pcap_split_mode must be none or unique_connections"
            )
        if self.cache_mode not in {"cold", "warm"}:
            raise ValueError("cache_mode must be cold or warm")
        if self.proxy_protocol_mode not in {"strict_single", "observe"}:
            raise ValueError(
                "proxy_protocol_mode must be strict_single or observe"
            )
        normalized_protocol = self.expected_proxy_protocol.replace(
            "-", "",
        ).replace("_", "")
        if self.expected_proxy_protocol and not normalized_protocol.isalnum():
            raise ValueError("expected_proxy_protocol must be a protocol name")

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_packets": self.capture_packets,
            "collect_cdp": self.collect_cdp,
            "collect_netlog": self.collect_netlog,
            "analyze_after_capture": self.analyze_after_capture,
            "headless": self.headless,
            "pcap_split_mode": self.pcap_split_mode,
            "cache_mode": self.cache_mode,
            "proxy_protocol_mode": self.proxy_protocol_mode,
            "expected_proxy_protocol": self.expected_proxy_protocol,
        }


@dataclass(frozen=True)
class TargetSource:
    mode: str = "manual"
    config_path: str | None = None
    config_sha256: str | None = None
    target_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        if self.mode == "manual":
            return {"mode": "manual"}
        if self.mode != "config":
            raise ValueError("target source mode must be manual or config")
        if self.config_path is None or self.config_sha256 is None or self.target_index is None:
            raise ValueError("config target source requires path, SHA-256 and target index")
        return {
            "mode": "config",
            "config_path": self.config_path,
            "config_sha256": self.config_sha256,
            "target_index": self.target_index,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> TargetSource:
        data = dict(payload or {"mode": "manual"})
        return cls(
            mode=data.get("mode", "manual"),
            config_path=data.get("config_path"),
            config_sha256=data.get("config_sha256"),
            target_index=data.get("target_index"),
        )


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
    wait_load_timeout: int = 30
    run_label: str = "all"
    target_source: TargetSource = field(default_factory=TargetSource)
    page_type: str = "capture"
    capture_group: str = ""
    playback: PlaybackPolicy | None = None

    schema_version: int = field(default=JOB_SCHEMA_VERSION, init=False)
    kind: str = field(default="capture", init=False)

    def __post_init__(self) -> None:
        if self.playback is None:
            return
        if not self.options.collect_cdp:
            raise ValueError("playback observation requires CDP collection")
        if self.playback.desired_primary_seconds > self.duration_seconds:
            raise ValueError(
                "playback desired_primary_seconds cannot exceed duration_seconds"
            )

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
            "wait_load_timeout": self.wait_load_timeout,
            "run_label": self.run_label,
            "target_source": self.target_source.to_dict(),
            "page_type": self.page_type,
            "capture_group": self.capture_group,
        }
        if self.playback is not None:
            payload["playback"] = self.playback.to_dict()
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
                pcap_split_mode=options.get(
                    "pcap_split_mode", "unique_connections",
                ),
                # Missing means a job written before cache policy existed.
                cache_mode=options.get("cache_mode", "warm"),
                proxy_protocol_mode=options.get(
                    "proxy_protocol_mode", "strict_single",
                ),
                expected_proxy_protocol=options.get("expected_proxy_protocol", ""),
            ),
            wait_load_timeout=data.get("wait_load_timeout", 30),
            run_label=data.get("run_label", data["network"]),
            target_source=TargetSource.from_dict(data.get("target_source")),
            page_type=data.get("page_type", data.get("run_label", "capture")).lower().replace("_", "-"),
            capture_group=data.get("capture_group", ""),
            playback=PlaybackPolicy.from_dict(data.get("playback")),
        )


@dataclass(frozen=True)
class AnalysisJobOptions:
    split_pcaps: bool = True
    pcap_split_mode: str = "unique_connections"
    write_flow_index: bool = True
    overwrite: bool = False

    def to_dict(self) -> dict[str, bool | str]:
        return {
            "split_pcaps": self.split_pcaps,
            "pcap_split_mode": self.pcap_split_mode,
            "write_flow_index": self.write_flow_index,
            "overwrite": self.overwrite,
        }


@dataclass(frozen=True)
class AnalysisJobSpec:
    job_id: str
    session_dir: str
    output_root: str
    options: AnalysisJobOptions = field(default_factory=AnalysisJobOptions)

    schema_version: int = field(default=JOB_SCHEMA_VERSION, init=False)
    kind: str = field(default="analysis", init=False)

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "job_id": self.job_id,
            "session_dir": self.session_dir,
            "output_root": self.output_root,
            "options": self.options.to_dict(),
        }
        if validate:
            validate_job(payload)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AnalysisJobSpec:
        data = dict(payload)
        validate_job(data)
        if data["kind"] != "analysis":
            raise ValueError("AnalysisJobSpec requires kind='analysis'")
        options = data.get("options", {})
        split_pcaps = options.get("split_pcaps", True)
        return cls(
            job_id=data["job_id"],
            session_dir=data["session_dir"],
            output_root=data["output_root"],
            options=AnalysisJobOptions(
                split_pcaps=split_pcaps,
                pcap_split_mode=options.get(
                    "pcap_split_mode",
                    "unique_connections" if split_pcaps else "none",
                ),
                write_flow_index=options.get("write_flow_index", True),
                overwrite=options.get("overwrite", False),
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

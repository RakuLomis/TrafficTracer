"""Shared data model types for TrafficTracer 2.0 CDP-attribution pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FlowTuple:
    network: str
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    dst_host: str = ""
    key: str = ""
    complete: bool = False
    source: str = ""
    scope: str = ""
    shared: bool = False

    @property
    def src(self) -> str:
        return _format_endpoint(self.src_ip, self.src_port)

    @property
    def dst(self) -> str:
        return _format_endpoint(self.dst_ip, self.dst_port)


def _format_endpoint(ip: str, port: int) -> str:
    if not ip:
        return ""
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{port}" if port else host


@dataclass
class AttributedRequest:
    request_id: str
    target_id: str
    frame_id: str
    url: str
    resource_type: str
    timestamp: float
    target_type: str = "page"
    loader_id: str = ""
    initiator_type: str = ""
    connection_id: int | None = None
    remote_ip: str = ""
    remote_port: int = 0
    connection_reused: bool = False
    response_status: int = 0
    from_disk_cache: bool = False
    from_service_worker: bool = False
    from_prefetch_cache: bool = False
    response_timestamp: float = 0.0
    completion_timestamp: float = 0.0
    failed: bool = False
    canceled: bool = False
    failure_reason: str = ""
    redirect_index: int = 0
    redirect_from_url: str = ""
    redirect_status: int = 0


@dataclass
class TransportConnection:
    netlog_source_id: int
    url: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    request_ids: list[str] = field(default_factory=list)
    first_observed: float | None = None
    last_observed: float | None = None
    network: str = ""
    attempted_protocols: list[str] = field(default_factory=list)
    application_protocol: str = "unknown"
    first_observed_utc: float | None = None
    last_observed_utc: float | None = None


@dataclass(frozen=True)
class FlowTerminal:
    status: str
    stage: str = ""
    error: str = ""
    bytes_up: int = 0
    bytes_down: int = 0
    duration_ms: int = 0
    error_class: str = ""
    error_class_source: str = "unavailable"


@dataclass
class CorrelatedFlowV2:
    url: str
    resource_type: str
    target_type: str
    relation: str
    pre_proxy_src: str
    pre_proxy_dst: str
    post_proxy_src: str
    post_proxy_dst: str
    protocol: str
    request_ids: list[str] = field(default_factory=list)
    connection_reused: bool = False
    pre_flow: FlowTuple | None = None
    post_flow: FlowTuple | None = None
    match_status: str = "legacy"
    match_confidence: float = 0.5
    conn_id: str = ""
    outer_conn_id: str = ""
    stable_connection_id: str = ""
    match_method: str = "none"
    match_candidates: list[dict] = field(default_factory=list)
    match_reason: str = ""
    match_evidence: list[str] = field(default_factory=list)
    terminal: FlowTerminal | None = None
    netlog_source_id: int | None = None
    proxy: str = ""
    proxy_type: str = ""
    leaf_proxy: str = ""
    leaf_proxy_type: str = ""
    egress_outcome: str = ""
    application_protocol: str = "unknown"
    attempted_protocols: list[str] = field(default_factory=list)
    first_observed: float | None = None
    last_observed: float | None = None
    first_observed_utc: float | None = None
    last_observed_utc: float | None = None


@dataclass
class VisitCorrelation:
    visit_url: str
    domain: str
    flows: list[CorrelatedFlowV2] = field(default_factory=list)
    cdp_request_count: int = 0
    netlog_connection_count: int = 0
    requests: list[AttributedRequest] = field(default_factory=list)

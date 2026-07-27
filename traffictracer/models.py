# traffictracer/models.py
"""Shared data model types for TrafficTracer 2.0 CDP-attribution pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field


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


@dataclass
class VisitCorrelation:
    visit_url: str
    domain: str
    flows: list[CorrelatedFlowV2] = field(default_factory=list)
    cdp_request_count: int = 0
    netlog_connection_count: int = 0

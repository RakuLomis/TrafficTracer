"""Exact pre-proxy to post-proxy flow lookup over a tracing JSONL file."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from ..models import FlowTuple
from .mihomo_log import MihomoConnection, UdpConnection, parse_tracing_log, parse_udp_tracing_log


@dataclass(frozen=True)
class FlowMapping:
    connection_id: str
    outer_conn_id: str
    pre_flow: FlowTuple
    post_flow: FlowTuple | None
    status: str
    error: str = ""
    stage: str = ""
    error_class: str = ""
    error_class_source: str = "unavailable"
    egress_outcome: str = ""


class FlowIndex:
    def __init__(self, mappings: list[FlowMapping]):
        self.mappings = mappings
        self._by_pre_key: dict[str, list[FlowMapping]] = {}
        for mapping in mappings:
            if mapping.pre_flow.complete and mapping.pre_flow.key:
                self._by_pre_key.setdefault(mapping.pre_flow.key, []).append(mapping)

    @classmethod
    def from_log(
        cls,
        path: str,
        max_event_seq: int | None = None,
        include_event_seqs: set[int] | None = None,
    ) -> "FlowIndex":
        mappings: list[FlowMapping] = []
        for conn in parse_tracing_log(
            path, max_event_seq, include_event_seqs
        ).values():
            mapping = _tcp_mapping(conn)
            if mapping:
                mappings.append(mapping)
        for conn in parse_udp_tracing_log(
            path, max_event_seq, include_event_seqs
        ).values():
            mapping = _udp_mapping(conn)
            if mapping:
                mappings.append(mapping)
        return cls(mappings)

    def lookup_key(self, key: str) -> list[FlowMapping]:
        """Return every matching session; duplicate/reused tuples remain explicit."""
        return list(self._by_pre_key.get(key, ()))

    def lookup(
        self, network: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
    ) -> list[FlowMapping]:
        return self.lookup_key(flow_key(network, src_ip, src_port, dst_ip, dst_port))


def flow_key(network: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    network = network.lower()
    if network.startswith("tcp"):
        network = "tcp"
    elif network.startswith("udp"):
        network = "udp"
    else:
        raise ValueError(f"unsupported network: {network}")
    src = _endpoint(src_ip, src_port)
    dst = _endpoint(dst_ip, dst_port)
    return f"{network}|{src}|{dst}"


def _endpoint(ip: str, port: int) -> str:
    address = ipaddress.ip_address(ip)
    address = getattr(address, "ipv4_mapped", None) or address
    if not 1 <= int(port) <= 65535 or address.is_unspecified:
        raise ValueError("flow endpoints require non-unspecified IPs and ports 1..65535")
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def _tcp_mapping(conn: MihomoConnection) -> FlowMapping | None:
    pre = conn.connect.pre_flow if conn.connect else None
    if not pre:
        return None
    dial = conn.proxy_dial
    close = conn.close
    return FlowMapping(
        connection_id=conn.conn_id,
        outer_conn_id=dial.outer_conn_id if dial else "",
        pre_flow=pre,
        post_flow=dial.post_flow if dial else None,
        status=close.status if close and close.status else ("mapped" if dial and dial.post_flow else "pending"),
        error=close.error if close else "",
        stage=close.stage if close else "",
        error_class=close.error_class if close else "",
        error_class_source=close.error_class_source if close else "unavailable",
        egress_outcome=dial.egress_outcome if dial else "",
    )


def _udp_mapping(conn: UdpConnection) -> FlowMapping | None:
    pre = conn.connect.pre_flow if conn.connect else None
    if not pre:
        return None
    dial = conn.proxy_dial
    close = conn.close
    return FlowMapping(
        connection_id=conn.conn_key,
        outer_conn_id=dial.outer_conn_id if dial else "",
        pre_flow=pre,
        post_flow=dial.post_flow if dial else None,
        status=close.status if close and close.status else ("mapped" if dial and dial.post_flow else "pending"),
        error=close.error if close else "",
        stage=close.stage if close else "",
        error_class=close.error_class if close else "",
        error_class_source=close.error_class_source if close else "unavailable",
        egress_outcome=dial.egress_outcome if dial else "",
    )

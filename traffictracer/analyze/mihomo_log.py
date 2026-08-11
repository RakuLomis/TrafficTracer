"""Mihomo tracing JSONL parser with normalized TCP/UDP flow indexes."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re

from ..models import FlowTuple

_ADDR_ANNOTATION_RE = re.compile(r"\([^)]*\)$")


def _clean_addr(raw: str) -> str:
    return _ADDR_ANNOTATION_RE.sub("", raw or "")


def parse_flow_tuple(raw: object) -> FlowTuple | None:
    if not isinstance(raw, dict):
        return None
    return FlowTuple(
        network=str(raw.get("network", "")).lower(),
        src_ip=str(raw.get("src_ip", "")),
        src_port=int(raw.get("src_port", 0) or 0),
        dst_ip=str(raw.get("dst_ip", "")),
        dst_port=int(raw.get("dst_port", 0) or 0),
        dst_host=str(raw.get("dst_host", "")),
        key=str(raw.get("key", "")),
        complete=bool(raw.get("complete", False)),
        source=str(raw.get("source", "")),
        scope=str(raw.get("scope", "")),
        shared=bool(raw.get("shared", False)),
    )


@dataclass(frozen=True)
class TcpConnect:
    ts: str
    conn_id: str
    src: str
    dst: str
    host: str
    pre_flow: FlowTuple | None = None
    event_seq: int = 0


@dataclass(frozen=True)
class TcpProxyDial:
    ts: str
    conn_id: str
    proxy: str
    proxy_type: str
    proxy_addr: str
    out_src: str
    out_dst: str = ""
    post_flow: FlowTuple | None = None
    outer_conn_id: str = ""
    event_seq: int = 0
    leaf_proxy: str = ""
    leaf_proxy_type: str = ""
    egress_outcome: str = ""


@dataclass(frozen=True)
class TcpClose:
    ts: str
    conn_id: str
    bytes_up: int
    bytes_down: int
    duration_ms: int
    status: str = ""
    stage: str = ""
    error: str = ""
    event_seq: int = 0


@dataclass(frozen=True)
class MihomoConnection:
    conn_id: str
    connect: TcpConnect | None
    proxy_dial: TcpProxyDial | None
    close: TcpClose | None


@dataclass(frozen=True)
class UdpConnect:
    ts: str
    conn_key: str
    src: str
    dst: str
    host: str
    process: str = ""
    process_path: str = ""
    in_name: str = ""
    pre_flow: FlowTuple | None = None
    event_seq: int = 0


@dataclass(frozen=True)
class UdpProxyDial:
    ts: str
    conn_key: str
    proxy: str
    proxy_type: str
    proxy_addr: str
    out_src: str
    out_dst: str = ""
    post_flow: FlowTuple | None = None
    outer_conn_id: str = ""
    event_seq: int = 0
    leaf_proxy: str = ""
    leaf_proxy_type: str = ""
    egress_outcome: str = ""


@dataclass(frozen=True)
class UdpClose:
    ts: str
    conn_key: str
    bytes_up: int
    bytes_down: int
    duration_ms: int
    status: str = ""
    stage: str = ""
    error: str = ""
    event_seq: int = 0


@dataclass(frozen=True)
class UdpConnection:
    conn_key: str
    connect: UdpConnect | None
    proxy_dial: UdpProxyDial | None
    close: UdpClose | None


def _events(path: str):
    with open(path, "r", encoding="utf-8") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(event, dict):
                yield event


def parse_tracing_log(path: str) -> dict[str, MihomoConnection]:
    connections: dict[str, dict] = {}
    for event in _events(path):
        etype = event.get("type", "")
        conn_id = event.get("conn_id", "")
        if not conn_id or not etype.startswith("tcp_"):
            continue
        conn = connections.setdefault(conn_id, {"connect": None, "proxy_dial": None, "close": None})
        common = {"ts": event.get("ts", ""), "conn_id": conn_id}
        if etype == "tcp_connect":
            conn["connect"] = TcpConnect(
                **common, src=_clean_addr(event.get("src", "")),
                dst=_clean_addr(event.get("dst", "")), host=event.get("host", ""),
                pre_flow=parse_flow_tuple(event.get("pre_flow")),
                event_seq=int(event.get("event_seq", 0) or 0),
            )
        elif etype == "tcp_proxy_dial":
            conn["proxy_dial"] = TcpProxyDial(
                **common, proxy=event.get("proxy", ""), proxy_type=event.get("proxy_type", ""),
                proxy_addr=_clean_addr(event.get("proxy_addr", "")),
                out_src=_clean_addr(event.get("out_src", "")),
                out_dst=_clean_addr(event.get("out_dst", "")),
                post_flow=parse_flow_tuple(event.get("post_flow")),
                outer_conn_id=event.get("outer_conn_id", ""),
                event_seq=int(event.get("event_seq", 0) or 0),
                leaf_proxy=event.get("leaf_proxy", ""),
                leaf_proxy_type=event.get("leaf_proxy_type", ""),
                egress_outcome=event.get("egress_outcome", ""),
            )
        elif etype == "tcp_close":
            conn["close"] = TcpClose(
                **common, bytes_up=int(event.get("bytes_up", 0) or 0),
                bytes_down=int(event.get("bytes_down", 0) or 0),
                duration_ms=int(event.get("duration_ms", 0) or 0),
                status=event.get("status", ""), stage=event.get("stage", ""),
                error=event.get("error", ""), event_seq=int(event.get("event_seq", 0) or 0),
            )
    return {cid: MihomoConnection(cid, row["connect"], row["proxy_dial"], row["close"])
            for cid, row in connections.items()}


def parse_udp_tracing_log(path: str) -> dict[str, UdpConnection]:
    connections: dict[str, dict] = {}
    for event in _events(path):
        etype = event.get("type", "")
        conn_key = event.get("conn_key", "")
        if not conn_key or not etype.startswith("udp_"):
            continue
        conn = connections.setdefault(conn_key, {"connect": None, "proxy_dial": None, "close": None})
        common = {"ts": event.get("ts", ""), "conn_key": conn_key}
        if etype == "udp_connect":
            conn["connect"] = UdpConnect(
                **common, src=_clean_addr(event.get("src", "")), dst=_clean_addr(event.get("dst", "")),
                host=event.get("host", ""), process=event.get("process", ""),
                process_path=event.get("process_path", ""), in_name=event.get("in_name", ""),
                pre_flow=parse_flow_tuple(event.get("pre_flow")),
                event_seq=int(event.get("event_seq", 0) or 0),
            )
        elif etype == "udp_proxy_dial":
            conn["proxy_dial"] = UdpProxyDial(
                **common, proxy=event.get("proxy", ""), proxy_type=event.get("proxy_type", ""),
                proxy_addr=_clean_addr(event.get("proxy_addr", "")), out_src=_clean_addr(event.get("out_src", "")),
                out_dst=_clean_addr(event.get("out_dst", "")), post_flow=parse_flow_tuple(event.get("post_flow")),
                outer_conn_id=event.get("outer_conn_id", ""), event_seq=int(event.get("event_seq", 0) or 0),
                leaf_proxy=event.get("leaf_proxy", ""),
                leaf_proxy_type=event.get("leaf_proxy_type", ""),
                egress_outcome=event.get("egress_outcome", ""),
            )
        elif etype == "udp_close":
            conn["close"] = UdpClose(
                **common, bytes_up=int(event.get("bytes_up", 0) or 0), bytes_down=int(event.get("bytes_down", 0) or 0),
                duration_ms=int(event.get("duration_ms", 0) or 0), status=event.get("status", ""),
                stage=event.get("stage", ""), error=event.get("error", ""),
                event_seq=int(event.get("event_seq", 0) or 0),
            )
    return {key: UdpConnection(key, row["connect"], row["proxy_dial"], row["close"])
            for key, row in connections.items()}


def parse_udp_connections(path: str) -> dict[str, tuple[UdpConnect, UdpClose | None]]:
    """Backward-compatible UDP connect/close view."""
    return {key: (conn.connect, conn.close) for key, conn in parse_udp_tracing_log(path).items()
            if conn.connect is not None}


def build_pre_flow_index(
    tcp: dict[str, MihomoConnection], udp: dict[str, UdpConnection] | None = None,
) -> dict[str, list[MihomoConnection | UdpConnection]]:
    """Index all complete logical flows; lists retain collisions explicitly."""
    index: dict[str, list[MihomoConnection | UdpConnection]] = {}
    for conn in [*tcp.values(), *((udp or {}).values())]:
        flow = conn.connect.pre_flow if conn.connect else None
        if flow and flow.complete and flow.key:
            index.setdefault(flow.key, []).append(conn)
    return index

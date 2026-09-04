"""Mihomo tracing JSONL parser with normalized TCP/UDP flow indexes."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import json
import re
from pathlib import Path

from ..models import CarrierBinding, FlowTuple
from .outcomes import terminal_error_class

_ADDR_ANNOTATION_RE = re.compile(r"\([^)]*\)$")
CAUSAL_TAIL_MAX_DELAY_MS = 2000.0
_PROXY_GROUP_TYPES = frozenset({"selector", "urltest", "fallback", "loadbalance", "relay"})
_NON_PROXY_TYPES = frozenset({"direct", "reject", "rejectdrop", "dns", "pass", "compatible"})


def _normalize_proxy_type(value: object) -> str:
    return str(value or "").lower().replace("-", "").replace("_", "")


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


def parse_flow_tuples(raw: object) -> tuple[FlowTuple, ...]:
    if not isinstance(raw, list):
        return ()
    return tuple(
        flow
        for item in raw
        if (flow := parse_flow_tuple(item)) is not None
    )


@dataclass(frozen=True)
class TcpConnect:
    ts: str
    conn_id: str
    src: str
    dst: str
    host: str
    in_name: str = ""
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
    carrier_id: str = ""
    carrier_relation: str = ""
    carrier_generation: int = 0
    carrier_protocol: str = ""
    carrier_paths: tuple[FlowTuple, ...] = ()
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
    error_class: str = ""
    error_class_source: str = "unavailable"
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
    carrier_id: str = ""
    carrier_relation: str = ""
    carrier_generation: int = 0
    carrier_protocol: str = ""
    carrier_paths: tuple[FlowTuple, ...] = ()
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
    error_class: str = ""
    error_class_source: str = "unavailable"
    event_seq: int = 0


@dataclass(frozen=True)
class UdpConnection:
    conn_key: str
    connect: UdpConnect | None
    proxy_dial: UdpProxyDial | None
    close: UdpClose | None


@dataclass(frozen=True)
class CarrierLifecycleRecord:
    event_type: str
    ts: str
    event_seq: int
    network: str
    carrier_id: str
    logical_conn_id: str
    conn_id: str
    conn_key: str
    relation: str
    generation: int
    protocol: str
    post_flow: FlowTuple | None
    physical_paths: tuple[FlowTuple, ...]


def trace_snapshot_info(path: str) -> dict:
    """Return the persisted deterministic cutoff and observed late-event count."""
    trace_path = Path(path)
    if trace_path.parent.name == "raw":
        context_path = trace_path.parent / "capture-context.json"
    else:
        name = trace_path.name.replace("mihomo_trace_", "capture_context_", 1)
        context_path = trace_path.with_name(Path(name).with_suffix(".json").name)
    boundary = None
    try:
        context = json.loads(context_path.read_text(encoding="utf-8"))
        candidate = context.get("trace_boundary") if isinstance(context, dict) else None
        if (
            isinstance(candidate, dict)
            and isinstance(candidate.get("event_seq"), int)
            and candidate["event_seq"] > 0
        ):
            boundary = candidate
    except (OSError, json.JSONDecodeError, TypeError):
        pass

    cutoff = boundary["event_seq"] if boundary else None
    late_events = 0
    max_event_seq = 0
    late_event_types: Counter[str] = Counter()
    max_late_delay_ms = 0.0
    causal_tail_event_seqs: list[int] = []
    causal_tail_types: Counter[str] = Counter()
    started_tcp: set[str] = set()
    started_udp: set[str] = set()
    barrier_time = _parse_timestamp(boundary.get("ts", "")) if boundary else None
    boundary_session = str(boundary.get("session_id", "")) if boundary else ""
    barrier_verified = boundary is None
    if trace_path.is_file():
        with trace_path.open("r", encoding="utf-8") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                    seq = int(event.get("event_seq", 0) or 0)
                except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
                    continue
                max_event_seq = max(max_event_seq, seq)
                event_session = str(event.get("session_id", ""))
                same_session = not boundary_session or event_session == boundary_session
                event_type = str(event.get("type", "unknown"))
                if cutoff is not None and seq <= cutoff and same_session:
                    if event_type == "tcp_connect" and event.get("conn_id"):
                        started_tcp.add(str(event["conn_id"]))
                    elif event_type == "udp_connect" and event.get("conn_key"):
                        started_udp.add(str(event["conn_key"]))
                if (
                    boundary is not None
                    and seq == cutoff
                    and event.get("type") == "trace_barrier"
                    and event.get("session_id", "") == boundary.get("session_id", "")
                ):
                    barrier_verified = True
                if cutoff is not None and seq > cutoff:
                    late_events += 1
                    late_event_types[event_type] += 1
                    event_time = _parse_timestamp(str(event.get("ts", "")))
                    late_delay_ms = (
                        (event_time - barrier_time).total_seconds() * 1000
                        if barrier_time is not None and event_time is not None
                        else None
                    )
                    causal = same_session and (
                        (event_type in {"tcp_proxy_dial", "tcp_close"}
                         and str(event.get("conn_id", "")) in started_tcp)
                        or
                        (event_type in {"udp_proxy_dial", "udp_close"}
                         and str(event.get("conn_key", "")) in started_udp)
                    )
                    if (
                        causal
                        and late_delay_ms is not None
                        and 0 <= late_delay_ms <= CAUSAL_TAIL_MAX_DELAY_MS
                    ):
                        causal_tail_event_seqs.append(seq)
                        causal_tail_types[event_type] += 1
                    if late_delay_ms is not None:
                        max_late_delay_ms = max(
                            max_late_delay_ms, late_delay_ms,
                        )
    if not barrier_verified:
        raise ValueError(
            f"trace barrier marker is missing or does not match capture context: {path}"
        )
    return {
        "source": "mihomo_barrier" if boundary else "legacy_unbounded",
        "cutoff_event_seq": cutoff,
        "barrier_ts": boundary.get("ts", "") if boundary else "",
        "barrier_session_id": boundary.get("session_id", "") if boundary else "",
        "late_event_count": late_events,
        "late_event_types": dict(sorted(late_event_types.items())),
        "causal_tail_event_count": len(causal_tail_event_seqs),
        "causal_tail_event_types": dict(sorted(causal_tail_types.items())),
        "causal_tail_event_seqs": causal_tail_event_seqs,
        "max_late_delay_ms": round(max_late_delay_ms, 3),
        "max_observed_event_seq": max_event_seq,
        "barrier_verified": barrier_verified,
    }


def _parse_timestamp(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _events(
    path: str,
    max_event_seq: int | None = None,
    include_event_seqs: set[int] | None = None,
):
    included = include_event_seqs or set()
    with open(path, "r", encoding="utf-8") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(event, dict):
                try:
                    event_seq = int(event.get("event_seq", 0) or 0)
                except (TypeError, ValueError):
                    event_seq = 0
                if (
                    max_event_seq is not None
                    and event_seq > max_event_seq
                    and event_seq not in included
                ):
                    continue
                yield event


def _event_carrier_protocol(event: dict) -> str:
    raw = event.get("carrier_protocol", "")
    if not raw and (event.get("carrier_id") or event.get("outer_conn_id")):
        raw = event.get("leaf_proxy_type", "")
    return _normalize_proxy_type(raw)


def _event_carrier_paths(event: dict) -> tuple[FlowTuple, ...]:
    paths = parse_flow_tuples(event.get("carrier_paths"))
    if paths:
        return paths
    post_flow = parse_flow_tuple(event.get("post_flow"))
    if (
        post_flow is not None
        and post_flow.complete
        and post_flow.shared
        and post_flow.scope == "physical"
    ):
        return (post_flow,)
    return ()


def observed_proxy_protocols(
    path: str, max_event_seq: int | None = None,
) -> dict[str, object]:
    """Summarize actual proxy leaf protocols within a durable trace cutoff."""
    trace_path = Path(path)
    if not trace_path.is_file():
        return {
            "protocols": [],
            "proxy_dial_events": 0,
            "unknown_protocol_events": 0,
        }
    protocols: set[str] = set()
    total = 0
    unknown = 0
    for event in _events(str(trace_path), max_event_seq):
        if event.get("type") not in {"tcp_proxy_dial", "udp_proxy_dial"}:
            continue
        if event.get("egress_outcome") not in {"", "proxy"}:
            continue
        total += 1
        raw_type = event.get("carrier_protocol") or event.get(
            "leaf_proxy_type", ""
        )
        normalized = _normalize_proxy_type(raw_type)
        if normalized and normalized not in _PROXY_GROUP_TYPES | _NON_PROXY_TYPES:
            protocols.add(normalized)
        else:
            unknown += 1
    return {
        "protocols": sorted(protocols),
        "proxy_dial_events": total,

        "unknown_protocol_events": unknown,
    }


def parse_carrier_events(
    path: str,
    max_event_seq: int | None = None,
    include_event_seqs: set[int] | None = None,
) -> list[CarrierLifecycleRecord]:
    event_types = {
        "carrier_open", "carrier_path_update",
        "logical_carrier_bind", "carrier_close",
    }
    records = []
    for event in _events(path, max_event_seq, include_event_seqs):
        event_type = str(event.get("type", ""))
        if event_type not in event_types:
            continue
        records.append(CarrierLifecycleRecord(
            event_type=event_type,
            ts=str(event.get("ts", "")),
            event_seq=int(event.get("event_seq", 0) or 0),
            network=str(event.get("network", "")),
            carrier_id=str(
                event.get("carrier_id", "") or event.get("outer_conn_id", "")
            ),
            logical_conn_id=str(event.get("logical_conn_id", "")),
            conn_id=str(event.get("conn_id", "")),
            conn_key=str(event.get("conn_key", "")),
            relation=str(event.get("carrier_relation", "")),
            generation=int(event.get("carrier_generation", 0) or 0),
            protocol=_event_carrier_protocol(event),
            post_flow=parse_flow_tuple(event.get("post_flow")),
            physical_paths=_event_carrier_paths(event),
        ))
    return records


def build_carrier_path_registry(
    records: list[CarrierLifecycleRecord],
) -> dict[tuple[str, int], tuple[FlowTuple, ...]]:
    """Fold lifecycle snapshots into complete paths per carrier generation."""
    accumulated: dict[tuple[str, int], list[FlowTuple]] = {}
    seen: dict[tuple[str, int], set[tuple]] = {}
    for record in sorted(records, key=lambda item: item.event_seq):
        if not record.carrier_id:
            continue
        identity = (record.carrier_id, record.generation)
        paths = accumulated.setdefault(identity, [])
        path_keys = seen.setdefault(identity, set())
        candidates = list(record.physical_paths)
        if (
            record.post_flow is not None
            and record.post_flow.complete
            and record.post_flow.scope == "physical"
            and record.post_flow.shared
        ):
            candidates.append(record.post_flow)
        for path in candidates:
            key = (
                path.network.lower(), path.src_ip, path.src_port,
                path.dst_ip, path.dst_port,
            )
            if not path.complete or key in path_keys:
                continue
            path_keys.add(key)
            paths.append(path)
    return {identity: tuple(paths) for identity, paths in accumulated.items()}


def enrich_carrier_bindings(
    flows: list[object],
    registry: dict[tuple[str, int], tuple[FlowTuple, ...]],
) -> int:
    """Apply final lifecycle paths to logical bindings of the same generation."""
    enriched = 0
    for flow in flows:
        binding = getattr(flow, "carrier_binding", None)
        if binding is None or not binding.carrier_id:
            continue
        paths = registry.get((binding.carrier_id, binding.generation))
        if paths is None and binding.generation == 0:
            candidates = [
                value for (carrier_id, _generation), value in registry.items()
                if carrier_id == binding.carrier_id
            ]
            if len(candidates) == 1:
                paths = candidates[0]
        if not paths:
            continue
        merged = list(binding.paths)
        known = {
            (item.network.lower(), item.src_ip, item.src_port, item.dst_ip, item.dst_port)
            for item in merged
        }
        for path in paths:
            key = (
                path.network.lower(), path.src_ip, path.src_port,
                path.dst_ip, path.dst_port,
            )
            if key not in known:
                known.add(key)
                merged.append(path)
        if tuple(merged) == binding.paths:
            continue
        flow.carrier_binding = CarrierBinding(
            carrier_id=binding.carrier_id, relation=binding.relation,
            generation=binding.generation, protocol=binding.protocol,
            paths=tuple(merged),
        )
        evidence = getattr(flow, "match_evidence", None)
        if (
            isinstance(evidence, list)
            and "carrier_paths_enriched_from_lifecycle" not in evidence
        ):
            evidence.append("carrier_paths_enriched_from_lifecycle")
        enriched += 1
    return enriched


def parse_tracing_log(
    path: str, max_event_seq: int | None = None,
    include_event_seqs: set[int] | None = None,
) -> dict[str, MihomoConnection]:
    connections: dict[str, dict] = {}
    for event in _events(path, max_event_seq, include_event_seqs):
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
                in_name=event.get("in_name", ""),
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
                carrier_id=event.get("carrier_id", "") or event.get("outer_conn_id", ""),
                carrier_relation=event.get("carrier_relation", ""),
                carrier_generation=int(event.get("carrier_generation", 0) or 0),
                carrier_protocol=_event_carrier_protocol(event),
                carrier_paths=_event_carrier_paths(event),
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
                error=event.get("error", ""),
                error_class=terminal_error_class(
                    status=event.get("status", ""), stage=event.get("stage", ""),
                    error=event.get("error", ""), explicit=event.get("error_class", ""),
                )[0],
                error_class_source=terminal_error_class(
                    status=event.get("status", ""), stage=event.get("stage", ""),
                    error=event.get("error", ""), explicit=event.get("error_class", ""),
                )[1], event_seq=int(event.get("event_seq", 0) or 0),
            )
    return {cid: MihomoConnection(cid, row["connect"], row["proxy_dial"], row["close"])
            for cid, row in connections.items()}


def parse_udp_tracing_log(
    path: str, max_event_seq: int | None = None,
    include_event_seqs: set[int] | None = None,
) -> dict[str, UdpConnection]:
    connections: dict[str, dict] = {}
    for event in _events(path, max_event_seq, include_event_seqs):
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
                carrier_id=event.get("carrier_id", "") or event.get("outer_conn_id", ""),
                carrier_relation=event.get("carrier_relation", ""),
                carrier_generation=int(event.get("carrier_generation", 0) or 0),
                carrier_protocol=_event_carrier_protocol(event),
                carrier_paths=_event_carrier_paths(event),
                leaf_proxy=event.get("leaf_proxy", ""),
                leaf_proxy_type=event.get("leaf_proxy_type", ""),
                egress_outcome=event.get("egress_outcome", ""),
            )
        elif etype == "udp_close":
            conn["close"] = UdpClose(
                **common, bytes_up=int(event.get("bytes_up", 0) or 0), bytes_down=int(event.get("bytes_down", 0) or 0),
                duration_ms=int(event.get("duration_ms", 0) or 0), status=event.get("status", ""),
                stage=event.get("stage", ""), error=event.get("error", ""),
                error_class=terminal_error_class(
                    status=event.get("status", ""), stage=event.get("stage", ""),
                    error=event.get("error", ""), explicit=event.get("error_class", ""),
                )[0],
                error_class_source=terminal_error_class(
                    status=event.get("status", ""), stage=event.get("stage", ""),
                    error=event.get("error", ""), explicit=event.get("error_class", ""),
                )[1], event_seq=int(event.get("event_seq", 0) or 0),
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

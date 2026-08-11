"""Stable connection identity and ambiguity-preserving candidate ranking."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from urllib.parse import urlparse

from traffictracer.models import FlowTuple, TransportConnection

from .flow_index import flow_key
from .mihomo_log import MihomoConnection


@dataclass(frozen=True)
class ConnectionCandidate:
    native_id: str
    method: str
    score: float
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class ConnectionDecision:
    status: str
    method: str
    confidence: float
    candidates: tuple[ConnectionCandidate, ...]
    selected_native_id: str | None = None
    reason: str = ""


def stable_connection_id(
    connection: TransportConnection,
    candidate_native_id: str = "",
    collision_registry: dict[str, str] | None = None,
) -> str:
    """Return a deterministic ID for one observed transport connection."""
    canonical = json.dumps(
        [
            _connection_network(connection),
            connection.src_ip,
            int(connection.src_port),
            connection.dst_ip,
            int(connection.dst_port),
            int(connection.netlog_source_id),
            connection.first_observed,
            candidate_native_id,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    digest = _stable_digest(canonical)
    base_id = "conn-" + digest[:32]
    if collision_registry is None:
        return base_id
    prior = collision_registry.get(base_id)
    if prior is None or prior == digest:
        collision_registry[base_id] = digest
        return base_id
    extended_id = f"{base_id}-{digest[32:40]}"
    extended_prior = collision_registry.get(extended_id)
    if extended_prior is not None and extended_prior != digest:
        raise RuntimeError("stable connection ID collision exceeds 40 bits")
    collision_registry[extended_id] = digest
    return extended_id


def _stable_digest(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def rank_connection_candidates(
    connection: TransportConnection,
    candidates: dict[str, MihomoConnection],
) -> ConnectionDecision:
    """Rank all candidates; equal best candidates remain explicitly ambiguous."""
    scored: list[ConnectionCandidate] = []
    key = _transport_key(connection)
    endpoint_src = _endpoint(connection.src_ip, connection.src_port)
    endpoint_dst = _endpoint(connection.dst_ip, connection.dst_port)
    host = (urlparse(connection.url).hostname or "").lower()

    for native_id, candidate in candidates.items():
        connect = candidate.connect
        if connect is None:
            continue
        evidence: list[str] = []
        time_delta = _time_delta(connection.first_observed, connect.ts)
        method = "none"
        score = 0.0
        pre = connect.pre_flow
        if key and pre and pre.complete and pre.key == key:
            method = "exact_pre_flow"
            if time_delta is not None and time_delta <= 2.0:
                score = 1.0
                evidence.extend(("normalized_pre_flow", f"time_delta_ms:{round(time_delta * 1000)}"))
            elif time_delta is None:
                score = 0.95
                evidence.extend(("normalized_pre_flow", "time_unavailable"))
            else:
                score = 0.9
                evidence.extend((
                    "normalized_pre_flow",
                    f"time_outside_window_ms:{round(time_delta * 1000)}",
                ))
        elif pre and pre.complete and _same_endpoints(connection, pre):
            method = "transport_network_reconciled"
            score = 0.0
            evidence.extend((
                "normalized_transport_endpoints",
                f"network_reconciled:{_connection_network(connection)}->{pre.network}",
            ))
            if time_delta is not None and time_delta <= 2.0:
                score = 0.98
                evidence.append(f"time_delta_ms:{round(time_delta * 1000)}")
            elif time_delta is None:
                score = 0.93
                evidence.append("time_unavailable")
        elif endpoint_src and endpoint_dst and connect.src == endpoint_src and connect.dst == endpoint_dst:
            method = "netlog_socket"
            if time_delta is not None and time_delta <= 2.0:
                score = 0.9
                evidence.extend(("source_and_destination", f"time_delta_ms:{round(time_delta * 1000)}"))
            elif time_delta is None:
                score = 0.85
                evidence.extend(("source_and_destination", "time_unavailable"))
        elif endpoint_dst and connect.dst == endpoint_dst:
            method = "endpoint_time"
            if time_delta is not None and time_delta <= 2.0:
                score = 0.78
                evidence.extend(("destination_endpoint", f"time_delta_ms:{round(time_delta * 1000)}"))
            elif time_delta is None:
                score = 0.65
                evidence.extend(("destination_endpoint", "time_unavailable"))
        elif host and connect.host.lower() == host:
            method = "host_time"
            if time_delta is not None and time_delta <= 5.0:
                score = 0.55
                evidence.extend(("destination_host", f"time_delta_ms:{round(time_delta * 1000)}"))
            elif time_delta is None:
                score = 0.4
                evidence.extend(("destination_host", "time_unavailable"))
        if score:
            scored.append(ConnectionCandidate(native_id, method, score, tuple(evidence)))

    ranked = tuple(sorted(scored, key=lambda item: (-item.score, item.native_id)))
    if not ranked:
        return ConnectionDecision("unmatched", "none", 0.0, (), reason="no_candidate")
    best_score = ranked[0].score
    best = tuple(item for item in ranked if item.score == best_score)
    if len(best) > 1:
        return ConnectionDecision(
            "ambiguous", best[0].method, best_score, ranked,
            reason="multiple_candidates",
        )
    winner = best[0]
    if winner.method in {"endpoint_time", "host_time"} and "time_unavailable" in winner.evidence:
        return ConnectionDecision(
            "unmatched", winner.method, winner.score, ranked,
            reason="insufficient_time",
        )
    return ConnectionDecision(
        "matched", winner.method, winner.score, ranked,
        selected_native_id=winner.native_id,
    )


def _time_delta(observed: float | None, raw: str | None) -> float | None:
    if observed is None or not raw:
        return None
    try:
        candidate = float(raw)
    except ValueError:
        try:
            candidate = datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    observed_value = float(observed)
    epoch_threshold = 1_000_000_000
    if (observed_value >= epoch_threshold) != (candidate >= epoch_threshold):
        # CDP timestamps are monotonic; Mihomo timestamps are UTC wall time.
        return None
    return abs(observed_value - candidate)


def _transport_key(connection: TransportConnection) -> str:
    try:
        return flow_key(
            _connection_network(connection), connection.src_ip, connection.src_port,
            connection.dst_ip, connection.dst_port,
        )
    except ValueError:
        return ""


def _connection_network(connection: TransportConnection) -> str:
    network = connection.network.lower()
    if network in {"tcp", "udp"}:
        return network
    return _network(connection.protocol)


def _network(value: str) -> str:
    return "udp" if value.lower().startswith(("udp", "quic")) else "tcp"


def _same_endpoints(connection: TransportConnection, flow: FlowTuple) -> bool:
    return (
        connection.src_ip == flow.src_ip
        and int(connection.src_port) == int(flow.src_port)
        and connection.dst_ip == flow.dst_ip
        and int(connection.dst_port) == int(flow.dst_port)
    )


def _endpoint(ip: str, port: int) -> str:
    if not ip or not port:
        return ""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

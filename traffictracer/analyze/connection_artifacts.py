"""Persist connection-centric v2 request and transport records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from traffictracer.contracts import validate_flow_v2
from traffictracer.models import CorrelatedFlowV2, FlowTuple, VisitCorrelation
from traffictracer.session.atomic import write_json_atomic
from traffictracer.version import FLOW_SCHEMA_V2_VERSION


CONNECTION_INDEX_V2_NAME = "connection-index-v2.json"
REQUEST_INDEX_V2_NAME = "request-index-v2.json"


@dataclass(frozen=True)
class ConnectionArtifacts:
    connection_index: Path
    request_index: Path
    generation_id: str


def persist_connection_artifacts(
    session_dir: str | Path,
    session_id: str,
    results: list[VisitCorrelation],
) -> ConnectionArtifacts:
    generation_id = str(uuid5(NAMESPACE_URL, f"{Path(session_dir).resolve().as_uri()}#analysis-v2"))
    connections = _merge_connection_records([
        _connection_record(flow, session_id, generation_id)
        for result in results
        for flow in result.flows
        if flow.stable_connection_id
    ])
    requests = _request_records(results, session_id, generation_id)
    for record in [*connections, *requests]:
        validate_flow_v2(record)
    connections.sort(key=lambda item: item["connection_id"])
    requests.sort(key=lambda item: item["request_id"])

    output = Path(session_dir) / "results"
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection_path = output / CONNECTION_INDEX_V2_NAME
    request_path = output / REQUEST_INDEX_V2_NAME
    write_json_atomic(connection_path, {
        "schema_version": FLOW_SCHEMA_V2_VERSION,
        "record_type": "connection_index",
        "analysis_generation_id": generation_id,
        "items": connections,
    })
    write_json_atomic(request_path, {
        "schema_version": FLOW_SCHEMA_V2_VERSION,
        "record_type": "request_index",
        "analysis_generation_id": generation_id,
        "items": requests,
    })
    return ConnectionArtifacts(connection_path, request_path, generation_id)


def _merge_connection_records(records: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for record in records:
        existing = merged.get(record["connection_id"])
        if existing is None:
            merged[record["connection_id"]] = record
            continue
        existing["request_ids"] = sorted(set(existing["request_ids"]) | set(record["request_ids"]))
        existing["shared"] = bool(existing["shared"] or record["shared"] or len(existing["request_ids"]) > 1)
    return list(merged.values())


def _connection_record(flow: CorrelatedFlowV2, session_id: str, generation_id: str) -> dict:
    candidates = [
        {
            "connection_id": item["connection_id"],
            "score": item["score"],
            "evidence": item["evidence"],
        }
        for item in flow.match_candidates
    ]
    match = {
        "status": flow.match_status,
        "method": flow.match_method,
        "confidence": flow.match_confidence,
        "candidates": candidates,
        "evidence": (
            flow.match_evidence
            or [flow.match_reason or "no_ranked_candidate"]
        ),
    }
    if flow.match_status in {"ambiguous", "unmatched"}:
        match["unmatched_reason"] = flow.match_reason or (
            "multiple_candidates" if flow.match_status == "ambiguous" else "no_candidate"
        )
    record = {
        "schema_version": FLOW_SCHEMA_V2_VERSION,
        "record_type": "connection",
        "session_id": session_id,
        "analysis_generation_id": generation_id,
        "connection_id": flow.stable_connection_id,
        "protocol": _network(flow.protocol),
        "pre_flow": _flow_payload(flow.pre_flow, "pre_proxy"),
        "post_flow": _flow_payload(flow.post_flow, "post_proxy") if flow.post_flow else None,
        "shared": bool(flow.connection_reused or (flow.post_flow and flow.post_flow.shared)),
        "match": match,
        "request_ids": sorted(set(flow.request_ids)),
    }
    if flow.outer_conn_id:
        record["outer_connection_id"] = flow.outer_conn_id
    return record


def _request_records(results: list[VisitCorrelation], session_id: str, generation_id: str) -> list[dict]:
    output: list[dict] = []
    for result in results:
        by_request = {
            request_id: flow
            for flow in result.flows
            for request_id in flow.request_ids
            if flow.stable_connection_id
        }
        for request in result.requests:
            flow = by_request.get(request.request_id)
            connection_id = flow.stable_connection_id if flow else None
            output.append({
                "schema_version": FLOW_SCHEMA_V2_VERSION,
                "record_type": "request",
                "session_id": session_id,
                "analysis_generation_id": generation_id,
                "request_id": request.request_id,
                "url": request.url,
                "resource_type": request.resource_type,
                "relation": _relation(request.url, result.domain),
                "connection_id": connection_id,
                "candidate_connection_ids": [connection_id] if connection_id else [],
                "attribution": (
                    {"status": "matched", "method": "netlog_socket", "confidence": 1.0, "evidence": ["netlog_request_id", "transport_request_ids"]}
                    if connection_id
                    else {"status": "unmatched", "method": "none", "confidence": 0.0, "evidence": ["request_not_in_transport_index"], "unmatched_reason": "no_transport_connection"}
                ),
            })
    return output


def _flow_payload(flow: FlowTuple | None, scope: str) -> dict:
    if flow is None:
        raise ValueError("connection record requires a pre-proxy flow")
    payload = asdict(flow)
    payload.pop("key", None)
    payload["network"] = _network(flow.network)
    payload["scope"] = scope
    payload["source"] = flow.source or "netlog"
    payload["shared"] = bool(flow.shared)
    return payload


def _network(value: str) -> str:
    return "udp" if value.lower().startswith(("udp", "quic")) else "tcp"


def _relation(url: str, domain: str) -> str:
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    return "same_site" if domain.lower() in host else "cross_site"

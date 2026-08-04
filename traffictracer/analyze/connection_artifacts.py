"""Persist connection-centric v2 request and transport records."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from traffictracer.contracts import validate_flow_v2, validate_pcap_index
from traffictracer.models import CorrelatedFlowV2, FlowTuple, VisitCorrelation
from traffictracer.analyze.pcap_splitter import ConnectionPcapResult, PcapSideResult
from traffictracer.session.atomic import write_json_atomic
from traffictracer.version import FLOW_SCHEMA_V2_VERSION, PCAP_INDEX_SCHEMA_VERSION, SESSION_SCHEMA_V2_VERSION


CONNECTION_INDEX_V2_NAME = "connection-index-v2.json"
REQUEST_INDEX_V2_NAME = "request-index-v2.json"
PCAP_INDEX_V1_NAME = "pcap-index-v1.json"


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


def persist_pcap_index(
    session_dir: str | Path,
    session_id: str,
    generation_id: str,
    split_mode: str,
    pcap_results: list[ConnectionPcapResult],
    correlations: list[VisitCorrelation],
) -> Path:
    """Persist the authoritative connection-to-PCAP map and coverage counters."""
    session = Path(session_dir)
    merged = _merge_pcap_results(pcap_results)
    payload = {
        "schema_version": PCAP_INDEX_SCHEMA_VERSION,
        "session_schema_version": SESSION_SCHEMA_V2_VERSION,
        "session_id": session_id,
        "analysis_generation_id": generation_id,
        "split_mode": split_mode,
        "raw_capture": {
            "tun_artifact_id": "capture-tun-pcap",
            "physical_artifact_id": "capture-physical-pcap",
        },
        "connections": [_pcap_record(item, session) for item in merged],
        "coverage": _coverage(correlations),
    }
    validate_pcap_index(payload)
    output = session / "results" / PCAP_INDEX_V1_NAME
    write_json_atomic(output, payload)
    return output


def _merge_pcap_results(
    items: list[ConnectionPcapResult],
) -> list[ConnectionPcapResult]:
    merged: dict[str, ConnectionPcapResult] = {}
    for item in items:
        existing = merged.get(item.connection_id)
        if existing is None:
            merged[item.connection_id] = item
            continue
        merged[item.connection_id] = replace(
            existing,
            request_ids=tuple(
                sorted(set(existing.request_ids) | set(item.request_ids))
            ),
            pre_proxy=_prefer_pcap(existing.pre_proxy, item.pre_proxy),
            post_proxy=_prefer_pcap(existing.post_proxy, item.post_proxy),
        )
    return [merged[key] for key in sorted(merged)]


def _prefer_pcap(
    left: PcapSideResult,
    right: PcapSideResult,
) -> PcapSideResult:
    order = {"success": 3, "empty": 2, "failed": 1, "not_requested": 0}
    return right if order[right.status] > order[left.status] else left


def _pcap_record(item: ConnectionPcapResult, session: Path) -> dict:
    return {
        "connection_id": item.connection_id,
        "protocol": item.protocol,
        "request_ids": list(item.request_ids),
        "pre_proxy": _relative_side(item.pre_proxy, session),
        "post_proxy": _relative_side(item.post_proxy, session),
    }


def _relative_side(side: PcapSideResult, session: Path) -> dict:
    payload = side.to_dict()
    if side.path is not None:
        try:
            payload["path"] = str(
                Path(side.path).resolve().relative_to(session.resolve())
            )
        except ValueError as exc:
            raise ValueError(
                f"derived PCAP is outside session directory: {side.path}"
            ) from exc
    return payload


def _coverage(results: list[VisitCorrelation]) -> dict:
    browser = Counter({"matched": 0, "ambiguous": 0, "unmatched": 0})
    connections: dict[str, CorrelatedFlowV2] = {}
    reasons: Counter[str] = Counter()
    for result in results:
        request_flows = {
            request_id: flow
            for flow in result.flows
            for request_id in flow.request_ids
        }
        request_ids = [request.request_id for request in result.requests]
        if not request_ids and result.cdp_request_count:
            request_ids = [
                f"unindexed-{index}" for index in range(result.cdp_request_count)
            ]
        for request_id in request_ids:
            flow = request_flows.get(request_id)
            status = _partition_status(
                flow.match_status if flow else "unmatched"
            )
            browser[status] += 1
            if status != "matched":
                reasons[_reason(flow, "no_transport_connection")] += 1
        for flow in result.flows:
            if flow.stable_connection_id:
                connections.setdefault(flow.stable_connection_id, flow)

    transport = Counter({"matched": 0, "ambiguous": 0, "unmatched": 0})
    with_post = shared = 0
    for flow in connections.values():
        status = _partition_status(flow.match_status)
        transport[status] += 1
        if status != "matched":
            reasons[_reason(flow, "no_candidate")] += 1
        if flow.post_flow is not None:
            with_post += 1
        else:
            reasons["missing_post_flow"] += 1
        if flow.connection_reused or bool(flow.post_flow and flow.post_flow.shared):
            shared += 1
    total = len(connections)
    return {
        "browser_requests": {"total": sum(browser.values()), **dict(browser)},
        "transport_connections": {
            "total": sum(transport.values()),
            **dict(transport),
        },
        "core_logical_flows": {
            "total": total,
            "with_post_flow": with_post,
            "shared": shared,
            "missing_post_flow": total - with_post,
        },
        "unmatched_reasons": dict(sorted(reasons.items())),
    }


def _partition_status(status: str) -> str:
    return status if status in {"ambiguous", "unmatched"} else "matched"


def _reason(flow: CorrelatedFlowV2 | None, fallback: str) -> str:
    import re

    value = flow.match_reason if flow and flow.match_reason else fallback
    normalized = re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")
    return normalized or fallback

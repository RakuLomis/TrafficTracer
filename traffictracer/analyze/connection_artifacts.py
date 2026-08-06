"""Persist connection-centric v2 request and transport records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import ipaddress
import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from traffictracer.contracts import validate_flow_v2, validate_pcap_index
from traffictracer.models import CorrelatedFlowV2, FlowTuple, VisitCorrelation
from traffictracer.analyze.pcap_splitter import ConnectionPcapResult, PcapSideResult
from traffictracer.analyze.pcap_mapping import reconcile_pcap_attribution
from traffictracer.analyze.artifacts import core_flow_records, layered_coverage
from traffictracer.analyze.request_resolver import resolve_visit_requests
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
    *,
    output_dir: str | Path | None = None,
    generation_id: str | None = None,
    pcap_results: list[ConnectionPcapResult] | None = None,
) -> ConnectionArtifacts:
    generation_id = generation_id or str(
        uuid5(NAMESPACE_URL, f"{Path(session_dir).resolve().as_uri()}#analysis-v2")
    )
    proxy_selections = _load_proxy_selections(Path(session_dir))
    connections = _merge_connection_records([
        _connection_record(
            flow, session_id, generation_id, proxy_selections,
        )
        for result in results
        for flow in result.flows
        if flow.stable_connection_id
    ])
    _annotate_outer_connection_reuse(connections)
    requests = _request_records(
        results, session_id, generation_id, pcap_results or [],
    )
    urls_by_connection: dict[str, set[str]] = {}
    request_ids_by_connection: dict[str, set[str]] = {}
    for request in requests:
        connection_id = request.get("connection_id")
        if connection_id:
            urls_by_connection.setdefault(connection_id, set()).add(request["url"])
            request_ids_by_connection.setdefault(connection_id, set()).add(
                request["request_id"]
            )
    for connection in connections:
        connection["request_ids"] = sorted(
            set(connection["request_ids"])
            | request_ids_by_connection.get(connection["connection_id"], set())
        )
        if len(connection["request_ids"]) > 1:
            connection["sharing"]["request_multiplexed"] = True
            connection["shared"] = True
        urls = sorted(urls_by_connection.get(connection["connection_id"], set()))
        connection["urls"] = urls
        connection["primary_url"] = urls[0] if urls else None
    for record in [*connections, *requests]:
        validate_flow_v2(record)
    connections.sort(key=lambda item: item["connection_id"])
    requests.sort(key=lambda item: item["request_id"])

    output = Path(output_dir) if output_dir is not None else Path(session_dir) / "results"
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
    reconcile_pcap_attribution(output, requests, pcap_results or [])
    return ConnectionArtifacts(connection_path, request_path, generation_id)


def _merge_connection_records(records: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for record in records:
        existing = merged.get(record["connection_id"])
        if existing is None:
            merged[record["connection_id"]] = record
            continue
        existing["request_ids"] = sorted(set(existing["request_ids"]) | set(record["request_ids"]))
        existing["sharing"]["request_multiplexed"] = bool(
            len(existing["request_ids"]) > 1
        )
        existing["sharing"]["post_flow_shared"] = bool(
            existing["sharing"]["post_flow_shared"]
            or record["sharing"]["post_flow_shared"]
        )
        existing["shared"] = bool(
            existing["sharing"]["request_multiplexed"]
            or existing["sharing"]["post_flow_shared"]
            or existing["sharing"]["outer_connection_reused"]
        )
    return list(merged.values())


def _connection_record(
    flow: CorrelatedFlowV2,
    session_id: str,
    generation_id: str,
    proxy_selections: dict[str, dict],
) -> dict:
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
        "sharing": {
            "request_multiplexed": bool(
                flow.connection_reused or len(set(flow.request_ids)) > 1
            ),
            "post_flow_shared": bool(
                flow.post_flow and flow.post_flow.shared
            ),
            "outer_connection_reused": False,
        },
        "shared": bool(
            flow.connection_reused
            or len(set(flow.request_ids)) > 1
            or (flow.post_flow and flow.post_flow.shared)
        ),
        "egress": _resolve_egress(flow, proxy_selections),
        "match": match,
        "request_ids": sorted(set(flow.request_ids)),
    }
    if flow.terminal is not None:
        terminal = asdict(flow.terminal)
        if flow.terminal.status.endswith("error"):
            terminal["error_class"] = _terminal_error_class(flow)
        record["terminal"] = terminal
    if flow.netlog_source_id is not None:
        record["netlog_source_id"] = flow.netlog_source_id
    if flow.conn_id:
        record["mihomo_connection_id"] = flow.conn_id
    if flow.outer_conn_id:
        record["outer_connection_id"] = flow.outer_conn_id
    return record


def _terminal_error_class(flow: CorrelatedFlowV2) -> str:
    assert flow.terminal is not None
    message = flow.terminal.error.lower()
    family = ""
    if flow.pre_flow is not None and flow.pre_flow.dst_ip:
        try:
            family = "ipv6" if ipaddress.ip_address(flow.pre_flow.dst_ip).version == 6 else "ipv4"
        except ValueError:
            family = ""
    if "timeout" in message or "timed out" in message:
        return f"{family}_timeout" if family else "network_timeout"
    if any(token in message for token in (
        "network is unreachable", "no route to host", "unreachable",
    )):
        return f"{family}_unreachable" if family else "network_unreachable"
    if flow.terminal.stage == "dial" or flow.terminal.status == "dial_error":
        return "dial_error"
    return "transport_error"


def _annotate_outer_connection_reuse(records: list[dict]) -> None:
    counts: dict[str, int] = {}
    for record in records:
        outer = record.get("outer_connection_id")
        if outer:
            counts[outer] = counts.get(outer, 0) + 1
    for record in records:
        outer = record.get("outer_connection_id")
        reused = bool(outer and counts.get(outer, 0) > 1)
        record["sharing"]["outer_connection_reused"] = reused
        record["shared"] = bool(
            record["sharing"]["request_multiplexed"]
            or record["sharing"]["post_flow_shared"]
            or reused
        )


def _load_proxy_selections(session: Path) -> dict[str, dict]:
    paths = [session / "raw" / "proxy-info.json"]
    paths.extend(sorted((session / "logs").glob("proxy_info_*.json")))
    for path in paths:
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, list):
            return {
                item["group"]: item
                for item in payload
                if isinstance(item, dict) and item.get("group")
            }
    return {}


def _resolve_egress(
    flow: CorrelatedFlowV2,
    selections: dict[str, dict],
) -> dict:
    policy = flow.proxy
    chain: list[str] = []
    selected_type = flow.proxy_type or ""
    current = policy
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        chain.append(current)
        selection = selections.get(current)
        if not selection:
            break
        selected_type = str(selection.get("type", "")) or selected_type
        node = str(selection.get("node", ""))
        if not node or node == current:
            break
        current = node
    if current and (not chain or chain[-1] != current):
        chain.append(current)

    terminal = chain[-1] if chain else ""
    lowered_type = selected_type.lower()
    if terminal.upper() == "DIRECT" or lowered_type == "direct":
        mode = "direct"
    elif terminal and (
        flow.post_flow is not None
        or lowered_type not in {"", "selector", "fallback", "urltest"}
    ):
        mode = "proxy"
    else:
        mode = "unknown"
    return {
        "mode": mode,
        "policy": policy or None,
        "selection_chain": chain,
        "selected_node": terminal or None,
        "selected_type": selected_type or None,
        "evidence": (
            "mihomo_trace_and_session_proxy_snapshot"
            if policy and policy in selections
            else "mihomo_trace"
            if policy
            else "unavailable"
        ),
    }


def _request_records(
    results: list[VisitCorrelation],
    session_id: str,
    generation_id: str,
    pcap_results: list[ConnectionPcapResult],
) -> list[dict]:
    output: list[dict] = []
    for result in results:
        for resolution in resolve_visit_requests(result, pcap_results):
            request = resolution.request
            candidates = list(resolution.candidates)
            flow = resolution.flow
            connection_id = flow.stable_connection_id if flow else None
            network_observation, observation_evidence = (
                _request_network_observation(request)
            )
            if connection_id:
                network_observation = "network"
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
                "candidate_connection_ids": [
                    item.stable_connection_id for item in candidates
                ],
                "network_observation": network_observation,
                "attribution": (
                    {
                        "status": resolution.status,
                        "method": resolution.method,
                        "confidence": 1.0 if connection_id else 0.0,
                        "evidence": list(resolution.evidence),
                        **({"unmatched_reason": resolution.unmatched_reason}
                           if resolution.unmatched_reason else {}),
                    }
                    if connection_id or resolution.status == "ambiguous"
                    else {
                        "status": "unmatched",
                        "method": resolution.method,
                        "confidence": 0.0,
                        "evidence": observation_evidence,
                        "unmatched_reason": _request_unmatched_reason(
                            request, network_observation, resolution.unmatched_reason,
                        ),
                    }
                ),
            })
    return output


def _request_unmatched_reason(
    request,
    network_observation: str,
    resolver_reason: str | None,
) -> str:
    if resolver_reason:
        return resolver_reason
    if network_observation not in {"network", "unknown"}:
        return "non_network_response"
    if request.response_status > 0:
        return "response_transport_unbound"
    if request.response_status == 0:
        return "no_response"
    return "no_transport_connection"


def _request_network_observation(
    request,
) -> tuple[str, list[str]]:
    """Classify whether Chrome expected a packet-bearing transport."""
    if request.from_service_worker:
        return "service_worker", ["cdp_from_service_worker"]
    if request.from_prefetch_cache:
        return "prefetch_cache", ["cdp_from_prefetch_cache"]
    if request.from_disk_cache:
        return "disk_cache", ["cdp_from_disk_cache"]
    if request.remote_ip or (
        request.connection_id is not None and request.connection_id > 0
    ):
        return "network", ["request_not_in_transport_index"]
    if request.connection_id == 0 and request.response_status > 0:
        return "browser_internal", [
            "cdp_connection_id_zero",
            "cdp_response_received",
        ]
    return "unknown", ["request_not_in_transport_index"]


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
    *,
    output_dir: str | Path | None = None,
) -> Path:
    """Persist the authoritative connection-to-PCAP map and coverage counters."""
    session = Path(session_dir)
    merged = _merge_pcap_results(pcap_results)
    output = Path(output_dir) if output_dir is not None else session / "results"
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
        "coverage": layered_coverage(
            _index_items(output / REQUEST_INDEX_V2_NAME),
            _index_items(output / CONNECTION_INDEX_V2_NAME),
            core_flow_records(session, session_id),
        ),
    }
    validate_pcap_index(payload)
    output_path = output / PCAP_INDEX_V1_NAME
    write_json_atomic(output_path, payload)
    return output_path


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


def _index_items(path: Path) -> list[dict]:
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    return list(payload.get("items", []))

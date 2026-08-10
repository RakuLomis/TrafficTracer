"""Resolve browser requests to canonical transport connections."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from traffictracer.models import AttributedRequest, CorrelatedFlowV2, VisitCorrelation

from .pcap_splitter import ConnectionPcapResult


@dataclass(frozen=True)
class RequestResolution:
    request: AttributedRequest
    flow: CorrelatedFlowV2 | None
    candidates: tuple[CorrelatedFlowV2, ...]
    method: str
    evidence: tuple[str, ...]
    status: str = "matched"
    unmatched_reason: str | None = None


def resolve_visit_requests(
    result: VisitCorrelation,
    pcap_results: list[ConnectionPcapResult],
) -> list[RequestResolution]:
    """Resolve one visit using direct, endpoint and temporal browser evidence."""
    all_flows = [flow for flow in result.flows if flow.stable_connection_id]
    pcap_by_connection = {item.connection_id: item for item in pcap_results}
    by_request: dict[str, list[CorrelatedFlowV2]] = {}
    for flow in all_flows:
        for request_id in flow.request_ids:
            by_request.setdefault(request_id, []).append(flow)

    preliminary: list[RequestResolution] = []
    for request in result.requests:
        direct = by_request.get(request.request_id, [])
        candidates = _rank_request_flows(
            _with_transport_race_alternatives(
                direct, all_flows, request.url, pcap_by_connection,
            ),
            pcap_by_connection,
        )
        flow, race_resolved = _select_preliminary_candidate(
            request, direct, candidates, pcap_by_connection,
        )
        status = (
            "matched" if flow is not None
            else "ambiguous" if len(candidates) > 1
            else "unmatched"
        )
        preliminary.append(RequestResolution(
            request=request,
            flow=flow,
            candidates=tuple(candidates),
            method="netlog_socket" if candidates else "none",
            evidence=(
                (
                    "netlog_request_id",
                    "transport_request_ids",
                    *(
                        ("transport_race_resolved", "pcap_observed")
                        if race_resolved else ()
                    ),
                )
                if flow is not None
                else (
                    "netlog_request_id",
                    "multiple_transport_connections",
                )
                if status == "ambiguous"
                else ()
            ),
            status=status,
            unmatched_reason=(
                "multiple_candidates" if status == "ambiguous" else None
            ),
        ))

    preliminary = [
        _resolve_response_endpoint(item, all_flows, pcap_by_connection)
        for item in preliminary
    ]

    # CDP connection IDs are browser-process local. This function is called per
    # visit, preventing evidence from leaking across pages or sessions.
    flows_by_cdp: dict[int, dict[str, CorrelatedFlowV2]] = {}
    evidence_requests_by_pair: dict[
        tuple[int, str], list[AttributedRequest]
    ] = {}
    for resolution in preliminary:
        cdp_id = resolution.request.connection_id
        flow = resolution.flow
        if cdp_id is None or cdp_id <= 0 or flow is None:
            continue
        flows_by_cdp.setdefault(cdp_id, {})[flow.stable_connection_id] = flow
        evidence_requests_by_pair.setdefault(
            (cdp_id, flow.stable_connection_id), [],
        ).append(resolution.request)

    resolved: list[RequestResolution] = []
    for resolution in preliminary:
        request = resolution.request
        if resolution.flow is not None:
            resolved.append(resolution)
            continue
        cdp_id = request.connection_id
        reusable = (
            cdp_id is not None
            and cdp_id > 0
            and request.response_status > 0
            and request.connection_reused
        )
        candidates_by_id = flows_by_cdp.get(cdp_id, {}) if reusable else {}
        candidates = _rank_request_flows(
            list(candidates_by_id.values()), pcap_by_connection,
        )
        if len(candidates) == 1:
            flow = candidates[0]
            prior = evidence_requests_by_pair[
                (cdp_id, flow.stable_connection_id)
            ][-1]
            resolved.append(RequestResolution(
                request=request,
                flow=flow,
                candidates=(flow,),
                method="cdp_connection_reuse",
                evidence=(
                    f"cdp_connection_id:{cdp_id}",
                    f"prior_request_id:{prior.request_id}",
                    "cdp_response_received",
                    "cdp_connection_reused",
                    "unique_transport_connection",
                ),
            ))
        elif len(candidates) > 1:
            selected, temporal_evidence = _select_temporal_candidate(
                request,
                candidates,
                cdp_id,
                evidence_requests_by_pair,
            )
            if selected is not None:
                resolved.append(RequestResolution(
                    request=request,
                    flow=selected,
                    candidates=tuple(candidates),
                    method="cdp_connection_reuse",
                    evidence=(
                        f"cdp_connection_id:{cdp_id}",
                        "cdp_response_received",
                        "cdp_connection_reused",
                        *temporal_evidence,
                    ),
                ))
            else:
                resolved.append(RequestResolution(
                    request=request,
                    flow=None,
                    candidates=tuple(candidates),
                    method="cdp_connection_reuse",
                    evidence=(
                        f"cdp_connection_id:{cdp_id}",
                        "cdp_response_received",
                        "cdp_connection_reused",
                        "multiple_transport_connections",
                        *temporal_evidence,
                    ),
                    status="ambiguous",
                    unmatched_reason="ambiguous_cdp_connection",
                ))
        else:
            resolved.append(resolution)
    return resolved


def _resolve_response_endpoint(
    resolution: RequestResolution,
    all_flows: list[CorrelatedFlowV2],
    pcap_by_connection: dict[str, ConnectionPcapResult],
) -> RequestResolution:
    """Seed a browser connection from its observed response endpoint."""
    request = resolution.request
    if (
        resolution.flow is not None
        or request.response_status <= 0
        or not request.remote_ip
        or not request.remote_port
    ):
        return resolution

    candidates = _rank_request_flows(
        [
            flow for flow in all_flows
            if _flow_matches_response_endpoint(flow, request)
        ],
        pcap_by_connection,
    )
    if not candidates:
        return resolution

    selected, _ = _select_preliminary_candidate(
        request, [], candidates, pcap_by_connection,
    )
    temporal_evidence: tuple[str, ...] = ()
    if selected is None:
        selected, temporal_evidence = _select_endpoint_lifecycle_candidate(
            request, candidates,
        )
    if selected is not None:
        return RequestResolution(
            request=request,
            flow=selected,
            candidates=tuple(candidates),
            method="cdp_response_endpoint",
            evidence=(
                f"cdp_response_endpoint:{request.remote_ip}:{request.remote_port}",
                "cdp_response_received",
                *(
                    ("unique_response_endpoint",)
                    if len(candidates) == 1
                    else temporal_evidence or ("unique_candidate_evidence",)
                ),
            ),
        )
    return RequestResolution(
        request=request,
        flow=None,
        candidates=tuple(candidates),
        method="cdp_response_endpoint",
        evidence=(
            f"cdp_response_endpoint:{request.remote_ip}:{request.remote_port}",
            "cdp_response_received",
            "multiple_transport_connections",
        ),
        status="ambiguous",
        unmatched_reason="ambiguous_response_endpoint",
    )


def _select_endpoint_lifecycle_candidate(
    request: AttributedRequest,
    candidates: list[CorrelatedFlowV2],
) -> tuple[CorrelatedFlowV2 | None, tuple[str, ...]]:
    """Select one endpoint candidate only with unique temporal evidence."""
    active = [
        flow for flow in candidates
        if flow.first_observed is not None
        and flow.last_observed is not None
        and flow.first_observed <= request.timestamp <= flow.last_observed
    ]
    if len(active) == 1:
        return active[0], (
            "request_within_transport_lifecycle",
            f"selected_connection_id:{active[0].stable_connection_id}",
        )
    if active:
        return None, ("multiple_active_transport_connections",)

    preceding = [
        flow for flow in candidates
        if flow.last_observed is not None
        and 0 <= request.timestamp - flow.last_observed <= 30.0
    ]
    if not preceding:
        return None, ("no_nearby_transport_lifecycle",)
    latest = max(flow.last_observed for flow in preceding)
    nearest = [flow for flow in preceding if flow.last_observed == latest]
    if len(nearest) != 1:
        return None, ("nearest_transport_lifecycle_tie",)
    selected = nearest[0]
    return selected, (
        "nearest_preceding_transport_lifecycle",
        f"temporal_gap_ms:{round((request.timestamp - latest) * 1000)}",
        f"selected_connection_id:{selected.stable_connection_id}",
    )


def _select_preliminary_candidate(
    request: AttributedRequest,
    direct: list[CorrelatedFlowV2],
    candidates: list[CorrelatedFlowV2],
    pcap_by_connection: dict[str, ConnectionPcapResult],
) -> tuple[CorrelatedFlowV2 | None, bool]:
    if len(candidates) == 1:
        return candidates[0], candidates[0] not in direct

    packet_backed = [
        flow for flow in candidates
        if _pcap_observed(pcap_by_connection.get(flow.stable_connection_id))
    ]
    direct_has_empty_capture = any(
        _pcap_empty(pcap_by_connection.get(flow.stable_connection_id))
        for flow in direct
    )
    if direct_has_empty_capture and len(packet_backed) == 1:
        return packet_backed[0], packet_backed[0] not in direct

    exact_url = [
        flow for flow in candidates
        if _canonical_request_url(flow.url) == _canonical_request_url(request.url)
    ]
    if len(exact_url) == 1:
        return exact_url[0], exact_url[0] not in direct

    complete_exact = [
        flow for flow in candidates
        if flow.match_status == "matched"
        and flow.match_method == "exact_pre_flow"
        and bool(flow.pre_flow and flow.pre_flow.complete)
        and bool(flow.post_flow and flow.post_flow.complete)
    ]
    if len(complete_exact) == 1:
        return complete_exact[0], complete_exact[0] not in direct
    return None, False


def _canonical_request_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        parsed.query,
        "",
    ))


def _select_temporal_candidate(
    request: AttributedRequest,
    candidates: list[CorrelatedFlowV2],
    cdp_id: int,
    evidence_requests_by_pair: dict[
        tuple[int, str], list[AttributedRequest]
    ],
) -> tuple[CorrelatedFlowV2 | None, tuple[str, ...]]:
    """Select only when endpoint or lifecycle evidence yields one candidate."""
    endpoint_matches = [
        flow for flow in candidates
        if _flow_matches_response_endpoint(flow, request)
    ]
    narrowed = endpoint_matches or candidates
    evidence: list[str] = []
    if endpoint_matches:
        evidence.append("cdp_response_endpoint_match")
        if len(endpoint_matches) == 1:
            evidence.append("unique_response_endpoint")
            return endpoint_matches[0], tuple(evidence)

    ranked: list[tuple[bool, float, float, CorrelatedFlowV2]] = []
    for flow in narrowed:
        prior_requests = evidence_requests_by_pair.get(
            (cdp_id, flow.stable_connection_id), [],
        )
        start = flow.first_observed
        if start is None and prior_requests:
            start = min(item.timestamp for item in prior_requests)
        end = flow.last_observed
        if end is None and prior_requests:
            end = max(_request_end(item) for item in prior_requests)
        prior = max(
            (
                item.timestamp for item in prior_requests
                if item.timestamp <= request.timestamp
            ),
            default=float("-inf"),
        )
        contains = bool(
            start is not None
            and end is not None
            and start <= request.timestamp <= end
        )
        ranked.append((
            contains,
            prior,
            end if end is not None else float("-inf"),
            flow,
        ))

    if not ranked:
        return None, tuple(evidence)
    ranked.sort(
        key=lambda item: (
            -int(item[0]), -item[1], -item[2], item[3].stable_connection_id,
        ),
    )
    best = ranked[0]
    best_key = best[:3]
    tied = [item for item in ranked if item[:3] == best_key]
    if len(tied) != 1:
        return None, (*evidence, "temporal_top_score_tie")

    contains, prior, _, selected = best
    if contains:
        return selected, (
            *evidence,
            "request_within_transport_lifecycle",
            f"selected_connection_id:{selected.stable_connection_id}",
        )
    if prior != float("-inf") and 0 <= request.timestamp - prior <= 30.0:
        return selected, (
            *evidence,
            "nearest_preceding_request",
            f"temporal_gap_ms:{round((request.timestamp - prior) * 1000)}",
            f"selected_connection_id:{selected.stable_connection_id}",
        )
    return None, (*evidence, "insufficient_time_evidence")


def _flow_matches_response_endpoint(
    flow: CorrelatedFlowV2,
    request: AttributedRequest,
) -> bool:
    return bool(
        request.remote_ip
        and request.remote_port
        and flow.pre_flow
        and flow.pre_flow.dst_ip == request.remote_ip
        and flow.pre_flow.dst_port == request.remote_port
    )


def _request_end(request: AttributedRequest) -> float:
    return (
        request.completion_timestamp
        or request.response_timestamp
        or request.timestamp
    )


def _rank_request_flows(
    flows: list[CorrelatedFlowV2],
    pcap_by_connection: dict[str, ConnectionPcapResult] | None = None,
) -> list[CorrelatedFlowV2]:
    pcap_by_connection = pcap_by_connection or {}
    unique = {flow.stable_connection_id: flow for flow in flows}
    return sorted(
        unique.values(),
        key=lambda flow: (
            -int(_pcap_observed(pcap_by_connection.get(flow.stable_connection_id))),
            -int(flow.match_status == "matched"),
            -int(flow.match_method == "exact_pre_flow"),
            -int(bool(flow.post_flow and flow.post_flow.complete)),
            -int(bool(flow.pre_flow and flow.pre_flow.complete)),
            -int(bool(flow.terminal and flow.terminal.status == "closed")),
            -float(flow.match_confidence),
            flow.stable_connection_id,
        ),
    )


def _with_transport_race_alternatives(
    direct: list[CorrelatedFlowV2],
    all_flows: list[CorrelatedFlowV2],
    request_url: str,
    pcap_by_connection: dict[str, ConnectionPcapResult],
) -> list[CorrelatedFlowV2]:
    if not direct or not any(
        _pcap_empty(pcap_by_connection.get(flow.stable_connection_id))
        for flow in direct
    ):
        return list(direct)
    resource_key = _transport_race_resource_key(request_url)
    alternatives = [
        flow for flow in all_flows
        if flow not in direct
        and _transport_race_resource_key(flow.url) == resource_key
        and flow.match_status == "matched"
        and bool(flow.post_flow and flow.post_flow.complete)
        and _pcap_observed(pcap_by_connection.get(flow.stable_connection_id))
    ]
    return [*direct, *alternatives]


def _pcap_observed(result: ConnectionPcapResult | None) -> bool:
    return bool(
        result
        and result.pre_proxy.status == "success"
        and result.pre_proxy.packet_count > 0
    )


def _pcap_empty(result: ConnectionPcapResult | None) -> bool:
    return bool(
        result
        and result.pre_proxy.status == "empty"
        and result.pre_proxy.packet_count == 0
    )


def _transport_race_resource_key(url: str) -> str:
    """Identify one resource path without site- or query-specific exceptions."""
    parsed = urlsplit(url)
    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        "",
        "",
    ))

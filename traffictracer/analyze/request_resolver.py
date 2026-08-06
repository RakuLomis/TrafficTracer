"""Resolve browser requests to canonical transport connections."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
    """Resolve a visit without broadcasting URL aliases across connections."""
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
        flow = candidates[0] if candidates else None
        race_resolved = bool(flow is not None and flow not in direct)
        preliminary.append(RequestResolution(
            request=request,
            flow=flow,
            candidates=tuple(candidates),
            method="netlog_socket" if flow is not None else "none",
            evidence=(
                "netlog_request_id",
                "transport_request_ids",
                *(("transport_race_resolved", "pcap_observed") if race_resolved else ()),
            ) if flow is not None else (),
            status="matched" if flow is not None else "unmatched",
        ))

    # CDP connection IDs are browser-process local. This function is called per
    # visit, preventing evidence from leaking across pages or Sessions.
    flows_by_cdp: dict[int, dict[str, CorrelatedFlowV2]] = {}
    evidence_request_by_pair: dict[tuple[int, str], str] = {}
    for resolution in preliminary:
        cdp_id = resolution.request.connection_id
        flow = resolution.flow
        if cdp_id is None or cdp_id <= 0 or flow is None:
            continue
        flows_by_cdp.setdefault(cdp_id, {})[flow.stable_connection_id] = flow
        evidence_request_by_pair.setdefault(
            (cdp_id, flow.stable_connection_id), resolution.request.request_id,
        )

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
            prior_request_id = evidence_request_by_pair[
                (cdp_id, flow.stable_connection_id)
            ]
            resolved.append(RequestResolution(
                request=request,
                flow=flow,
                candidates=(flow,),
                method="cdp_connection_reuse",
                evidence=(
                    f"cdp_connection_id:{cdp_id}",
                    f"prior_request_id:{prior_request_id}",
                    "cdp_response_received",
                    "cdp_connection_reused",
                    "unique_transport_connection",
                ),
            ))
        elif len(candidates) > 1:
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
                ),
                status="ambiguous",
                unmatched_reason="ambiguous_cdp_connection",
            ))
        else:
            resolved.append(resolution)
    return resolved


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
    parsed = urlsplit(url)
    query = [
        (key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key not in {"rn", "alr"}
    ]
    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        urlencode(sorted(query)),
        "",
    ))

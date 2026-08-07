"""Build the legacy correlation artifact from canonical v2 indexes."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from traffictracer.models import VisitCorrelation
from .request_observation import NON_NETWORK_OBSERVATIONS


def build_legacy_projection(
    results: Iterable[VisitCorrelation],
    request_records: list[dict],
    connection_records: list[dict],
) -> dict[str, dict]:
    """Project canonical request/connection records into the legacy shape."""
    connections = {
        item["connection_id"]: item
        for item in connection_records
        if item.get("connection_id")
    }
    requests_by_connection: dict[str, list[dict]] = defaultdict(list)
    for request in request_records:
        connection_id = request.get("connection_id")
        if not connection_id:
            continue
        if request.get("network_observation") in NON_NETWORK_OBSERVATIONS:
            continue
        if request.get("attribution", {}).get("status") != "matched":
            continue
        requests_by_connection[connection_id].append(request)

    projected: dict[str, dict] = {}
    for result in results:
        request_keys = {
            (request.request_id, request.url)
            for request in result.requests
        }
        original_flows = {
            flow.stable_connection_id: flow
            for flow in result.flows
            if flow.stable_connection_id
        }
        entry = projected.setdefault(result.domain, {
            "visit_url": result.visit_url,
            "domain": result.domain,
            "flows": [],
            "cdp_request_count": 0,
            "netlog_connection_count": 0,
        })
        entry["cdp_request_count"] += len(result.requests)
        entry["netlog_connection_count"] += result.netlog_connection_count

        connection_ids = sorted({
            request.get("connection_id")
            for request in request_records
            if (request.get("request_id"), request.get("url")) in request_keys
            and request.get("connection_id")
        })
        for connection_id in connection_ids:
            connection = connections.get(connection_id)
            if not connection:
                continue
            if connection.get("match", {}).get("status") != "matched":
                continue
            requests = [
                request
                for request in requests_by_connection.get(connection_id, [])
                if (request.get("request_id"), request.get("url")) in request_keys
            ]
            if not requests:
                continue
            entry["flows"].append(
                _legacy_flow(connection, requests, original_flows.get(connection_id))
            )

    for entry in projected.values():
        entry["flows"].sort(key=lambda item: item["stable_connection_id"])
    return projected


def merge_legacy_projection(
    destination: dict[str, dict],
    projection: dict[str, dict],
) -> None:
    """Merge v2 projections with domain-only legacy fallback results."""
    for domain, source in projection.items():
        existing = destination.get(domain)
        if existing is None:
            destination[domain] = source
            continue
        existing["flows"].extend(source["flows"])
        existing["cdp_request_count"] += source["cdp_request_count"]
        existing["netlog_connection_count"] += source["netlog_connection_count"]


def _legacy_flow(connection: dict, requests: list[dict], original) -> dict:
    request_ids = sorted({item["request_id"] for item in requests})
    urls = sorted({item["url"] for item in requests})
    primary_url = connection.get("primary_url")
    if primary_url not in urls:
        primary_url = urls[0]
    primary_request = next(
        (item for item in requests if item["url"] == primary_url),
        requests[0],
    )
    pre_flow = _legacy_tuple(connection["pre_flow"])
    post_flow = (
        _legacy_tuple(connection["post_flow"])
        if connection.get("post_flow") is not None
        else None
    )
    match = connection.get("match", {})
    sharing = connection.get("sharing", {})
    payload = {
        "url": primary_url,
        "urls": urls,
        "resource_type": primary_request.get("resource_type", ""),
        "target_type": getattr(original, "target_type", "") if original else "",
        "relation": primary_request.get("relation", "unknown"),
        "pre_proxy_src": _endpoint(pre_flow, "src"),
        "pre_proxy_dst": _endpoint(pre_flow, "dst"),
        "post_proxy_src": _endpoint(post_flow, "src") if post_flow else "",
        "post_proxy_dst": _endpoint(post_flow, "dst") if post_flow else "",
        "protocol": connection["protocol"],
        "application_protocol": getattr(original, "protocol", "") if original else "",
        "request_ids": request_ids,
        "connection_reused": bool(sharing.get("request_multiplexed")),
        "pre_flow": pre_flow,
        "post_flow": post_flow,
        "terminal": connection.get("terminal"),
        "match_status": match.get("status", "unmatched"),
        "match_confidence": match.get("confidence", 0.0),
        "conn_id": connection.get("mihomo_connection_id", ""),
        "netlog_source_id": connection.get("netlog_source_id"),
        "outer_conn_id": connection.get("outer_connection_id", ""),
        "stable_connection_id": connection["connection_id"],
        "match_method": match.get("method", "none"),
        "match_candidates": match.get("candidates", []),
        "match_reason": match.get("unmatched_reason", ""),
        "match_evidence": match.get("evidence", []),
    }
    return payload


def _legacy_tuple(flow: dict) -> dict:
    payload = dict(flow)
    payload["key"] = (
        f"{payload['network']}|"
        f"{_endpoint(payload, 'src')}|"
        f"{_endpoint(payload, 'dst')}"
    )
    return payload


def _endpoint(flow: dict | None, side: str) -> str:
    if flow is None:
        return ""
    ip = flow[f"{side}_ip"]
    port = flow[f"{side}_port"]
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

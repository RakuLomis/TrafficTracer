"""Persist UI-ready normalized Flow index and analysis summary artifacts."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from traffictracer.contracts import validate_flow
from traffictracer.models import FlowTuple
from traffictracer.session.atomic import write_json_atomic
from traffictracer.version import FLOW_SCHEMA_VERSION

from .flow_index import FlowIndex, FlowMapping


FLOW_INDEX_NAME = "flow-index.json"
SUMMARY_NAME = "summary.json"


@dataclass(frozen=True)
class AnalysisArtifacts:
    flow_index: Path
    summary: Path


def persist_analysis_artifacts(
    session_dir: str | Path,
    session_id: str,
) -> AnalysisArtifacts:
    session = Path(session_dir)
    mappings: list[FlowMapping] = []
    for trace_path in sorted((session / "logs").glob("mihomo_trace_*.jsonl")):
        mappings.extend(FlowIndex.from_log(str(trace_path)).mappings)
    mappings = [
        mapping
        for mapping in mappings
        if mapping.pre_flow.complete and bool(mapping.pre_flow.key)
    ]

    pre_counts = Counter(mapping.pre_flow.key for mapping in mappings)
    outer_counts = Counter(
        mapping.outer_conn_id for mapping in mappings if mapping.outer_conn_id
    )
    items = [
        _flow_item(mapping, session_id, pre_counts, outer_counts)
        for mapping in sorted(
            mappings,
            key=lambda item: (
                item.pre_flow.key,
                item.pre_flow.network,
                item.connection_id,
            ),
        )
    ]
    for item in items:
        validate_flow(item)

    error_count = sum(bool(mapping.error) for mapping in mappings)
    warnings = _warnings(items, pre_counts, error_count)
    match_counts = Counter(item["match"]["status"] for item in items)
    protocol_counts = Counter(item["protocol"] for item in items)
    index_payload = {
        "schema_version": FLOW_SCHEMA_VERSION,
        "session_id": session_id,
        "pagination": {
            "total": len(items),
            "default_limit": 100,
            "max_limit": 1000,
        },
        "items": items,
    }
    summary_payload = {
        "schema_version": FLOW_SCHEMA_VERSION,
        "session_id": session_id,
        "total_flows": len(items),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "match_counts": dict(sorted(match_counts.items())),
        "shared_flows": sum(bool(item["shared"]) for item in items),
        "missing_post_flows": sum(item["post_flow"] is None for item in items),
        "duplicate_pre_flow_keys": sum(count > 1 for count in pre_counts.values()),
        "error_flows": error_count,
        "warnings": warnings,
    }

    results = session / "results"
    results.mkdir(parents=True, exist_ok=True, mode=0o700)
    flow_index_path = results / FLOW_INDEX_NAME
    summary_path = results / SUMMARY_NAME
    write_json_atomic(flow_index_path, index_payload)
    write_json_atomic(summary_path, summary_payload)
    return AnalysisArtifacts(flow_index_path, summary_path)


def _flow_item(
    mapping: FlowMapping,
    session_id: str,
    pre_counts: Counter[str],
    outer_counts: Counter[str],
) -> dict:
    candidate_count = pre_counts[mapping.pre_flow.key]
    usable_post = (
        mapping.post_flow
        if mapping.post_flow is not None and mapping.post_flow.complete
        else None
    )
    shared = bool(
        mapping.pre_flow.shared
        or (usable_post is not None and usable_post.shared)
        or (
            mapping.outer_conn_id
            and outer_counts[mapping.outer_conn_id] > 1
        )
    )
    if usable_post is None:
        match_status = "unmatched"
        confidence = 0.0
        reason = "no complete post-proxy flow"
    elif candidate_count > 1:
        match_status = "ambiguous"
        confidence = 0.5
        reason = "pre-proxy tuple is reused by multiple logical flows"
    else:
        match_status = "matched"
        confidence = 1.0
        reason = "exact normalized pre-proxy tuple"

    item = {
        "schema_version": FLOW_SCHEMA_VERSION,
        "session_id": session_id,
        "flow_id": f"{_network(mapping.pre_flow.network)}:{mapping.connection_id}",
        "protocol": _network(mapping.pre_flow.network),
        "pre_flow": _tuple_payload(mapping.pre_flow, "pre_proxy"),
        "post_flow": (
            _tuple_payload(usable_post, "post_proxy")
            if usable_post is not None
            else None
        ),
        "shared": shared,
        "match": {
            "status": match_status,
            "confidence": confidence,
            "candidate_count": candidate_count,
            "reason": reason,
        },
        "request_ids": [],
        "conn_id": mapping.connection_id,
    }
    if mapping.outer_conn_id:
        item["outer_conn_id"] = mapping.outer_conn_id
    return item


def _tuple_payload(flow: FlowTuple, scope: str) -> dict:
    payload = {
        "network": _network(flow.network),
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "complete": flow.complete,
        "source": flow.source or "mihomo",
        "scope": scope,
        "shared": flow.shared,
    }
    if flow.dst_host:
        payload["dst_host"] = flow.dst_host
    return payload


def _network(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith("tcp"):
        return "tcp"
    if lowered.startswith("udp"):
        return "udp"
    raise ValueError(f"unsupported normalized flow network: {value}")


def _warnings(
    items: list[dict],
    pre_counts: Counter[str],
    error_count: int,
) -> list[dict]:
    warnings: list[dict] = []
    duplicate_keys = sorted(key for key, count in pre_counts.items() if count > 1)
    if duplicate_keys:
        warnings.append({
            "code": "DUPLICATE_PRE_FLOW",
            "count": len(duplicate_keys),
            "message": "Some pre-proxy tuples map to multiple logical flows.",
            "keys": duplicate_keys,
        })
    shared_count = sum(bool(item["shared"]) for item in items)
    if shared_count:
        warnings.append({
            "code": "SHARED_OUTER_FLOW",
            "count": shared_count,
            "message": "Shared outer flows are not exclusive one-to-one mappings.",
        })
    missing_count = sum(item["post_flow"] is None for item in items)
    if missing_count:
        warnings.append({
            "code": "POST_FLOW_UNAVAILABLE",
            "count": missing_count,
            "message": "Some logical flows have no complete post-proxy tuple.",
        })
    if error_count:
        warnings.append({
            "code": "FLOW_ERRORS",
            "count": error_count,
            "message": "Some logical flows ended with a tracing error.",
        })
    return warnings
